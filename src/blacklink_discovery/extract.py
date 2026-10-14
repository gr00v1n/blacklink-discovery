"""Syntax-aware occurrence extraction with indexed original-source locations."""

import html
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, replace
from functools import lru_cache
from urllib.parse import unquote, urlsplit

import idna
import tldextract
import tree_sitter_javascript
from tree_sitter import Language, Parser

from .markup import Markup
from .text import Positions

PSL = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
URL = re.compile(r"(?:(?:https?|wss?)://|//)[^\s<>\"'`]+", re.IGNORECASE)
ASCII_HOST = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[.])+[a-zA-Z][a-zA-Z0-9-]*")
FILES = {
    "js",
    "mjs",
    "cjs",
    "css",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "ico",
    "json",
    "map",
    "woff",
    "woff2",
    "pdf",
    "txt",
    "html",
    "zip",
}
ESCAPES = re.compile(
    r"\\(?:\r\n|[\r\n\u2028\u2029]|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", re.DOTALL
)
CSS_ESCAPES = re.compile(r"\\(?:[0-9a-fA-F]{1,6}[ \t\r\n\f]?|\r\n|[\r\n\f]|.)", re.DOTALL)
ENTITIES = re.compile(r"&(?:#[xX][0-9a-fA-F]+;?|#\d+;?|[a-zA-Z][a-zA-Z0-9]+;)")
PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2})+")


@dataclass(frozen=True)
class Mention:
    host: str
    registered: str
    host_type: str
    start: int
    end: int
    line: int
    column: int
    source: str
    method: str
    evidence: str


@lru_cache(maxsize=16384)
def normalize(value: str) -> tuple[str, str, str] | None:
    value = value.strip().rstrip(".").lower()
    if len(value) > 253:
        return None
    try:
        return str(ipaddress.ip_address(value)), "", "ip"
    except ValueError:
        pass
    try:
        value = idna.encode(value, uts46=True).decode()
    except idna.IDNAError:
        return None
    if len(value) > 253:
        return None
    return (
        value,
        PSL(value).top_domain_under_public_suffix,
        "dns" if "." in value else "single_label",
    )


class OriginalSpans:
    def __init__(self, start, size):
        self.start, self.size = start, size

    def __len__(self):
        return self.size

    def __getitem__(self, index):
        if isinstance(index, slice):
            return ((self.start + i, self.start + i + 1) for i in range(*index.indices(self.size)))
        return self.start + index, self.start + index + 1


def transformed(value, spans, pattern, decode):
    if not pattern.search(value):
        return value, spans
    chunks, mapping, previous = [], [], 0
    for match in pattern.finditer(value):
        chunks.append(value[previous : match.start()])
        mapping.extend(spans[previous : match.start()])
        replacement = decode(match[0])
        chunks.append(replacement)
        mapping.extend([(spans[match.start()][0], spans[match.end() - 1][1])] * len(replacement))
        previous = match.end()
    chunks.append(value[previous:])
    mapping.extend(spans[previous:])
    return "".join(chunks), mapping


def escape_value(raw: str, css=False) -> str:
    tail = raw[1:]
    if tail.startswith(("\n", "\r", "\u2028", "\u2029", "\f")):
        return ""
    try:
        if css and re.match(r"[0-9a-fA-F]", tail):
            code = int(tail.strip(), 16)
            return chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else "\ufffd"
        if tail.startswith("u{"):
            code = int(tail[2:-1], 16)
            return chr(code) if code <= 0x10FFFF else raw
        if tail.startswith(("u", "x")):
            return chr(int(tail[1:], 16))
    except ValueError:
        return raw
    return {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v"}.get(tail, tail)


def decoded(value: str, start: int, kind: str):
    spans = OriginalSpans(start, len(value))
    if kind in {"js", "json", "css"}:
        value, spans = transformed(
            value,
            spans,
            CSS_ESCAPES if kind == "css" else ESCAPES,
            lambda raw: escape_value(raw, kind == "css"),
        )
        # Combine UTF-16 pairs while retaining both original escape spans.
        value, spans = transformed(
            value,
            spans,
            re.compile(r"[\ud800-\udbff][\udc00-\udfff]"),
            lambda raw: chr(0x10000 + ((ord(raw[0]) - 0xD800) << 10) + ord(raw[1]) - 0xDC00),
        )
    if kind == "html":
        value, spans = transformed(value, spans, ENTITIES, html.unescape)
    # Decode one UTF-8 character at a time, not an entire percent-encoded run.
    percent_chars = re.compile(
        r"%(?:[cC][2-9a-fA-F]|[dD][0-9a-fA-F])(?:%[89aAbB][0-9a-fA-F])"
        r"|%[eE][0-9a-fA-F](?:%[89aAbB][0-9a-fA-F]){2}"
        r"|%[fF][0-4](?:%[89aAbB][0-9a-fA-F]){3}|%[0-9a-fA-F]{2}"
    )
    value, spans = transformed(value, spans, percent_chars, unquote)
    return value, spans


def js_decode(value: str) -> str:
    return decoded(value, 0, "js")[0]


@lru_cache(maxsize=1)
def host_pattern():
    # Python's \w excludes combining marks; include every Unicode mark category
    # in both label consumption and boundaries, then let IDNA validate candidates.
    marks = "".join(chr(i) for i in range(0x110000) if unicodedata.category(chr(i)).startswith("M"))
    label = rf"[^\W_](?:[^\W_]|[{marks}]|-)*"
    return re.compile(
        rf"(?<![\w.{marks}-]){label}(?:[.。．｡]{label})+(?![\w{marks}-]|[.。．｡][\w{marks}-])"
    )


def candidates(value: str):
    for match in host_pattern().finditer(value):
        # Never discard a legal IDN; an adjacent-prose heuristic may only add a candidate.
        yield match[0], match.start(), match.end(), False
        ascii_match = (
            ASCII_HOST.search(match[0]) if re.search(r"[\u3400-\u9fff]", match[0]) else None
        )
        if ascii_match and match[0][: ascii_match.start()].endswith((".", "。", "．", "｡")):
            ascii_match = None
        if ascii_match and PSL(ascii_match[0]).suffix:
            yield (
                ascii_match[0],
                match.start() + ascii_match.start(),
                match.start() + ascii_match.end(),
                False,
            )
    for match in URL.finditer(value):
        try:
            raw = match[0] if not match[0].startswith("//") else "https:" + match[0]
            host = urlsplit(raw).hostname
            if host:
                # URLs to file-like hosts still have explicit hostname semantics.
                relative = match[0].lower().find(host.lower())
                if relative >= 0:
                    yield host, match.start() + relative, match.start() + relative + len(host), True
        except ValueError:
            pass


def extract(text: str, kind: str) -> list[Mention]:
    positions = Positions(text)
    results = {}

    def add(value, spans, source, method, expression=None):
        for candidate, left, right, explicit in candidates(value):
            norm = normalize(candidate)
            if not norm or not spans or left == right:
                continue
            host, registered, host_type = norm
            if not explicit and (host.replace(".", "").isdigit() or host_type == "ip"):
                continue
            if not explicit and host.rsplit(".", 1)[-1] in FILES:
                host_type = "file_candidate"
            a, b = expression or (spans[left][0], spans[right - 1][1])
            line, column = positions.locate(a)
            item = Mention(
                host,
                registered,
                host_type,
                a,
                b,
                line,
                column,
                source,
                method,
                text[max(0, a - 80) : min(len(text), b + 80)],
            )
            key = (host, a, b, source)
            if key not in results or explicit:
                results[key] = item

    def scan(raw, start, source, token_kind="text", method="raw"):
        value, spans = decoded(raw, start, token_kind)
        add(value, spans, source, method if value == raw else "decoded")

    excluded, regions = [], []
    if kind == "html":
        markup = Markup(text)
        for a, b in markup.comments:
            regions.append((a, b, "HTML_COMMENT", "html"))
        for script_kind, a, b in markup.scripts:
            excluded.append((a, b))
            for mention in extract(text[a:b], script_kind):
                start, end = a + mention.start, a + mention.end
                line, column = positions.locate(start)
                moved = replace(
                    mention,
                    start=start,
                    end=end,
                    line=line,
                    column=column,
                    evidence=text[max(0, start - 80) : min(len(text), end + 80)],
                )
                results[(moved.host, start, end, moved.source)] = moved
        for _, _, a, b in markup.tags:
            tag = text[a:b]
            for match in re.finditer(
                r"\bon\w+\s*=\s*([\"'])(.*?)\1", tag, re.IGNORECASE | re.DOTALL
            ):
                attribute, mapping = transformed(
                    match[2],
                    OriginalSpans(a + match.start(2), len(match[2])),
                    ENTITIES,
                    html.unescape,
                )
                for mention in extract(attribute, "js"):
                    start, end = mapping[mention.start][0], mapping[mention.end - 1][1]
                    line, column = positions.locate(start)
                    moved = replace(
                        mention,
                        start=start,
                        end=end,
                        line=line,
                        column=column,
                        source="HTML_EVENT",
                        evidence=text[max(0, start - 80) : min(len(text), end + 80)],
                    )
                    results[(moved.host, start, end, moved.source)] = moved
    elif kind == "js":
        data = text.encode("utf-8")
        tree = Parser(Language(tree_sitter_javascript.language())).parse(data)
        constants = {}
        analysis = [(tree.root_node, False)]
        while analysis:
            node, visited = analysis.pop()
            if not visited:
                if node.type == "comment":
                    regions.append(
                        (
                            positions.character(node.start_byte),
                            positions.character(node.end_byte),
                            "JS_COMMENT",
                            "text",
                        )
                    )
                analysis.append((node, True))
                analysis.extend((c, False) for c in node.named_children)
                continue
            constant = node.type == "string" or (
                node.type == "template_string"
                and not any(c.type == "template_substitution" for c in node.named_children)
            )
            if node.type == "parenthesized_expression":
                children = [c for c in node.named_children if c.type != "comment"]
                constant = len(children) == 1 and constants[children[0].id]
            elif node.type == "binary_expression":
                operator = node.child_by_field_name("operator")
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                constant = bool(
                    operator
                    and left
                    and right
                    and data[operator.start_byte : operator.end_byte] == b"+"
                    and constants[left.id]
                    and constants[right.id]
                )
            constants[node.id] = constant
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            a, b = positions.character(node.start_byte), positions.character(node.end_byte)
            if node.type == "comment":
                continue
            if node.type == "member_expression":
                # Dot-property syntax is not a hostname, but nested strings still get scanned.
                excluded.append((a, b))
            if node.type in {"string", "template_string"}:
                excluded.append((a, b))
                if node.type == "string" or not any(
                    c.type == "template_substitution" for c in node.named_children
                ):
                    scan(text[a + 1 : b - 1], a + 1, "JS_STRING", "js", "js_decode")
                else:
                    left = a + 1
                    for child in node.named_children:
                        if child.type == "template_substitution":
                            right = positions.character(child.start_byte)
                            scan(text[left:right], left, "JS_STRING", "js", "js_decode")
                            left = positions.character(child.end_byte)
                    scan(text[left : b - 1], left, "JS_STRING", "js", "js_decode")
                    stack.extend(reversed(node.named_children))
                continue
            if node.type == "binary_expression" and constants[node.id]:
                pending, pieces, valid = [node], [], True
                literals = []
                while pending and valid:
                    current = pending.pop()
                    if current.type == "parenthesized_expression":
                        pending.extend(
                            reversed([c for c in current.named_children if c.type != "comment"])
                        )
                    elif current.type == "binary_expression":
                        operator = current.child_by_field_name("operator")
                        if (
                            operator is None
                            or data[operator.start_byte : operator.end_byte] != b"+"
                        ):
                            valid = False
                        else:
                            pending.extend(
                                [
                                    current.child_by_field_name("right"),
                                    current.child_by_field_name("left"),
                                ]
                            )
                    elif current.type == "string" or (
                        current.type == "template_string"
                        and not any(
                            c.type == "template_substitution" for c in current.named_children
                        )
                    ):
                        literals.append(current)
                        pieces.append(
                            js_decode(data[current.start_byte + 1 : current.end_byte - 1].decode())
                        )
                    else:
                        valid = False
                if valid:
                    value = "".join(pieces)
                    add(value, [(a, b)] * len(value), "JS_EXPRESSION", "concat", (a, b))
                    # The complete expression owns its nested concatenations; scan literals only.
                    stack.extend(reversed(literals))
                    continue
            stack.extend(reversed(node.named_children))

    # Interval sweep: no per-candidate full-result relabeling or prefix decoding.
    for a, b, source, token_kind in regions:
        scan(text[a:b], a, source, token_kind)
        excluded.append((a, b))
    intervals = sorted(excluded)
    cursor = 0
    for a, b in intervals:
        if a > cursor:
            scan(
                text[cursor:a],
                cursor,
                kind.upper(),
                kind if kind in {"html", "json", "css"} else "text",
            )
        cursor = max(cursor, b)
    if cursor < len(text):
        scan(
            text[cursor:], cursor, kind.upper(), kind if kind in {"html", "json", "css"} else "text"
        )

    # Within each host, discard enclosing duplicate passes using a suffix minimum.
    groups = {}
    for item in results.values():
        groups.setdefault(item.host, []).append(item)
    unique = []
    for group in groups.values():
        group.sort(key=lambda m: (m.start, m.end, 0 if m.method == "raw" else 1))
        nearest = float("inf")
        for item in reversed(group):
            if item.end < nearest:
                unique.append(item)
            nearest = min(nearest, item.end)
    return sorted(unique, key=lambda m: (m.start, m.host, m.method))
