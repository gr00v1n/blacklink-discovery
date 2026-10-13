"""Full-text extraction backed by syntax-aware JS recovery and source offsets."""

import html
import ipaddress
import re
from dataclasses import dataclass, replace
from urllib.parse import unquote, urlsplit

import idna
import tldextract
import tree_sitter_javascript
from tree_sitter import Language, Node, Parser

PSL = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
LABEL = r"[^\W_](?:[^\W_]|-)*"
HOST = re.compile(rf"(?<![\w.-]){LABEL}(?:\.{LABEL})+(?![\w-]|\.[\w-])", re.UNICODE)
URL = re.compile(r"(?:https?://|//)[^\s<>\"'`]+", re.IGNORECASE)
ESCAPE = re.compile(r"\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(.))", re.DOTALL)


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


def normalize(value: str) -> tuple[str, str, str] | None:
    value = value.strip().rstrip(".").lower()
    try:
        address = ipaddress.ip_address(value)
        return str(address), "", "ip"
    except ValueError:
        pass
    try:
        value = idna.encode(value, uts46=True).decode()
    except idna.IDNAError:
        return None
    if len(value) > 253:
        return None
    parsed = PSL(value)
    return value, parsed.top_domain_under_public_suffix, "dns" if "." in value else "single_label"


def js_decode(value: str) -> str:
    def replace(match: re.Match) -> str:
        hexadecimal = next((part for part in match.groups()[:3] if part is not None), None)
        if hexadecimal is not None:
            code = int(hexadecimal, 16)
            return chr(code) if code <= 0x10FFFF else match[0]
        return {"n": "\n", "r": "\r", "t": "\t", "\n": "", "\r": ""}.get(match[4], match[4])

    return ESCAPE.sub(replace, value)


def candidates(value: str):
    for match in HOST.finditer(value):
        yield match[0], match.start(), match.end()
    for match in URL.finditer(value):
        try:
            parsed = urlsplit(match[0] if not match[0].startswith("//") else "https:" + match[0])
            if parsed.hostname:
                yield parsed.hostname, match.start(), match.end()
        except ValueError:
            continue


def extract(text: str, kind: str) -> list[Mention]:
    results: dict[tuple, Mention] = {}
    comment_ranges = (
        [(m.start(), m.end()) for m in re.finditer(r"<!--[\s\S]*?(?:-->|$)", text)]
        if kind == "html"
        else []
    )

    def add(value: str, start: int, end: int, source: str, method: str, exact: bool = False):
        for candidate, left, right in candidates(value):
            normalized = normalize(candidate)
            if not normalized:
                continue
            host, registered, host_type = normalized
            a, b = (start + left, start + right) if exact else (start, end)
            line = text.count("\n", 0, a) + 1
            column = a - text.rfind("\n", 0, a)
            evidence = text[max(0, a - 80) : min(len(text), b + 80)]
            key = (host, a, b, source)
            results[key] = Mention(
                host, registered, host_type, a, b, line, column, source, method, evidence
            )

    # Always scan raw text, including syntax errors and nonexecuting content.
    for match in HOST.finditer(text):
        source = (
            "HTML_COMMENT"
            if any(a <= match.start() < b for a, b in comment_ranges)
            else kind.upper()
        )
        add(match[0], match.start(), match.end(), source, "raw", exact=True)
    for match in URL.finditer(text):
        add(match[0], match.start(), match.end(), kind.upper(), "url")

    # Decode individual tokens, retaining the original token span rather than fake offsets.
    for token in re.finditer(r"[^\s<>\"'`]+", text):
        value = html.unescape(token[0]) if kind == "html" else token[0]
        if "%" in value:
            value = unquote(value)
        if value != token[0]:
            add(value, token.start(), token.end(), kind.upper(), "decoded")

    if kind == "js":
        data = text.encode("utf-8")
        parser = Parser(Language(tree_sitter_javascript.language()))
        tree = parser.parse(data)

        def bounds(node: Node):
            return len(data[: node.start_byte].decode()), len(data[: node.end_byte].decode())

        def value(node: Node | None) -> str | None:
            if node is None:
                return None
            raw = data[node.start_byte : node.end_byte].decode()
            if node.type == "string":
                return js_decode(raw[1:-1])
            if node.type == "template_string" and not any(
                c.type == "template_substitution" for c in node.named_children
            ):
                return js_decode(raw[1:-1])
            if node.type == "parenthesized_expression" and node.named_children:
                return value(node.named_children[0])
            if node.type == "binary_expression":
                operator = node.child_by_field_name("operator")
                if operator and data[operator.start_byte : operator.end_byte] == b"+":
                    left, right = (
                        value(node.child_by_field_name("left")),
                        value(node.child_by_field_name("right")),
                    )
                    if left is not None and right is not None:
                        return left + right
            return None

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in {"comment", "string", "template_string", "binary_expression"}:
                a, b = bounds(node)
                if node.type == "comment":
                    # Relabel raw mentions without losing their exact positions.
                    for key, mention in list(results.items()):
                        if a <= mention.start and mention.end <= b:
                            del results[key]
                            fields = mention.__dict__ | {"source": "JS_COMMENT"}
                            updated = Mention(**fields)
                            results[(updated.host, updated.start, updated.end, updated.source)] = (
                                updated
                            )
                else:
                    recovered = value(node)
                    if recovered is not None:
                        add(
                            recovered,
                            a,
                            b,
                            "JS_EXPRESSION" if node.type == "binary_expression" else "JS_STRING",
                            "concat" if node.type == "binary_expression" else "js_decode",
                        )
            stack.extend(reversed(node.named_children))
    if kind == "html":
        for script in re.finditer(r"<script\b[^>]*>([\s\S]*?)</script\s*>", text, re.IGNORECASE):
            offset = script.start(1)
            for mention in extract(script[1], "js"):
                a, b = offset + mention.start, offset + mention.end
                moved = replace(
                    mention,
                    start=a,
                    end=b,
                    line=text.count("\n", 0, a) + 1,
                    column=a - text.rfind("\n", 0, a),
                    evidence=text[max(0, a - 80) : min(len(text), b + 80)],
                )
                for key, existing in list(results.items()):
                    if existing.host == moved.host and a <= existing.start and existing.end <= b:
                        del results[key]
                results[(moved.host, a, b, moved.source)] = moved
    # Raw and decoded passes must not count one occurrence multiple times.
    ordered = sorted(results.values(), key=lambda item: (item.end - item.start, item.start))
    unique = []
    for mention in ordered:
        if not any(
            m.host == mention.host and mention.start <= m.start and m.end <= mention.end
            for m in unique
        ):
            unique.append(mention)
    return sorted(unique, key=lambda item: (item.start, item.host, item.method))
