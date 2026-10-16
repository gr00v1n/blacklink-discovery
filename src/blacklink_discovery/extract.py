"""Syntax-aware occurrence extraction with indexed original-source locations."""

import html
import ipaddress
import json
import re
import unicodedata
from array import array
from bisect import bisect_right
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
URL = re.compile(r"(?:(?:https?|wss?)://|(?<![\w+/:\-])//)[^\s<>\"'`]+", re.IGNORECASE)
BASE64_DATA = re.compile(r"data:[^,\s\"'<>]*;base64,[A-Za-z0-9+/=]+", re.IGNORECASE)
ASCII_HOST = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[.])+[a-zA-Z][a-zA-Z0-9-]*")
FILES = {
    "js",
    "mjs",
    "cjs",
    "vue",
    "jsx",
    "tsx",
    "ts",
    "scss",
    "less",
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
    "htm",
    "zip",
    "ttf",
    "otf",
    "eot",
    "xml",
    "dtd",
    "shtml",
    "aspx",
    "php",
    "mp4",
    "doc",
    "docx",
    "apk",
    "git",
    "md",
}
ESCAPES = re.compile(
    r"\\(?:\r\n|[\r\n\u2028\u2029]|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", re.DOTALL
)
CSS_ESCAPES = re.compile(r"\\(?:[0-9a-fA-F]{1,6}[ \t\r\n\f]?|\r\n|[\r\n\f]|.)", re.DOTALL)
ENTITIES = re.compile(r"&(?:#[xX][0-9a-fA-F]+;?|#\d+;?|[a-zA-Z][a-zA-Z0-9]+;)")
PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2})+")
SVG_NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
SVG_ARITY = {"m": 2, "l": 2, "h": 1, "v": 1, "c": 6, "s": 4, "q": 4, "t": 2, "a": 7}
CSS_DIMENSION = re.compile(
    r"(?<![\w./-])[+-]?(?:[0-9]+\.[0-9]+|\.[0-9]+)"
    r"(?:px|em|rem|ex|ch|vw|vh|vmin|vmax|cm|mm|in|pt|pc|deg|rad|grad|turn|ms|s)(?![\w.-])",
    re.IGNORECASE,
)
CSS_TOKEN = re.compile(r"/\*.*?\*/|<!--.*?-->|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", re.DOTALL)
ATTRIBUTE = re.compile(r"(?<![\w:@-])([\w:@-]+)\s*=\s*([\"'])(.*?)\2", re.DOTALL)
CSS_SELECTOR_HOST = re.compile(r"(?<![\w.-])[a-zA-Z][\w-]*(?:\.[\w-]+)+")
TIME_FORMAT = re.compile(r"(?:T|(?<![A-Za-z]))(?:HH?|hh?):mm?:ss?\.S{1,9}Z?(?![A-Za-z])")
VERSION = re.compile(r"v?[0-9]+(?:\.[0-9]+)+(?:[-+][a-zA-Z0-9.-]+)?")
SCIENTIFIC_NUMBER = re.compile(r"[0-9]+\.[0-9]+[eE][+-]?[0-9]+")
JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
JSON_ESCAPE = re.compile(
    r"\\u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|" + ESCAPES.pattern
)
BOOTSTRAP_KEY = re.compile(
    r"(?:[a-z]+\.)*bs\.(?:alert|affix|button|carousel|collapse|dropdown|modal|popover|scrollspy|select|tab|toast|tooltip)(?:\.[a-z-]+)*",
    re.IGNORECASE,
)


def json_sources(text: str):
    """Locate source-map source strings without losing their JSON evidence coordinates."""
    try:
        document = json.loads(text)
    except ValueError:
        return
    if not isinstance(document, dict) or not isinstance(document.get("sourcesContent"), list):
        return
    decoder = json.JSONDecoder()
    for token in JSON_STRING.finditer(text):
        if json.loads(token[0]) != "sourcesContent":
            continue
        opening = re.match(r"\s*:\s*\[", text[token.end() :])
        if not opening:
            continue
        offset = token.end() + opening.end()
        while offset < len(text):
            offset = re.compile(r"\s*").match(text, offset).end()
            if text[offset : offset + 1] == "]":
                break
            content, end = decoder.raw_decode(text, offset)
            if isinstance(content, str):
                try:
                    content.encode("utf-8")
                except UnicodeEncodeError:
                    pass
                else:
                    value, spans = transformed(
                        text[offset + 1 : end - 1],
                        OriginalSpans(offset + 1, end - offset - 2),
                        JSON_ESCAPE,
                        lambda raw: json.loads('"' + raw + '"'),
                    )
                    yield offset, end, value, spans
            offset = re.compile(r"\s*").match(text, end).end()
            if text[offset : offset + 1] != ",":
                break
            offset += 1


def js_key_context(node, data: bytes, parents) -> bool:
    parent = parents.get(node.id)
    if parent is None:
        return False
    ancestor = parent
    for _ in range(6):
        if ancestor.type == "pair":
            key = ancestor.child_by_field_name("key")
            if (
                key
                and data[key.start_byte : key.end_byte].strip(b"\"'") == b"aria-activedescendant"
            ):
                return True
            break
        ancestor = parents.get(ancestor.id)
        if ancestor is None:
            break
    if parent.type == "pair":
        key = parent.child_by_field_name("key")
        if key and key.id == node.id:
            return True
        return bool(
            key
            and data[key.start_byte : key.end_byte].strip(b"\"'")
            in {
                b"type",
                b"visualColorAccessPath",
                b"visualBorderColorAccessPath",
                b"expression",
                b"className",
                b"staticClass",
                b"rawName",
            }
        )
    if parent.type != "arguments":
        return False
    call = parents.get(parent.id)
    if call is None or call.type != "call_expression":
        return False
    function = call.child_by_field_name("function")
    if function is None:
        return False
    prop = (
        function.child_by_field_name("property")
        if function.type == "member_expression"
        else function
    )
    if prop is None:
        return False
    method = data[prop.start_byte : prop.end_byte]
    arguments = [c for c in parent.named_children if c.type != "comment"]
    index = next((i for i, c in enumerate(arguments) if c.id == node.id), -1)
    raw = data[node.start_byte : node.end_byte].strip(b"\"'")
    if method in {b"on", b"one", b"off"} and index == 1:
        # jQuery's delegated selector follows the event name, not the first argument.
        return bool(re.match(rb"(?:[a-z]+)?[.#][\w-]+(?:\s|[.#[:>+~,]|$)", raw))
    if method in {b"log", b"debug", b"info", b"warn", b"error"} and index == 0:
        obj = function.child_by_field_name("object")
        if obj and data[obj.start_byte : obj.end_byte] == b"console" and len(arguments) > 1:
            # A dotted label describing the following property is not a hostname.
            label = re.fullmatch(rb"[A-Za-z_$][\w$]*((?:\.[A-Za-z_$][\w$]*)+)", raw)
            following = data[arguments[1].start_byte : arguments[1].end_byte]
            return bool(label and following.endswith(label[1]))
    if method in {b"dispatch", b"broadcast"}:
        return index == 1
    if index != 0:
        return False
    if method in {b"get", b"getShallow"}:
        return bool(
            re.match(
                rb"(?:emphasis|normal|label|itemStyle|lineStyle|areaStyle|axisLine|axisLabel|axisTick|splitLine|textStyle|crossStyle|handle|force|axisPointer|tooltip|pointer|series|name|breadcrumb|circular|rippleEffect|effect|title|option|outline)\.",
                raw,
            )
        )
    if method == b"for":
        obj = function.child_by_field_name("object")
        return bool(obj and data[obj.start_byte : obj.end_byte] == b"Symbol")
    return method in {
        b"$t",
        b"t",
        b"getModel",
        b"on",
        b"off",
        b"trigger",
        b"emit",
        b"$on",
        b"$off",
        b"$emit",
        b"addEventListener",
        b"removeEventListener",
        b"querySelector",
        b"querySelectorAll",
        b"matches",
        b"hasClass",
        b"addClass",
        b"removeClass",
        b"closest",
        b"children",
        b"Event",
        b"ActiveXObject",
        b"$watch",
    }


def syntax_spans(value: str, source: str) -> list[tuple[int, int]]:
    """Exclude typed drawing/style syntax, not arbitrary unknown hostname suffixes."""
    spans = []
    if source not in {"JS_STRING", "JS_EXPRESSION", "HTML", "CSS"}:
        return spans

    def css(raw, offset):
        # Keep comments and quoted values available to the domain extractor.
        masked = CSS_TOKEN.sub(lambda m: " " * len(m[0]), raw)
        spans.extend((offset + m.start(), offset + m.end()) for m in CSS_DIMENSION.finditer(masked))
        for head in re.finditer(r"(?:^|(?<=[{};]))([^{};]+)\{", masked):
            # Only selector tokens are excluded; attribute strings and URLs remain evidence.
            for match in CSS_SELECTOR_HOST.finditer(head[1]):
                spans.append(
                    (offset + head.start(1) + match.start(), offset + head.start(1) + match.end())
                )

    if source == "CSS" or (source in {"JS_STRING", "JS_EXPRESSION"} and "{" in value):
        css(value, 0)
    if source in {"JS_STRING", "JS_EXPRESSION"}:
        spans.extend(match.span() for match in TIME_FORMAT.finditer(value))
        for match in CSS_DIMENSION.finditer(value):
            if match.span() == (0, len(value)) or (
                value[max(0, match.start() - 1) : match.start()] == "["
                and value[match.end() : match.end() + 1] == "]"
            ):
                spans.append(match.span())
    if "<" in value:
        markup = Markup(value)
        for tag, _, a, b in markup.tags:
            for attr in ATTRIBUTE.finditer(value[a:b]):
                start = a + attr.start(3)
                if tag == "path" and attr[1].lower() == "d" and is_svg_path(attr[3]):
                    spans.append((start, a + attr.end(3)))
                elif attr[1].lower() == "style":
                    css(attr[3], start)
        for kind, a, b in markup.scripts:
            if kind == "css":
                css(value[a:b], a)
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    return merged


def is_svg_path(value: str) -> bool:
    """Recognize a complete path, never a path-like prefix of a hostname or prose."""
    value = value.strip()
    value = value.removeprefix("path://")
    if not value or value[0] not in "Mm":
        return False
    command, count, offset = "", 0, 0
    while offset < len(value):
        char = value[offset]
        if char in " \t\r\n,":
            offset += 1
            continue
        if char.lower() in SVG_ARITY or char in "Zz":
            if command and (not count or count % SVG_ARITY[command]):
                return False
            if char in "Zz":
                if not command:
                    return False
                command, count = "", 0
            else:
                command, count = char.lower(), 0
            offset += 1
            continue
        if not command:
            return False
        # Arc flags consume one character each, even in compact forms such as 011.5.
        if command == "a" and count % 7 in (3, 4):
            if char not in "01":
                return False
            offset += 1
        else:
            number = SVG_NUMBER.match(value, offset)
            if not number:
                return False
            offset = number.end()
        count += 1
    return not command or bool(count and count % SVG_ARITY[command] == 0)


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


class MappedSpans:
    """Piecewise source ranges: unchanged runs never allocate per-character tuples."""

    def __init__(self):
        self.ends = array("Q")
        self.starts = array("Q")
        self.stops = array("Q")
        self.linear = bytearray()

    def __len__(self):
        return self.ends[-1] if self.ends else 0

    def append(self, size, start, stop, linear=False):
        if size:
            self.ends.append(len(self) + size)
            self.starts.append(start)
            self.stops.append(stop)
            self.linear.append(linear)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return (self[i] for i in range(*index.indices(len(self))))
        if not 0 <= index < len(self):
            raise IndexError(index)
        segment = bisect_right(self.ends, index)
        left = self.ends[segment - 1] if segment else 0
        start, stop = self.starts[segment], self.stops[segment]
        if self.linear[segment]:
            start += index - left
            return start, start + 1
        return start, stop

    def append_slice(self, spans, left, right):
        if isinstance(spans, OriginalSpans):
            self.append(right - left, spans.start + left, spans.start + right, linear=True)
            return
        while left < right:
            segment = bisect_right(spans.ends, left)
            end = min(right, spans.ends[segment])
            self.append(end - left, spans[left][0], spans[end - 1][1], spans.linear[segment])
            left = end


def transformed(value, spans, pattern, decode):
    if not pattern.search(value):
        return value, spans
    chunks, mapping, previous = [], MappedSpans(), 0
    for match in pattern.finditer(value):
        chunks.append(value[previous : match.start()])
        mapping.append_slice(spans, previous, match.start())
        replacement = decode(match[0])
        chunks.append(replacement)
        mapping.append(len(replacement), spans[match.start()][0], spans[match.end() - 1][1])
        previous = match.end()
    chunks.append(value[previous:])
    mapping.append_slice(spans, previous, len(value))
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


def js_style_context(node, data: bytes, parents) -> bool:
    parent = parents.get(node.id)
    if parent is None:
        return False
    if parent.type == "pair":
        key = parent.child_by_field_name("key")
        if key and data[key.start_byte : key.end_byte].strip(b"\"'") in {
            b"transition",
            b"animation",
            b"margin",
            b"padding",
            b"font",
            b"fontSize",
            b"lineHeight",
            b"border",
            b"boxShadow",
            b"transform",
            b"background",
        }:
            return True
        container = parents.get(parent.id)
        owner = parents.get(container.id) if container else None
        if owner and owner.type == "pair":
            key = owner.child_by_field_name("key")
            return bool(
                key
                and data[key.start_byte : key.end_byte].strip(b"\"'") in {b"style", b"staticStyle"}
            )
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left and left.type == "member_expression":
            prop = left.child_by_field_name("property")
            obj = left.child_by_field_name("object")
            if prop and data[prop.start_byte : prop.end_byte] == b"cssText":
                return True
            if obj and obj.type == "member_expression":
                prop = obj.child_by_field_name("property")
                return bool(prop and data[prop.start_byte : prop.end_byte] == b"style")
    return False


@lru_cache(maxsize=1)
def host_pattern():
    # Python's \w excludes combining marks; include every Unicode mark category
    # in both label consumption and boundaries, then let IDNA validate candidates.
    marks = "".join(chr(i) for i in range(0x110000) if unicodedata.category(chr(i)).startswith("M"))
    label = rf"[^\W_](?:[^\W_]|[{marks}]|-)*"
    return re.compile(
        rf"(?<![\w.{marks}-]){label}(?:[.。．｡]{label})+(?![\w{marks}-]|[.。．｡][\w{marks}-])"
    )


def candidates(value: str, source: str):
    # Binary data URLs are opaque, not protocol-relative hosts inside an image/font.
    # Keep the exact string length so every retained candidate has original coordinates.
    value = BASE64_DATA.sub(lambda m: " " * len(m[0]), value)
    for match in host_pattern().finditer(value):
        candidate, left, right, explicit = match[0], match.start(), match.end(), False
        if source == "JS_COMMENT" and re.search(r"[\u3400-\u9fff]", candidate):
            # Chinese prose can sit directly against a CSS class or JS property.
            # Split only when the remainder is recognizable code, never an arbitrary IDN.
            boundary = re.search(
                r"[\u3400-\u9fff]((?:[.#][A-Za-z][A-Za-z0-9_-]*|[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*))(?=[\u3400-\u9fff]|$)",
                candidate,
            )
            if boundary:
                candidate = boundary[1]
                left, right, explicit = left + boundary.start(1), left + boundary.end(1), True
        # Never discard a legal IDN; an adjacent-prose heuristic may only add a candidate.
        yield candidate, left, right, explicit
        ascii_match = (
            ASCII_HOST.search(candidate) if re.search(r"[\u3400-\u9fff]", candidate) else None
        )
        if ascii_match and candidate[: ascii_match.start()].endswith((".", "。", "．", "｡")):
            ascii_match = None
        if ascii_match and PSL(ascii_match[0]).suffix:
            yield (
                ascii_match[0],
                left + ascii_match.start(),
                left + ascii_match.end(),
                False,
            )
    for match in URL.finditer(value):
        try:
            raw = match[0] if not match[0].startswith("//") else "https:" + match[0]
            host = urlsplit(raw).hostname
            # A webpack module id such as "//Fk" is not a protocol-relative hostname.
            prefix = value[max(0, match.start() - 80) : match.start()].lower()
            tail = prefix.rsplit(".replace(", 1)[-1].strip()
            replacement = ".replace(" in prefix and tail.strip("'\"") == ""
            if (
                host
                and not replacement
                and (
                    not match[0].startswith("//")
                    or source != "JS_STRING"
                    or "." in host
                    or ":" in host
                )
            ):
                # URLs to file-like hosts still have explicit hostname semantics.
                relative = match[0].lower().find(host.lower())
                if relative >= 0:
                    yield host, match.start() + relative, match.start() + relative + len(host), True
        except ValueError:
            pass


def extract(text: str, kind: str) -> list[Mention]:
    # Source maps may embed Vue single-file components among their JavaScript sources.
    if kind == "js" and re.match(r"\s*(?:<!--[\s\S]*?-->\s*)*<template\b", text):
        kind = "html"
    positions = Positions(text)
    results = {}

    def add(
        value,
        spans,
        source,
        method,
        expression=None,
        syntax_kind=None,
        original_syntax=None,
        key_context=False,
    ):
        # Only complete JS string values have path semantics; comments still scan verbatim.
        if source == "JS_STRING" and is_svg_path(value):
            return
        syntax = (
            original_syntax
            if original_syntax is not None
            else syntax_spans(value, syntax_kind or source)
        )
        syntax_starts = [a for a, _ in syntax]
        for candidate, left, right, explicit in candidates(value, source):
            syntax_left, syntax_right = (
                (spans[left][0], spans[right - 1][1])
                if original_syntax is not None
                else (left, right)
            )
            interval = bisect_right(syntax_starts, syntax_left) - 1
            if not explicit and interval >= 0 and syntax_right <= syntax[interval][1]:
                continue
            if explicit and source == "JS_COMMENT" and candidate.startswith((".", "#")):
                left += 1
                host = candidate[1:].lower()
                registered, host_type = "", "syntax_candidate"
            else:
                norm = normalize(candidate)
                if not norm or not spans or left == right:
                    continue
                host, registered, host_type = norm
            if not explicit and (host.replace(".", "").isdigit() or host_type == "ip"):
                continue
            raw_left = spans[left][0]
            raw_prefix = text[max(0, raw_left - 220) : raw_left]
            if (
                explicit
                and source == "JS_STRING"
                and "new URL(" in raw_prefix
                and host in {"a", "b", "x", "xn--e1aybc"}
            ):
                host_type = "syntax_candidate"
            if not explicit and (
                host.rsplit(".", 1)[-1] in FILES or value[max(0, left - 1) : left] in {"/", "\\"}
            ):
                host_type = "file_candidate"
            elif (
                explicit
                and source == "JS_COMMENT"
                and (
                    candidate.startswith((".", "#"))
                    or re.fullmatch(r"[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*", candidate)
                )
            ):
                host_type = "syntax_candidate"
            elif (
                not explicit
                and source in {"JS_STRING", "HTML", "HTML_COMMENT"}
                and ".replace(" in value[max(0, left - 80) : left].lower()
                and "//" in value[max(0, left - 12) : left]
            ):
                continue
            elif not explicit and (
                key_context
                or source in {"JS_STRING", "JS_EXPRESSION", "CSS"}
                and (
                    BOOTSTRAP_KEY.fullmatch(candidate)
                    or value[max(0, left - 1) : left] == "$"
                    and candidate.startswith("vuetify.")
                    or value[max(0, left - 7) : left].lower() == "progid:"
                )
            ):
                host_type = "syntax_candidate"
            elif not explicit and not registered:
                prefix = value[max(0, left - 40) : left].lower()
                if (
                    VERSION.fullmatch(candidate)
                    or SCIENTIFIC_NUMBER.fullmatch(candidate)
                    or re.fullmatch(r"vol\.[0-9]+", candidate, re.IGNORECASE)
                    or source == "JS_COMMENT"
                    and prefix.rstrip().endswith("thx")
                    or source
                    in {"JS", "JS_STRING", "JS_EXPRESSION", "CSS", "JS_COMMENT", "HTML_COMMENT"}
                    and (
                        re.fullmatch(
                            r"(?:Symbol|Object|Array|JSON|Math|Date|RegExp|Promise|Reflect|console|KeyboardEvent|this|self|document|window|location|el|store|data|React|jQuery|Microsoft|MouseEvent|DOMNode|sessionStorage|process|moment|fecha|AMap|CSS|props|modifier|arrow|itemStyle|lineStyle|emphasis|visualMap|controlStyle|item|settings|Events|config|pointer|general|series|label|attrs|query|res)(?:\.[A-Za-z_$][\w$]*)+",
                            candidate,
                        )
                        or re.match(r"\s*\(", value[right:])
                        or candidate.startswith(("DXImageTransform.Microsoft.", "v-"))
                        or value[max(0, left - 1) : left] in {"$", "@"}
                        or re.fullmatch(r"resource\.[A-Z][A-Za-z]+", candidate)
                        or re.fullmatch(r"[A-Z][A-Za-z]+Res\.data(?:\.[A-Za-z]+)+", candidate)
                        or re.fullmatch(
                            r"(?:click|keydown|keyup|mouseup|mousedown|input)\.(?:dismiss|mask)",
                            candidate,
                        )
                        or re.fullmatch(r"(?:HHmmss\.S+|IE[0-9]+\.0)", candidate)
                        or BOOTSTRAP_KEY.fullmatch(candidate)
                    )
                ):
                    host_type = "syntax_candidate"
                elif (
                    candidate in {"e.g", "i.e"}
                    or re.fullmatch(r"[12][0-9]{3}\.(?:the|The)", candidate)
                    or (
                        any(c in candidate for c in ".。．｡")
                        and len(re.findall(r"[\u3040-\u30ff\u3400-\u9fff]", candidate)) >= 6
                    )
                    or ("。" in candidate and len(re.findall(r"[\u3400-\u9fff]", candidate)) >= 5)
                    or re.fullmatch(r"[0-9]+[．｡][\u3400-\u9fff\d-]+", candidate)
                    or re.fullmatch(r"[0-9]+\.[\u3400-\u9fff\d-]{2,}", candidate)
                    or (
                        re.search(r"[\u3400-\u9fff]", candidate)
                        and re.search(r"\.[0-9]+$", candidate)
                    )
                ):
                    host_type = "prose_candidate"
            if not explicit and source in {"HTML", "HTML_COMMENT", "JS_STRING"}:
                prefix = value[max(0, left - 200) : left]
                if re.search(
                    r"""(?:v-[\w-]+|:[\w-]+|@[\w-]+)=(?:"[^"]*|'[^']*)$""", prefix
                ) or re.search(r"\{\{[^{}]*$", prefix):
                    host_type = "syntax_candidate"
                if re.search(r'(?:class|className)=["\'][^"\']*$', prefix) and (
                    CSS_DIMENSION.fullmatch(candidate)
                    or re.fullmatch(r"(?:[a-z]+-)+[0-9]+\.[0-9]+", candidate)
                ):
                    host_type = "syntax_candidate"
                if (
                    not registered
                    and "编号" in prefix[-40:]
                    and re.fullmatch(r"[0-9]+[a-zA-Z](?:\.[0-9]+[a-zA-Z])+", candidate)
                ):
                    host_type = "prose_candidate"
                if re.search(r"""\bon\w+=["']?$""", prefix, re.IGNORECASE) and re.match(
                    r"\s*\(", value[right:]
                ):
                    host_type = "syntax_candidate"
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

    def scan(
        raw, start, source, token_kind="text", method="raw", syntax_kind=None, key_context=False
    ):
        # A JS comment delimiter is not a protocol-relative URL prefix.
        if source == "JS_COMMENT" and raw.startswith("//"):
            raw, start = raw[2:], start + 2
        value, spans = decoded(raw, start, token_kind)
        # Parse attribute boundaries before entity decoding can introduce literal quotes.
        original_syntax = (
            [(start + a, start + b) for a, b in syntax_spans(raw, "HTML")]
            if source == "HTML"
            else None
        )
        add(
            value,
            spans,
            source,
            method if value == raw else "decoded",
            syntax_kind=syntax_kind,
            original_syntax=original_syntax,
            key_context=key_context,
        )

    excluded, regions = [], []
    if kind == "json":
        for a, b, value, mapping in json_sources(text):
            excluded.append((a, b))
            for mention in extract(value, "js"):
                start, end = mapping[mention.start][0], mapping[mention.end - 1][1]
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
    elif kind == "html":
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
        parents = {}
        style_contexts = {}
        key_contexts = {}
        analysis = [(tree.root_node, False)]
        while analysis:
            node, visited = analysis.pop()
            if not visited:
                parent = parents.get(node.id)
                style_contexts[node.id] = (
                    style_contexts[parent.id]
                    if parent and parent.type in {"binary_expression", "parenthesized_expression"}
                    else js_style_context(node, data, parents)
                )
                key_contexts[node.id] = (
                    key_contexts[parent.id]
                    if parent and parent.type in {"binary_expression", "parenthesized_expression"}
                    else js_key_context(node, data, parents)
                )
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
                parents.update((c.id, node) for c in node.named_children)
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
            if node.type == "number":
                excluded.append((a, b))
                continue
            if node.type == "member_expression":
                # Dot-property syntax is not a hostname, but nested strings still get scanned.
                excluded.append((a, b))
            if node.type in {"string", "template_string"}:
                excluded.append((a, b))
                if node.type == "string" or not any(
                    c.type == "template_substitution" for c in node.named_children
                ):
                    value, spans = decoded(text[a + 1 : b - 1], a + 1, "js")
                    # Entity decoding inside markup strings must not change quote boundaries.
                    original_syntax = None
                    if "<" in value:
                        original_syntax = [
                            (spans[left][0], spans[right - 1][1])
                            for left, right in syntax_spans(value, "HTML")
                        ]
                    add(
                        value,
                        spans,
                        "JS_STRING",
                        "js_decode" if value == text[a + 1 : b - 1] else "decoded",
                        syntax_kind="CSS" if style_contexts[node.id] else None,
                        original_syntax=original_syntax,
                        key_context=key_contexts[node.id],
                    )
                else:
                    left = a + 1
                    for child in node.named_children:
                        if child.type == "template_substitution":
                            right = positions.character(child.start_byte)
                            scan(
                                text[left:right],
                                left,
                                "JS_STRING",
                                "js",
                                "js_decode",
                                syntax_kind="CSS" if style_contexts[node.id] else None,
                            )
                            left = positions.character(child.end_byte)
                    scan(
                        text[left : b - 1],
                        left,
                        "JS_STRING",
                        "js",
                        "js_decode",
                        syntax_kind="CSS" if style_contexts[node.id] else None,
                        key_context=key_contexts[node.id],
                    )
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
                    if is_svg_path(value):
                        # The path owns its fragments, but comments are scanned separately.
                        excluded.append((a, b))
                        continue
                    add(
                        value,
                        [(a, b)] * len(value),
                        "JS_EXPRESSION",
                        "concat",
                        (a, b),
                        syntax_kind="CSS" if style_contexts[node.id] else None,
                        key_context=key_contexts[node.id],
                    )
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
