"""Shared decoded-text positions and conservative response decoding."""

import codecs
import re
from array import array
from bisect import bisect_right


class Positions:
    def __init__(self, text: str, legacy: bool = False):
        pattern = r"\n" if legacy else r"\r\n|[\n\r\u2028\u2029]"
        self.lines = [0, *(m.end() for m in re.finditer(pattern, text))]
        self.bytes = None
        self.text = text

    def locate(self, offset: int) -> tuple[int, int]:
        line = bisect_right(self.lines, offset)
        return line, offset - self.lines[line - 1] + 1

    def character(self, byte: int) -> int:
        if self.bytes is None:
            offsets = array("I", [0])
            size = 0
            for char in self.text:
                size += len(char.encode("utf-8"))
                offsets.append(size)
            self.bytes = offsets
        return bisect_right(self.bytes, byte) - 1


def decode_body(body: bytes, content_type: str) -> tuple[str, str, str]:
    charset = re.search(r"charset\s*=\s*['\"]?([\w.-]+)", content_type, re.IGNORECASE)
    if body.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = "utf-32"
    elif body.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    elif body.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    elif charset:
        encoding = charset[1]
    else:
        mime = content_type.lower().split(";", 1)[0].strip()
        declaration = None
        if "html" in mime:
            from .markup import Markup

            for tag, attrs, _, _ in Markup(body[:4096].decode("ascii", errors="replace")).tags:
                if tag == "meta":
                    declared = attrs.get("charset") or (
                        re.search(
                            r"charset\s*=\s*([\w.-]+)", attrs.get("content", ""), re.IGNORECASE
                        )
                        if attrs.get("http-equiv", "").lower() == "content-type"
                        else None
                    )
                    if declared:
                        declaration = declared if isinstance(declared, str) else declared[1]
                        break
        elif "xml" in mime:
            match = re.match(
                rb"\s*<\?xml\s+[^?]*encoding=['\"]([\w.-]+)['\"]", body[:4096], re.IGNORECASE
            )
            declaration = match[1].decode("ascii") if match else None
        elif "css" in mime:
            match = re.match(rb'@charset\s+"([\w.-]+)";', body[:4096], re.IGNORECASE)
            declaration = match[1].decode("ascii") if match else None
        encoding = declaration or "utf-8"
    try:
        return body.decode(encoding), encoding, ""
    except LookupError:
        return body.decode("utf-8", errors="replace"), "utf-8", f"unknown charset {encoding}"
    except UnicodeDecodeError:
        return (
            body.decode(encoding, errors="replace"),
            encoding,
            "response contains undecodable bytes",
        )
