"""HTML source spans without treating quoted > or comments as script syntax."""

from html.parser import HTMLParser

from .text import Positions


class Markup(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.positions = Positions(text)
        self.comments = []
        self.scripts = []
        self.tags = []
        self.active = None
        self.feed(text)
        self.close()
        if self.active:
            self.scripts.append((*self.active, len(text)))

    def source_offset(self):
        line, column = self.getpos()
        # HTMLParser's lines count LF only, independently of display positions.
        if not hasattr(self, "lf_lines"):
            self.lf_lines = [0] + [i + 1 for i, c in enumerate(self.text) if c == "\n"]
        return self.lf_lines[line - 1] + column

    def handle_comment(self, data):
        start = self.source_offset()
        self.comments.append((start, start + len(data) + 7))

    def handle_starttag(self, tag, attrs):
        start = self.source_offset()
        end = start + len(self.get_starttag_text())
        attrs = dict(attrs)
        self.tags.append((tag, attrs, start, end))
        if tag in {"script", "style"}:
            mime = (attrs.get("type") or "").lower().strip()
            kind = (
                "js"
                if mime in {"", "module", "text/javascript", "application/javascript"}
                else "json"
                if "json" in mime
                else "text"
            )
            self.active = ("css" if tag == "style" else kind, end)

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.active:
            self.scripts.append((*self.active, self.source_offset()))
            self.active = None
