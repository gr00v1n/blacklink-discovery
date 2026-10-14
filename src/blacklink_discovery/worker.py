"""Killable browser extraction worker; never owns a SQLite connection."""

import json
import sys
from dataclasses import asdict

from .collect import references
from .extract import extract


def main():
    item = json.load(sys.stdin)
    text, kind, url = item["text"], item["kind"], item["url"]
    result = {
        "mentions": [asdict(m) for m in extract(text, kind)],
        "references": list(references(text, url, kind)),
        "sources": [],
    }
    if kind == "json":
        try:
            mapping = json.loads(text)
        except ValueError:
            mapping = None
        if isinstance(mapping, dict) and "sourcesContent" in mapping:
            if not isinstance(mapping["sourcesContent"], list):
                raise ValueError("sourcesContent must be an array")
            for index, content in enumerate(mapping["sourcesContent"]):
                if isinstance(content, str):
                    warning = ""
                    try:
                        content.encode("utf-8")
                    except UnicodeEncodeError:
                        content = content.encode("utf-8", errors="replace").decode()
                        warning = "invalid Unicode in source map"
                    result["sources"].append(
                        {
                            "index": index,
                            "text": content,
                            "error": warning,
                            "mentions": [asdict(m) for m in extract(content, "js")],
                        }
                    )
    json.dump(result, sys.stdout, ensure_ascii=True)


if __name__ == "__main__":
    main()
