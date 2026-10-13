import json
import re
import time
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from .store import Store

ASSET = re.compile(r"\.(?:m?js|css|json|map)(?:$|\?)", re.IGNORECASE)


def clean_url(base: str, value: str) -> str | None:
    url = urldefrag(urljoin(base, value.strip()))[0]
    try:
        parsed = urlsplit(url)
        if parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username:
            return url
    except ValueError:
        pass
    return None


def kind_for(url: str, mime: str) -> str:
    path = urlsplit(url).path.lower()
    if "javascript" in mime or path.endswith((".js", ".mjs")):
        return "js"
    if "html" in mime:
        return "html"
    if "css" in mime or path.endswith(".css"):
        return "css"
    if "json" in mime or path.endswith((".json", ".map")):
        return "json"
    if "xml" in mime or path.endswith(".xml"):
        return "xml"
    return "text"


class Links(HTMLParser):
    def __init__(self, url: str):
        super().__init__(convert_charrefs=True)
        self.base = url
        self.links: list[tuple[str, bool, str]] = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "base" and attributes.get("href"):
            self.base = urljoin(self.base, attributes["href"])
        for key in ("href", "src"):
            value = attributes.get(key)
            if value:
                url = clean_url(self.base, value)
                if url:
                    asset = (
                        tag == "script"
                        or (
                            tag == "link"
                            and attributes.get("rel") in {"stylesheet", "modulepreload", "manifest"}
                        )
                        or bool(ASSET.search(url))
                    )
                    if tag in {"a", "iframe", "script", "link"}:
                        self.links.append((url, asset, f"{tag}.{key}"))


def references(text: str, url: str, kind: str):
    if kind == "html":
        parser = Links(url)
        parser.feed(text)
        yield from parser.links
    if kind in {"js", "css"}:
        patterns = [
            r"sourceMappingURL\s*=\s*([^\s*]+)",
            r"(?:import\s*(?:[^;\n]*?\sfrom\s*)?|import\s*\(|require\s*\()\s*['\"]([^'\"]+)['\"]",
            r"['\"]([^'\"]+\.(?:m?js|css|json|map)(?:\?[^'\"]*)?)['\"]",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                child = clean_url(url, match[1])
                if child:
                    yield child, True, "resource_dependency"
    if kind == "xml":
        try:
            root = ET.fromstring(text)
            for node in root.iter():
                if node.tag.split("}")[-1] == "loc" and node.text:
                    child = clean_url(url, node.text)
                    if child:
                        yield child, False, "sitemap"
        except ET.ParseError:
            pass
    if urlsplit(url).path.endswith("robots.txt"):
        for match in re.finditer(r"^Sitemap:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE):
            child = clean_url(url, match[1])
            if child:
                yield child, False, "robots_sitemap"


def enqueue(store: Store, run: int, site: str, url: str, depth: int, asset: bool):
    store.db.execute(
        "INSERT OR IGNORE INTO queue(run_id,site,url,depth,asset) VALUES(?,?,?,?,?)",
        (run, site, url, depth, int(asset)),
    )
    store.db.commit()


def process(
    store: Store,
    run: int,
    site: str,
    url: str,
    body: bytes,
    text: str,
    kind: str,
    depth: int,
    max_depth: int,
    external_assets: set[str],
    status: int = 200,
):
    store.save(run, site, url, body, text, kind, status)
    for child, asset, relation in references(text, url, kind):
        store.edge(run, site, url, child, relation)
        same = urlsplit(child).netloc == urlsplit(site).netloc
        permitted = same or (asset and urlsplit(child).hostname in external_assets)
        enqueue(store, run, site, child, depth + 1, asset)
        state = (
            "skipped_scope"
            if not permitted
            else "skipped_depth"
            if not asset and depth >= max_depth
            else "pending"
        )
        if state != "pending":
            store.db.execute(
                "UPDATE queue SET state=?,error=? WHERE run_id=? AND site=? AND url=? AND state='pending'",
                (state, state, run, site, child),
            )
            store.db.commit()
    if kind == "json":
        try:
            mapping = json.loads(text)
            if isinstance(mapping, dict):
                for index, content in enumerate(mapping.get("sourcesContent") or []):
                    if isinstance(content, str):
                        derived = f"{url}#sourcesContent/{index}"
                        store.edge(run, site, url, derived, "source_map_content")
                        store.save(run, site, derived, content.encode(), content, "js")
        except (ValueError, TypeError):
            pass


def crawl(
    store: Store,
    run: int,
    sites: list[str],
    depth: int,
    delay: float,
    external_assets: set[str],
    max_bytes: int,
    max_urls: int = 0,
):
    for site in sites:
        enqueue(store, run, site, site, 0, False)
        for path in ("/robots.txt", "/sitemap.xml"):
            enqueue(store, run, site, urljoin(site, path), 0, False)
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        count = 0
        while not max_urls or count < max_urls:
            row = store.db.execute(
                "SELECT * FROM queue WHERE run_id=? AND state='pending' ORDER BY depth,rowid LIMIT 1",
                (run,),
            ).fetchone()
            if row is None:
                break
            count += 1
            url, site = row["url"], row["site"]
            time.sleep(delay)
            store.db.execute(
                "INSERT INTO attempts(run_id,site,url,count) VALUES(?,?,?,1) "
                "ON CONFLICT(run_id,site,url) DO UPDATE SET count=count+1",
                (run, site, url),
            )
            store.db.commit()
            try:
                if urlsplit(url).netloc != urlsplit(site).netloc and not (
                    row["asset"] and urlsplit(url).hostname in external_assets
                ):
                    raise ValueError("outside authorized target/asset hosts")
                with client.stream("GET", url) as response:
                    if response.is_redirect:
                        target = clean_url(url, response.headers.get("location", ""))
                        if target:
                            store.edge(run, site, url, target, "redirect")
                            if urlsplit(target).netloc == urlsplit(site).netloc or (
                                row["asset"] and urlsplit(target).hostname in external_assets
                            ):
                                enqueue(store, run, site, target, row["depth"], bool(row["asset"]))
                            else:
                                raise ValueError(
                                    "redirect outside exact host; recorded, not followed"
                                )
                    if not response.is_redirect:
                        response.raise_for_status()
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValueError(
                                f"response exceeds {max_bytes} bytes; not marked complete"
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    encoding = response.encoding or "utf-8"
                    text = body.decode(encoding, errors="replace")
                    kind = kind_for(url, response.headers.get("content-type", ""))
                    process(
                        store,
                        run,
                        site,
                        url,
                        body,
                        text,
                        kind,
                        row["depth"],
                        depth,
                        external_assets,
                        response.status_code,
                    )
                store.db.execute(
                    "UPDATE queue SET state='done',error=NULL WHERE run_id=? AND site=? AND url=?",
                    (run, site, url),
                )
            except (httpx.HTTPError, ValueError, LookupError) as error:
                store.db.execute(
                    "UPDATE queue SET state='failed',error=? WHERE run_id=? AND site=? AND url=?",
                    (str(error), run, site, url),
                )
            store.db.commit()


def import_katana(
    store: Store, path: str, site: str, run: int, depth: int, external_assets: set[str]
):
    with Path(path).open() as stream:
        for line in stream:
            item = json.loads(line)
            request = item["request"]
            url = request["endpoint"]
            if request.get("source"):
                store.edge(run, site, request["source"], url, "katana_reference")
            response = item.get("response", {})
            if "body" in response:
                text = response["body"]
                mime = next(
                    (
                        v
                        for k, v in response.get("headers", {}).items()
                        if k.lower() == "content-type"
                    ),
                    "",
                )
                process(
                    store,
                    run,
                    site,
                    url,
                    text.encode(),
                    text,
                    kind_for(url, mime),
                    0,
                    depth,
                    external_assets,
                    response.get("status_code", 0),
                )
                enqueue(store, run, site, url, 0, bool(ASSET.search(url)))
                store.db.execute(
                    "UPDATE queue SET state='done',error=NULL WHERE run_id=? AND site=? AND url=?",
                    (run, site, url),
                )
            elif item.get("error"):
                enqueue(store, run, site, url, 0, bool(ASSET.search(url)))
                store.db.execute(
                    "UPDATE queue SET state='failed',error=? WHERE run_id=? AND site=? AND url=?",
                    (item["error"], run, site, url),
                )
    store.db.commit()
