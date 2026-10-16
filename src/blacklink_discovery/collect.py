import gzip
import io
import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from curl_cffi.requests.exceptions import RequestException

from .markup import Markup
from .static_http import (
    DEFAULT_FINGERPRINTS,
    FORBIDDEN_ATTEMPTS,
    FingerprintClient,
    validate_fingerprints,
)
from .store import Store
from .text import decode_body
from .urls import authorized, canonical_url, non_text_response, non_text_url

ASSET = re.compile(r"\.(?:m?js|css|json|map)(?:$|\?)", re.IGNORECASE)


def clean_url(base: str, value: str) -> str | None:
    try:
        return canonical_url(value.strip(), base)
    except (ValueError, AttributeError):
        return None


def kind_for(url: str, mime: str, prefix: bytes = b"") -> str:
    if non_text_response(url, mime, prefix):
        return "binary"
    path, mime = urlsplit(url).path.lower(), mime.lower()
    if "javascript" in mime or path.endswith((".js", ".mjs", ".cjs")):
        return "js"
    if "html" in mime or path.endswith((".html", ".htm")):
        return "html"
    if "css" in mime or path.endswith(".css"):
        return "css"
    if "json" in mime or path.endswith((".json", ".map")):
        return "json"
    if "xml" in mime or path.endswith((".xml", ".rss", ".atom", ".xml.gz")):
        return "xml"
    return "text"


def references(text: str, url: str, kind: str):
    if kind == "html":
        markup = Markup(text)
        base = url
        for tag, attrs, _, _ in markup.tags:
            if tag == "base" and attrs.get("href"):
                candidate = clean_url(url, attrs["href"])
                if candidate:
                    base = candidate
                    break
        for tag, attrs, start, end in markup.tags:
            rel = set((attrs.get("rel") or "").lower().split())
            for key in ("href", "src"):
                if tag not in {"a", "iframe", "script", "link"} or not attrs.get(key):
                    continue
                child = clean_url(base, attrs[key])
                if child:
                    asset = (
                        tag == "script"
                        or bool(rel & {"stylesheet", "modulepreload", "manifest"})
                        or ("preload" in rel and attrs.get("as") in {"script", "style", "fetch"})
                        or bool(ASSET.search(child))
                    )
                    yield child, asset, f"{tag}.{key}", start, end
        for script_kind, a, b in markup.scripts:
            if script_kind == "js":
                for child, asset, relation, start, end in references(text[a:b], base, "js"):
                    yield child, asset, relation, a + start, a + end
    if kind in {"js", "css"}:
        patterns = [
            r"sourceMappingURL\s*=\s*([^\s*]+)",
            r"(?:import\s*(?:[^;\n]*?\sfrom\s*)?|export\s+[^;\n]*?\sfrom\s*|import\s*\(|require\s*\()\s*['\"]([^'\"]+)['\"]",
            r"@import\s+(?:url\()?\s*['\"]?([^'\"\s;)]+)",
            r"['\"]([^'\"]+\.(?:m?js|css|json|map)(?:\?[^'\"]*)?)['\"]",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                value = match[1]
                # Dependency tokens must be paths/URLs, not prose or build commands.
                if re.search(r"[\s<>`{}|]", value):
                    continue
                child = clean_url(url, value)
                if child:
                    yield child, True, "resource_dependency", match.start(1), match.end(1)
    if kind == "xml":
        try:
            root = ET.fromstring(text)
        except ET.ParseError as error:
            raise ValueError(f"malformed XML: {error}") from error
        for node in root.iter():
            if node.tag.split("}")[-1] == "loc" and node.text:
                child = clean_url(url, node.text)
                if child:
                    nested = root.tag.split("}")[-1] == "sitemapindex"
                    yield child, nested, "sitemap_index" if nested else "sitemap", None, None
    if urlsplit(url).path.lower().endswith("robots.txt"):
        for match in re.finditer(r"^Sitemap:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE):
            child = clean_url(url, match[1])
            if child:
                yield child, True, "robots_sitemap", match.start(1), match.end(1)


def enqueue(
    store: Store, run: int, site: str, url: str, depth: int, asset: bool, state: str = "pending"
):
    existing = store.db.execute(
        "SELECT depth,asset,state,error FROM queue WHERE run_id=? AND site=? AND url=?",
        (run, site, url),
    ).fetchone()
    if existing is None:
        store.db.execute(
            "INSERT INTO queue(run_id,site,url,depth,asset,state,error) VALUES(?,?,?,?,?,?,?)",
            (run, site, url, depth, int(asset), state, None if state == "pending" else state),
        )
    else:
        # Keep minimum discovered depth and asset capability; terminal valid rows are never downgraded.
        next_state = (
            existing["state"] if existing["state"] in {"pending", "done", "failed"} else state
        )
        store.db.execute(
            "UPDATE queue SET depth=?,asset=?,state=?,error=? WHERE run_id=? AND site=? AND url=?",
            (
                min(existing["depth"], depth),
                int(bool(existing["asset"]) or asset),
                next_state,
                None if next_state == "pending" else existing["error"],
                run,
                site,
                url,
            ),
        )
    store.db.commit()


def record_expansion(store: Store, resource_id: int, depth: int):
    store.db.execute(
        "INSERT INTO expansions(resource_id,depth) VALUES(?,?) "
        "ON CONFLICT(resource_id) DO UPDATE SET depth=MIN(depth,excluded.depth)",
        (resource_id, depth),
    )
    store.db.commit()


def process(
    store,
    run,
    site,
    url,
    body,
    text,
    kind,
    depth,
    max_depth,
    external_assets,
    status=200,
    expand=True,
    *,
    collector="static",
    encoding="",
    error="",
    mentions=None,
    queue_references=True,
    parent_resource_id=0,
):
    if non_text_response(url, "", body[:16]) or kind == "binary":
        if queue_references:
            enqueue(store, run, site, url, depth, False, "skipped_type")
        return None
    resource_id = store.save(
        run,
        site,
        url,
        body,
        text,
        kind,
        status,
        error,
        collector=collector,
        encoding=encoding,
        mentions=mentions,
        parent_resource_id=parent_resource_id,
    )
    if expand:
        try:
            children = list(references(text, url, kind))
        except ValueError:
            if queue_references:
                record_expansion(store, resource_id, depth)
            raise
        for child, asset, relation, start, end in children:
            permitted = authorized(child, site, asset, external_assets)
            store.edge(
                run,
                site,
                url,
                child,
                relation,
                parent_resource_id=resource_id,
                start=start,
                end=end,
            )
            state = "pending" if permitted else "skipped_scope"
            if non_text_url(child):
                state = "skipped_type"
            if permitted and not asset and depth >= max_depth:
                state = "skipped_depth" if state == "pending" else state
            if queue_references:
                enqueue(
                    store,
                    run,
                    site,
                    child,
                    depth
                    if relation in {"sitemap", "sitemap_index", "robots_sitemap"}
                    else depth + 1,
                    asset,
                    state,
                )
        if queue_references:
            record_expansion(store, resource_id, depth)
    if kind == "json":
        try:
            mapping = json.loads(text)
        except (ValueError, TypeError):
            return resource_id
        if (
            isinstance(mapping, dict)
            and "sourcesContent" in mapping
            and not isinstance(mapping["sourcesContent"], list)
        ):
            raise ValueError("source map sourcesContent must be an array")
        if isinstance(mapping, dict) and isinstance(mapping.get("sourcesContent"), list):
            sources = mapping["sourcesContent"]
            for index, content in enumerate(sources):
                if not isinstance(content, str):
                    continue
                derived = f"{url}#sourcesContent/{index}"
                try:
                    encoded = content.encode("utf-8")
                except UnicodeEncodeError:
                    encoded = content.encode("utf-8", errors="replace")
                    store.save(
                        run,
                        site,
                        derived,
                        encoded,
                        encoded.decode(),
                        "js",
                        status,
                        "invalid Unicode in source map",
                        parent_resource_id=resource_id,
                        collector="source_map",
                    )
                    enqueue(store, run, site, derived, depth, True, "failed")
                    continue
                store.save(
                    run,
                    site,
                    derived,
                    encoded,
                    content,
                    "js",
                    status,
                    parent_resource_id=resource_id,
                    collector="source_map",
                )
                store.edge(
                    run, site, url, derived, "source_map_content", parent_resource_id=resource_id
                )
    return resource_id


def next_fingerprint(store: Store, run: int, site: str, url: str, fingerprints: list[str]):
    forbidden = dict(
        store.db.execute(
            "SELECT fingerprint,COUNT(*) FROM static_requests WHERE run_id=? AND site=? AND url=? AND status=403 GROUP BY fingerprint",
            (run, site, url),
        )
    )
    return next((p for p in fingerprints if forbidden.get(p, 0) < FORBIDDEN_ATTEMPTS), None)


def crawl(
    store: Store,
    run: int,
    sites: list[str],
    depth: int,
    delay: float,
    external_assets: set[str],
    max_bytes: int,
    max_urls: int = 0,
    user_agent: str | None = None,
    fingerprints=DEFAULT_FINGERPRINTS,
):
    fingerprints = validate_fingerprints(fingerprints)
    authorized_sites = {canonical_url(site) for site in sites}
    # Only configured sites seed work. Existing rows cannot authorize their own site.
    for site in sorted(authorized_sites):
        enqueue(store, run, site, site, 0, False)
        for path in ("/robots.txt", "/sitemap.xml"):
            enqueue(store, run, site, urljoin(site, path), 0, False)
    store.db.execute(
        "CREATE INDEX IF NOT EXISTS queue_pending_schedule ON queue(run_id,state,depth)"
    )
    with FingerprintClient(user_agent=user_agent) as client:
        count = 0
        while not max_urls or count < max_urls:
            row = store.db.execute(
                "SELECT * FROM queue WHERE run_id=? AND state='pending' ORDER BY depth,rowid LIMIT 1",
                (run,),
            ).fetchone()
            if row is None:
                break
            url, row_site = row["url"], row["site"]
            request_id = None
            try:
                site = canonical_url(row_site)
                if site not in authorized_sites:
                    store.db.execute(
                        "UPDATE queue SET state='skipped_scope',error='site is not in saved authorization' WHERE run_id=? AND site=? AND url=?",
                        (run, row_site, url),
                    )
                    store.db.commit()
                    continue
                url = canonical_url(url)
                if not authorized(url, site, bool(row["asset"]), external_assets):
                    raise ValueError("outside authorized target/asset hosts")
                if non_text_url(url):
                    store.db.execute(
                        "UPDATE queue SET state='skipped_type',error='non-target resource' WHERE run_id=? AND site=? AND url=?",
                        (run, row_site, row["url"]),
                    )
                    store.db.commit()
                    continue
                fingerprint = next_fingerprint(store, run, site, url, fingerprints)
                if fingerprint is None:
                    raise ValueError("HTTP 403: fingerprint attempts exhausted")
                count += 1
                time.sleep(delay)
                store.db.execute(
                    "INSERT INTO attempts(run_id,site,url,count) VALUES(?,?,?,1) ON CONFLICT(run_id,site,url) DO UPDATE SET count=count+1",
                    (run, site, url),
                )
                request_id = store.db.execute(
                    "INSERT INTO static_requests(run_id,site,url,fingerprint) VALUES(?,?,?,?)",
                    (run, site, url, fingerprint),
                ).lastrowid
                store.db.commit()
                with client.stream("GET", url, fingerprint=fingerprint) as response:
                    store.db.execute(
                        "UPDATE static_requests SET status=? WHERE id=?",
                        (response.status_code, request_id),
                    )
                    store.db.commit()
                    is_redirect = response.status_code in {301, 302, 303, 307, 308}
                    location = response.headers.get("location")
                    if location:
                        target = clean_url(url, location)
                        if target:
                            store.save(
                                run,
                                site,
                                url + "#location",
                                location.encode(),
                                location,
                                "response_header",
                                response.status_code,
                                collector="static_header",
                            )
                            store.edge(run, site, url, target, "redirect")
                            if is_redirect and authorized(
                                target, site, bool(row["asset"]), external_assets
                            ):
                                enqueue(store, run, site, target, row["depth"], bool(row["asset"]))
                    mime = response.headers.get("content-type", "")
                    if non_text_response(url, mime):
                        store.db.execute(
                            "UPDATE queue SET state='skipped_type',error='non-target response type' WHERE run_id=? AND site=? AND url=?",
                            (run, row_site, row["url"]),
                        )
                        store.db.commit()
                        continue
                    chunks, size, binary = [], 0, False
                    prefix = b""
                    for chunk in response.iter_content():
                        prefix = (prefix + chunk[:16])[:16]
                        if non_text_response(url, mime, prefix):
                            binary = True
                            break
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValueError(f"response exceeds {max_bytes} bytes")
                        chunks.append(chunk)
                    if binary:
                        store.db.execute(
                            "UPDATE queue SET state='skipped_type',error='binary response signature' WHERE run_id=? AND site=? AND url=?",
                            (run, row_site, row["url"]),
                        )
                        store.db.commit()
                        continue
                    body = b"".join(chunks)
                    decoded_body = body
                    if body.startswith(b"\x1f\x8b") and urlsplit(url).path.lower().endswith(".gz"):
                        store.save(
                            run,
                            row_site,
                            url,
                            body,
                            body.decode("utf-8", errors="replace"),
                            "compressed",
                            response.status_code,
                            collector="static_received",
                            encoding="binary",
                            mentions=[],
                        )
                        with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
                            decoded_body = compressed.read(max_bytes + 1)
                        if len(decoded_body) > max_bytes:
                            raise ValueError("decompressed sitemap exceeds response limit")
                    text, encoding, decode_warning = decode_body(decoded_body, mime)
                    kind = kind_for(url, mime)
                    if store.db.execute(
                        "SELECT 1 FROM edges WHERE run_id=? AND site=? AND child=? AND relation IN ('robots_sitemap','sitemap_index')",
                        (run, row_site, row["url"]),
                    ).fetchone():
                        kind = "xml"
                    received = store.save(
                        run,
                        row_site,
                        url,
                        body,
                        text,
                        kind,
                        response.status_code,
                        decode_warning,
                        collector="static_received",
                        encoding=encoding,
                        mentions=[],
                    )
                    store.db.execute(
                        "UPDATE static_requests SET resource_id=? WHERE id=?",
                        (received, request_id),
                    )
                    store.db.commit()
                    progress(store, run, "response_parse", url)
                    process(
                        store,
                        run,
                        row_site,
                        url,
                        body,
                        text,
                        kind,
                        row["depth"],
                        depth,
                        external_assets,
                        response.status_code,
                        expand=200 <= response.status_code < 300,
                        encoding=encoding,
                        error=decode_warning,
                    )
                    error = decode_warning or (
                        f"HTTP {response.status_code}" if response.status_code >= 400 else None
                    )
                    if is_redirect and (
                        not location
                        or not clean_url(url, location)
                        or not authorized(
                            clean_url(url, location), site, bool(row["asset"]), external_assets
                        )
                    ):
                        error = "redirect outside authorized scope or invalid location"
                    state = (
                        "failed"
                        if response.status_code >= 400 or decode_warning or error
                        else "done"
                    )
                    store.db.execute(
                        "UPDATE queue SET state=?,error=? WHERE run_id=? AND site=? AND url=?",
                        (state, error, run, row_site, row["url"]),
                    )
            except (RequestException, ValueError, LookupError, OSError, EOFError) as error:
                store.db.rollback()
                store.db.execute(
                    "UPDATE queue SET state='failed',error=? WHERE run_id=? AND site=? AND url=?",
                    (str(error), run, row_site, row["url"]),
                )
                if request_id is not None:
                    store.db.execute(
                        "UPDATE static_requests SET error=? WHERE id=?", (str(error), request_id)
                    )
            if (
                request_id is not None
                and store.db.execute(
                    "SELECT status FROM static_requests WHERE id=?", (request_id,)
                ).fetchone()[0]
                == 403
            ):
                following = next_fingerprint(store, run, site, url, fingerprints)
                store.db.execute(
                    "UPDATE queue SET state=?,error=? WHERE run_id=? AND site=? AND url=?",
                    (
                        "pending" if following else "failed",
                        f"HTTP 403: {fingerprint}; "
                        + ("retry queued" if following else "all fingerprints exhausted"),
                        run,
                        row_site,
                        row["url"],
                    ),
                )
                if following and following != fingerprint:
                    progress(
                        store,
                        run,
                        "fingerprint_rotated",
                        json.dumps({"url": url, "from": fingerprint, "to": following}),
                    )
            store.db.commit()


def progress(store, run, phase, detail=""):
    store.db.execute(
        "INSERT INTO run_events(run_id,event,detail) VALUES(?,?,?)", (run, phase, detail)
    )
    store.db.commit()


def import_katana(
    store: Store, path: str, site: str, run: int, depth: int, external_assets: set[str]
):
    site = canonical_url(site)
    with Path(path).open(encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            try:
                item = json.loads(line)
                request = item["request"]
                url = canonical_url(request["endpoint"])
                if request.get("source"):
                    store.edge(run, site, request["source"], url, "katana_reference")
                response = item.get("response", {})
                status = response.get("status_code", 0)
                error = item.get("error") or (f"HTTP {status}" if not 200 <= status < 400 else "")
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
                    if non_text_response(url, mime, text.encode("utf-8")[:16]):
                        store.save(
                            run,
                            site,
                            url + "#observed-url",
                            url.encode(),
                            url,
                            "katana_url",
                            collector="katana_url",
                        )
                        enqueue(store, run, site, url, 0, False, "skipped_type")
                        progress(store, run, "import_record", str(number))
                        continue
                    process(
                        store,
                        run,
                        site,
                        url,
                        text.encode("utf-8"),
                        text,
                        kind_for(url, mime),
                        0,
                        depth,
                        external_assets,
                        status,
                        expand=not error,
                        collector="katana",
                        encoding="upstream decoded",
                        error=error,
                    )
                else:
                    error = error or "Katana record has no response body"
                enqueue(
                    store, run, site, url, 0, bool(ASSET.search(url)), "failed" if error else "done"
                )
                store.db.execute(
                    "UPDATE queue SET state=?,error=? WHERE run_id=? AND site=? AND url=?",
                    ("failed" if error else "done", error, run, site, url),
                )
                store.db.commit()
                progress(store, run, "import_record", str(number))
            except (ValueError, KeyError, TypeError) as error:
                store.db.rollback()
                progress(store, run, "import_failed", f"line {number}: {type(error).__name__}")
                raise ValueError(f"Katana import stopped at line {number}") from error
    progress(store, run, "import_finished")
