import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from blacklink_discovery.browser import BrowserLimits, collect_browser
from blacklink_discovery.store import Store
from blacklink_discovery.supervise import status, verify


def chrome_path():
    from playwright.sync_api import sync_playwright

    candidate = os.environ.get("TEST_CHROME")
    if candidate:
        return candidate
    with sync_playwright() as p:
        if Path(p.chromium.executable_path).is_file():
            return p.chromium.executable_path
    pytest.skip("install optional Playwright Chromium or set TEST_CHROME for browser E2E")


def test_browser_records_binary_urls_without_downloading_or_parsing_files(tmp_path):
    pytest.importorskip("playwright")
    chrome = chrome_path()
    requested = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requested.append(self.path)
            body = b"""<img src="/photo.png"><iframe src="/report.pdf"></iframe>
                <script>fetch('/download');fetch('/mislabelled');</script>"""
            mime = "text/html"
            if self.path in {"/download", "/mislabelled"}:
                body = b"%PDF-1.6 binary-only.example.net"
                mime = "application/pdf" if self.path == "/download" else "text/plain"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    store = Store(str(tmp_path))
    try:
        run = asyncio.run(collect_browser(store, site, None, chrome, 1, set()))
        assert "/photo.png" not in requested and "/report.pdf" not in requested
        assert "/download" in requested and "/mislabelled" in requested
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM request_observations WHERE run_id=? AND state='not_text'",
                (run,),
            ).fetchone()[0]
            >= 4
        )
        assert store.db.execute(
            "SELECT 1 FROM resources WHERE run_id=? AND collector='browser_url' AND url LIKE '%/report.pdf#observed-url'",
            (run,),
        ).fetchone()
        assert not store.db.execute(
            "SELECT 1 FROM findings WHERE host='binary-only.example.net'"
        ).fetchone()
        assert verify(store, run)["integrity_ok"]
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_combined_scan_follows_dynamic_links_without_manual_seeds(tmp_path):
    pytest.importorskip("playwright")
    from blacklink_discovery.supervise import resume, save_config

    chrome = chrome_path()
    requested = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requested.append(self.path)
            browser = "Chrome" in self.headers.get("User-Agent", "")
            body = {
                "/": b"<script>document.write('<a href=\"/child\">next</a>')</script>",
                "/child": b"<!-- legacy.example.net --><script>document.write('<a href=\"/grandchild\">next</a>')</script>",
                "/grandchild": b'<a href="/">loop</a><a href="/too-deep">depth</a><a href="http://localhost:1/outside">external</a>',
            }.get(self.path, b"not found")
            self.send_response(
                200 if browser and self.path in {"/", "/child", "/grandchild"} else 403
            )
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body if browser else b"denied")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    store = Store(str(tmp_path))
    try:
        run = store.new_run("combined-test")
        save_config(
            store,
            run,
            {
                "sites": [site],
                "depth": 2,
                "delay": 0,
                "asset_hosts": [],
                "max_bytes": 100000,
                "browser_crawl": True,
                "browser_chrome": chrome,
            },
        )
        resume(store, run, max_urls=3)
        assert not status(store, run)["queue_exhausted"]
        resume(store, run)
        assert "/child" in requested and "/grandchild" in requested
        assert "/too-deep" not in requested
        assert status(store, run)["queue_exhausted"]
        assert store.db.execute(
            "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=? AND f.host='legacy.example.net' AND f.source='HTML_COMMENT'",
            (run,),
        ).fetchone()[0]
        assert store.db.execute(
            "SELECT COUNT(*) FROM queue WHERE run_id=? AND state='skipped_scope'", (run,)
        ).fetchone()[0]
        assert verify(store, run)["integrity_ok"]
        before = len(requested)
        resume(store, run)
        assert len(requested) == before
        assert not list(tmp_path.glob("*.csv")) and not list(tmp_path.glob("*.xlsx"))
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("shortcut", ["same_wave", "later_wave", "navigated_later_wave"])
def test_combined_scan_reexpands_shorter_paths_and_preserves_crlf(tmp_path, shortcut):
    pytest.importorskip("playwright")
    from blacklink_discovery.supervise import resume, save_config

    chrome = chrome_path()
    requested = []
    target = "/x" if shortcut == "same_wave" else "/late"
    pages = {
        "/": '<a href="/a">long</a><iframe src="/frame"></iframe><script src="/app.js"></script>',
        "/a": '<a href="/b">next</a>',
        "/b": '<a href="/x">next</a>',
        "/x": '<a href="/y">previously too deep</a>',
        "/y": "<!-- reached.example.net -->",
        "/late": "<script>document.write('<a href=\"/x\">shortcut</a>')</script>",
        "/frame": '<iframe src="/frame2"></iframe>',
        "/frame2": '<iframe src="/frame3"></iframe>',
        "/frame3": '<a href="/frame-deep">too deep</a>',
        "/app.js": "\r\n// legacy.example.net\r\ndocument.write('<a href=\""
        + target
        + "\">shortcut</a>');",
    }
    if shortcut == "navigated_later_wave":
        pages["/x"] = "<script>location.href='/landing'</script>"
        pages["/landing"] = '<a href="/y">previously too deep</a>'

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requested.append(self.path)
            self.send_response(200 if self.path in pages else 404)
            self.send_header(
                "Content-Type", "text/javascript" if self.path == "/app.js" else "text/html"
            )
            self.end_headers()
            self.wfile.write(pages.get(self.path, "missing").encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    store = Store(str(tmp_path))
    try:
        run = store.new_run("short-path")
        save_config(
            store,
            run,
            {
                "sites": [site],
                "depth": 3,
                "delay": 0,
                "asset_hosts": [],
                "max_bytes": 100000,
                "browser_crawl": True,
                "browser_chrome": chrome,
            },
        )
        resume(store, run)
        assert "/y" in requested
        assert "/frame-deep" not in requested
        assert requested.count("/x") == 2  # One static request and one browser visit.
        assert verify(store, run)["integrity_ok"]
        assert status(store, run)["workflow_exhausted"]
        imported = store.db.execute(
            "SELECT r.evidence_path,t.path FROM resources r JOIN text_views t ON t.resource_id=r.id WHERE r.run_id=? AND r.url=? AND r.collector='browser_response'",
            (run, site + "app.js"),
        ).fetchone()
        assert imported
        assert (tmp_path / imported[0]).read_bytes() == (tmp_path / imported[1]).read_bytes()
        assert b"\r\n" in (tmp_path / imported[1]).read_bytes()
        assert not list(tmp_path.glob("*.csv"))
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize(
    "first_status,final_status", [(200, 403), (403, 200), (200, "pushState"), (200, "replaceState")]
)
def test_browser_dom_tracks_final_document_status(tmp_path, first_status, final_status):
    pytest.importorskip("playwright")
    from blacklink_discovery.supervise import merge_browser

    chrome = chrome_path()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            initial = self.path == "/"
            if isinstance(final_status, str):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    (
                        "<script>history."
                        + final_status
                        + "({},'', '/route');document.write('<a href=\"/only-final\">link</a>')</script>"
                    ).encode()
                )
                return
            self.send_response(first_status if initial else final_status)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<script>setTimeout(()=>location.href='/final',100)</script>"
                if initial
                else b'<a href="/only-final">link</a>'
            )

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    store = Store(str(tmp_path))
    try:
        child = asyncio.run(collect_browser(store, site, None, chrome, 0.5, set()))
        assert store.db.execute(
            "SELECT status FROM resources WHERE run_id=? AND collector='browser_dom'", (child,)
        ).fetchone()[0] == (200 if isinstance(final_status, str) else final_status)
        parent = store.new_run("merge")
        merge_browser(store, parent, child, site, 0, {"depth": 2, "asset_hosts": []})
        found = store.db.execute(
            "SELECT COUNT(*) FROM queue WHERE run_id=? AND url=?", (parent, site + "only-final")
        ).fetchone()[0]
        assert bool(found) == (final_status == 200 or isinstance(final_status, str))
        assert verify(store, parent)["integrity_ok"]
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_browser_read_only_capture_redirects_failures_and_limits(tmp_path):
    pytest.importorskip("playwright")
    chrome = chrome_path()
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(("GET", self.path))
            code, mime, body = 200, "text/html", b""
            if self.path == "/":
                body = b"""<body><!-- raw.example.net --><script src="/app.js"></script></body>"""
            elif self.path == "/app.js":
                mime = "Application/JavaScript"
                body = b"""// legacy.example.net
                document.body.insertAdjacentHTML('beforeend','<a href="https://dynamic.example.net">dynamic</a>');
                fetch('/data'); fetch('/post',{method:'POST'});fetch('/redirect');
                new WebSocket('ws://127.0.0.1:1/socket');"""
            elif self.path == "/data":
                mime = "application/json"
                body = b'{"host":"api\\u002eexample\\u002enet"}'
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header(
                    "Location", f"http://localhost:{self.server.server_port}/forbidden"
                )
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"redirect.example.net")
                return
            elif self.path == "/denied":
                code = 403
                body = b"denied.example.net"
            elif self.path == "/huge":
                body = b"x" * 10000
            elif self.path == "/no-mime":
                body = b"<script>fetch('/payload');fetch('/broken')</script>"
            elif self.path in {"/payload", "/broken"}:
                self.send_response(500 if self.path == "/broken" else 200)
                self.end_headers()
                self.wfile.write(b"hidden.example.net")
                return
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def do_POST(self):
            requests.append(("POST", self.path))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}"
    store = Store(str(tmp_path))
    try:
        run = asyncio.run(collect_browser(store, site + "/", None, chrome, 0.5, set()))
        hosts = {
            r[0]
            for r in store.db.execute(
                "SELECT host FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=?",
                (run,),
            )
        }
        assert {
            "raw.example.net",
            "legacy.example.net",
            "dynamic.example.net",
            "api.example.net",
            "redirect.example.net",
        } <= hosts
        assert not any(method == "POST" for method, _ in requests)
        assert not any(path == "/forbidden" for _, path in requests)
        assert verify(store, run)["integrity_ok"]
        assert status(store, run)["queue"].get("pending", 0) == 0
        assert not status(store, run)["coverage_clear"]
        assert (
            store.db.execute(
                "SELECT count(*) FROM request_observations WHERE run_id=? AND state='blocked'",
                (run,),
            ).fetchone()[0]
            >= 2
        )
        denied = asyncio.run(collect_browser(store, site + "/denied", None, chrome, 0, set()))
        assert not status(store, denied)["coverage_clear"]
        assert store.db.execute(
            "SELECT count(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=? AND host='denied.example.net'",
            (denied,),
        ).fetchone()[0]
        limited = asyncio.run(
            collect_browser(
                store, site + "/huge", None, chrome, 0, set(), BrowserLimits(response_bytes=100)
            )
        )
        assert not status(store, limited)["coverage_clear"]
        untyped = asyncio.run(collect_browser(store, site + "/no-mime", None, chrome, 0.5, set()))
        assert not status(store, untyped)["coverage_clear"]
        assert store.db.execute(
            "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=? AND r.url LIKE '%/payload' AND f.host='hidden.example.net'",
            (untyped,),
        ).fetchone()[0]
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_browser_connection_failure_closes_without_transport_race(tmp_path):
    pytest.importorskip("playwright")
    chrome = chrome_path()
    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = server.server_port
    server.server_close()
    store = Store(str(tmp_path))
    try:
        run = asyncio.run(
            collect_browser(store, f"http://127.0.0.1:{port}/", None, chrome, 0, set())
        )
        report = status(store, run)
        assert not report["coverage_clear"]
        assert "request failed" in report["last_event"]["detail"]
        assert "cleanup failed" not in report["last_event"]["detail"]
        assert "cleanup deadline" not in report["last_event"]["detail"]
        assert verify(store, run)["integrity_ok"]
    finally:
        store.close()


def test_browser_success_and_parser_failure_preserves_received_source(tmp_path, monkeypatch):
    pytest.importorskip("playwright")
    chrome = chrome_path()
    body = b"<body><!-- retained.example.net --></body>"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header(
                "Content-Type", "application/json" if self.path.startswith("/item") else "text/html"
            )
            self.end_headers()
            self.wfile.write(
                b"<script>for(let i=0;i<16;i++)fetch('/item'+i)</script>"
                if self.path == "/burst"
                else body
            )

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    store = Store(str(tmp_path))
    try:
        successful = asyncio.run(collect_browser(store, site, None, chrome, 0, set()))
        assert status(store, successful)["coverage_clear"]
        assert verify(store, successful)["integrity_ok"]

        async def interrupted():
            import time

            started = time.monotonic()
            run = await collect_browser(
                store, site, None, chrome, 10, set(), BrowserLimits(seconds=1)
            )
            assert time.monotonic() - started < 5
            return run

        timed = asyncio.run(interrupted())
        assert not status(store, timed)["coverage_clear"]

        from blacklink_discovery.browser import parse_response

        async def dead_parser(text, kind, url, seconds):
            if kind == "json":
                raise RuntimeError("test consumer death")
            return await parse_response(text, kind, url, seconds)

        monkeypatch.setattr("blacklink_discovery.browser.parse_response", dead_parser)

        async def burst():
            import time

            started = time.monotonic()
            run = await collect_browser(store, site + "burst", None, chrome, 10, set())
            assert time.monotonic() - started < 5
            return run

        crashed = asyncio.run(burst())
        assert not status(store, crashed)["coverage_clear"]

        async def failed_dom(text, kind, url, seconds):
            if text.startswith("<html>"):
                raise RuntimeError("test DOM unexpected failure")
            return await parse_response(text, kind, url, seconds)

        monkeypatch.setattr("blacklink_discovery.browser.parse_response", failed_dom)
        with pytest.raises(RuntimeError, match="DOM unexpected failure"):
            asyncio.run(collect_browser(store, site, None, chrome, 0, set()))
        dom_run = store.db.execute("SELECT MAX(id) FROM runs").fetchone()[0]
        assert not status(store, dom_run)["coverage_clear"]
        assert status(store, dom_run)["last_event"]["event"] == "browser_partial"
        assert store.db.execute(
            "SELECT COUNT(*) FROM resources WHERE run_id=? AND collector='browser_dom_received'",
            (dom_run,),
        ).fetchone()[0]

        async def failed_parser(*args):
            raise TimeoutError("test parser deadline")

        monkeypatch.setattr("blacklink_discovery.browser.parse_response", failed_parser)
        failed = asyncio.run(collect_browser(store, site, None, chrome, 0, set()))
        assert not status(store, failed)["coverage_clear"]
        assert status(store, failed)["queue"].get("pending", 0) == 0
        received = store.db.execute(
            "SELECT r.evidence_path FROM request_observations o JOIN resources r ON r.id=o.resource_id WHERE o.run_id=? AND r.collector='browser_received'",
            (failed,),
        ).fetchall()
        assert received and all((tmp_path / r[0]).read_bytes() == body for r in received)
        assert store.db.execute(
            "SELECT COUNT(*) FROM resources WHERE run_id=? AND collector='browser_dom_received'",
            (failed,),
        ).fetchone()[0]
        assert verify(store, failed)["integrity_ok"]
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()


def test_shared_script_is_parsed_once_across_parent_page_batches(tmp_path):
    pytest.importorskip("playwright")
    chrome = chrome_path()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/app.js":
                body = b"const host='shared.example.net';"
                mime = "text/javascript"
            else:
                body = f'<script src="/app.js"></script><a href="{self.path}next">next</a>'.encode()
                mime = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    store = Store(str(tmp_path))
    try:
        parent = store.new_run("parent")
        store.db.execute(
            "INSERT INTO browser_fallbacks(run_id,site,url,state) VALUES(?,?,?,'started')",
            (parent, site, site),
        )
        store.db.execute(
            "INSERT INTO browser_fallbacks(run_id,site,url,state) VALUES(?,?,?,'started')",
            (parent, site, site + "next"),
        )
        store.db.commit()
        first = asyncio.run(
            collect_browser(
                store, site, None, chrome, 0, set(), parent_run=parent, parent_site=site
            )
        )
        second = asyncio.run(
            collect_browser(
                store, site + "next", None, chrome, 0, set(), parent_run=parent, parent_site=site
            )
        )
        assert first != second
        parsed = store.db.execute(
            "SELECT COUNT(*) FROM resources WHERE run_id=? AND url=? AND collector='browser_response'",
            (parent, site + "app.js"),
        ).fetchone()[0]
        mentions = store.db.execute(
            "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id "
            "WHERE r.run_id=? AND r.url=? AND f.host='shared.example.net'",
            (parent, site + "app.js"),
        ).fetchone()[0]
        positions = store.db.execute(
            "SELECT COUNT(*) FROM edges WHERE run_id=? AND child=? AND relation='browser_response'",
            (parent, site + "app.js"),
        ).fetchone()[0]
        assert positions == 2
        assert parsed == 1
        assert mentions == 1
        sites = {
            row[0]
            for row in store.db.execute(
                "SELECT DISTINCT site FROM resources WHERE run_id=? AND collector='browser_response'",
                (parent,),
            )
        }
        assert sites == {site}
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()
