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
