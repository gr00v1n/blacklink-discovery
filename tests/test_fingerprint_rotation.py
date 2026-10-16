import gzip
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from blacklink_discovery.collect import enqueue
from blacklink_discovery.store import Store
from blacklink_discovery.supervise import resume, retry, save_config, status, verify


def test_real_curl_profiles_rotate_after_three_403_and_survive_resume(tmp_path):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            fingerprint = (
                "chrome" if "Chrome/" in ua else "firefox" if "Firefox/" in ua else "safari"
            )
            requests.append((self.path, fingerprint, self.headers.get("Cookie", "")))
            code = 403 if self.path in {"/recover", "/deny"} else 200
            if self.path == "/recover" and fingerprint == "safari":
                code = 200
            if self.path == "/login":
                code = 401
            if self.path == "/busy":
                code = 503
            if self.path == "/redirect":
                code = 302
            body = f"<!-- {fingerprint}.example.net -->".encode()
            if self.path == "/huge":
                body = b"x" * 10000
            if self.path == "/asset.js":
                body = gzip.compress(b"// compressed.example.net")
            self.send_response(code)
            self.send_header(
                "Content-Type",
                "application/javascript" if self.path == "/asset.js" else "text/html",
            )
            if self.path == "/asset.js":
                self.send_header("Content-Encoding", "gzip")
            if fingerprint == "chrome":
                self.send_header("Set-Cookie", "chrome_only=1; Path=/")
            if self.path == "/redirect":
                self.send_header("Location", f"http://localhost:{self.server.server_port}/outside")
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
        run = store.new_run("profiles")
        save_config(
            store,
            run,
            {"sites": [site], "depth": 2, "delay": 0, "asset_hosts": [], "max_bytes": 1000},
        )
        enqueue(store, run, site, site + "recover", 0, False)
        resume(store, run, max_urls=2)
        assert [fp for path, fp, _ in requests if path == "/recover"] == ["chrome", "chrome"]
        store.close()
        store = Store(str(tmp_path))
        resume(store, run, max_urls=2)
        assert [fp for path, fp, _ in requests if path == "/recover"] == ["chrome"] * 3 + ["safari"]
        assert all(not cookie for path, fp, cookie in requests if fp == "safari")
        assert (
            store.db.execute(
                "SELECT state FROM queue WHERE run_id=? AND url=?", (run, site + "recover")
            ).fetchone()[0]
            == "done"
        )
        for path in ("deny", "login", "busy", "redirect", "huge", "asset.js"):
            enqueue(store, run, site, site + path, 0, False)
        resume(store, run)
        assert [fp for path, fp, _ in requests if path == "/deny"] == ["chrome"] * 3 + [
            "safari"
        ] * 3 + ["firefox"] * 3
        for path in ("/login", "/busy", "/redirect"):
            assert sum(p == path for p, _, _ in requests) == 1
        assert not any(p == "/outside" for p, _, _ in requests)
        before = len(requests)
        retry(store, run, 100, [site + "deny"])
        resume(store, run)
        assert (
            len(requests) == before
        )  # Explicit retry cannot reset exhausted 403 profile counters.
        rows = store.db.execute(
            "SELECT fingerprint,status,resource_id FROM static_requests WHERE run_id=? AND url=? ORDER BY id",
            (run, site + "recover"),
        ).fetchall()
        assert [r[1] for r in rows] == [403, 403, 403, 200]
        assert all(r[2] is not None for r in rows)
        assert (
            store.db.execute(
                "SELECT error FROM queue WHERE run_id=? AND url=?", (run, site + "huge")
            ).fetchone()[0]
            == "response exceeds 1000 bytes"
        )
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM findings WHERE host='compressed.example.net'"
            ).fetchone()[0]
            == 1
        )
        assert verify(store, run)["integrity_ok"]
        assert status(store, run)["config"]["fingerprints"] == [
            "chrome142",
            "safari260",
            "firefox144",
        ]
        assert not list(tmp_path.rglob("*.csv")) and not list(tmp_path.rglob("*.xlsx"))
    finally:
        store.close()
        server.shutdown()
        server.server_close()
        thread.join()
