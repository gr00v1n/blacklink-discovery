import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def test_supervision_cli_retry_resume_and_tamper(tmp_path):
    attempts = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            attempts.append(self.path)
            transient = self.path == "/unstable" and attempts.count(self.path) == 1
            body = (
                '<a href="/unstable">retry</a><!-- legacy.example.net -->'
                if self.path == "/"
                else "// recovered.example.net"
            )
            self.send_response(503 if transient else 200)
            self.send_header("Content-Type", "text/html" if self.path == "/" else "text/javascript")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site = f"http://127.0.0.1:{server.server_port}/"
    sites = tmp_path / "sites.txt"
    sites.write_text(site)
    output = tmp_path / "results"

    def cli(*args, code=0):
        result = subprocess.run(
            ["blacklink-discovery", "--output", str(output), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == code, result.stderr + result.stdout
        return result.stdout

    try:
        cli("scan", "--sites", str(sites), "--delay", "0", "--max-urls", "1")
        first = json.loads(cli("status", "--run", "1"))
        assert first["queue"]["pending"] > 0
        assert first["config"]["sites"] == [site]
        cli("scan", "--sites", str(sites), "--resume", "1", "--depth", "10", code=2)
        cli("resume", "--run", "1")
        failed = json.loads(cli("failures", "--run", "1"))
        assert failed["total"] == 1 and failed["items"][0]["attempts"] == 1
        before = len(attempts)
        limited = json.loads(cli("retry", "--run", "1", "--max-attempts", "1"))
        assert limited["queued"] == 0
        queued = json.loads(cli("retry", "--run", "1", "--url", site + "unstable"))
        assert queued["queued"] == 1 and len(attempts) == before
        cli("resume", "--run", "1")
        report = json.loads(cli("verify", "--run", "1"))
        assert report["integrity_ok"] and report["coverage_clear"]
        assert attempts.count("/unstable") == 2
        assert json.loads(cli("failures", "--run", "1"))["total"] == 0
        text_view = next((output / "evidence").glob("*.utf8"))
        text_view.write_text("tampered")
        broken = json.loads(cli("verify", "--run", "1", code=1))
        assert not broken["integrity_ok"]
        assert any("hash mismatch" in issue["problem"] for issue in broken["issues"])
        cli("status", "--run", "999", code=2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_project_skill_frontmatter():
    path = Path(__file__).parents[1] / ".agents/skills/supervising-blacklink-discovery/SKILL.md"
    text = path.read_text()
    assert text.startswith("---\nname: supervising-blacklink-discovery\n")
    assert path.parent.name == "supervising-blacklink-discovery"
    assert "description:" in text and "Use when" in text
    assert len(text.splitlines()) < 500
