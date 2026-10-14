import json
import sqlite3

import httpx

from blacklink_discovery.cli import main


def test_collection_persists_without_export_until_requested(tmp_path, monkeypatch):
    output = tmp_path / "output"
    sites = tmp_path / "sites.txt"
    sites.write_text("https://site.example/\n")
    client = httpx.Client
    monkeypatch.setattr(
        "blacklink_discovery.collect.httpx.Client",
        lambda **kwargs: client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    text="<urlset/>" if request.url.path.endswith(".xml") else "legacy.example.net",
                    headers={"content-type": "text/plain"},
                )
            ),
            **kwargs,
        ),
    )

    def cli(*args):
        monkeypatch.setattr("sys.argv", ["blacklink-discovery", "--output", str(output), *args])
        main()

    def no_exports():
        assert not (output / "current.json").exists()
        assert not (output / "generations").exists()
        assert not list(output.rglob("*.csv"))
        assert not list(output.rglob("*.xlsx"))

    cli("scan", "--sites", str(sites), "--delay", "0")
    no_exports()
    with sqlite3.connect(output / "discovery.sqlite") as db:
        assert db.execute(
            "SELECT COUNT(*) FROM findings WHERE host='legacy.example.net'"
        ).fetchone()[0]
    cli("resume", "--run", "1")
    no_exports()
    imported = tmp_path / "katana.jsonl"
    imported.write_text(
        json.dumps(
            {
                "request": {"endpoint": "https://site.example/app.js"},
                "response": {"status_code": 200, "body": "// imported.example.net"},
            }
        )
        + "\n"
    )
    cli("import-katana", "--jsonl", str(imported), "--site", "https://site.example/")
    no_exports()

    async def browser(store, url, *_args):
        run = store.new_run("browser-test")
        text = "dynamic.example.net"
        store.save(run, url, url + "#dom", text.encode(), text, "html", collector="browser_dom")
        return run

    monkeypatch.setattr("blacklink_discovery.browser.collect_browser", browser)
    cli("browser", "--url", "https://site.example/")
    no_exports()
    cli("export", "--run", "1")
    manifest = (output / "current.json").read_bytes()
    target = output / json.loads(manifest)["path"]
    assert (target / "results.xlsx").is_file()
    assert (target / "发现明细.csv").is_file()
    cli("resume", "--run", "1")
    assert (output / "current.json").read_bytes() == manifest
