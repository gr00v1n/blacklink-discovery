import hashlib
import json
import subprocess

from blacklink_discovery.store import Store


def test_results_cli_filters_pages_and_evidence(tmp_path):
    store = Store(str(tmp_path))
    run = store.new_run("query-test")
    other = store.new_run("other-run")
    site = "https://business.example/"
    text = (
        '// 中文说明\n// legacy.example.net\nconst h="cdn."+"example.net";\n// legacy.example.net\n'
    )
    store.save(run, site, site + "app.js", text.encode(), text, "js")
    store.save(
        other, site, site + "other.js", b"// other.example.net", "// other.example.net", "js"
    )
    store.save(
        run,
        "https://second.example/",
        "https://second.example/app.js",
        b"// legacy.example.net",
        "// legacy.example.net",
        "js",
    )
    store.close()

    def cli(*args, code=0, output=tmp_path):
        result = subprocess.run(
            ["blacklink-discovery", "--output", str(output), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == code, result.stderr + result.stdout
        return json.loads(result.stdout) if code == 0 else result.stderr

    before = hashlib.sha256((tmp_path / "discovery.sqlite").read_bytes()).hexdigest()
    summary = cli(
        "domains",
        "--run",
        str(run),
        "--site",
        site,
        "--source",
        "JS_COMMENT",
        "--domain",
        "LEGACY.EXAMPLE.NET.",
    )
    assert summary["total"] == 1
    assert summary["items"][0]["occurrences"] == 2
    assert summary["items"][0]["domain"] == "legacy.example.net"
    first = cli(
        "findings", "--run", str(run), "--site", site, "--source", "JS_COMMENT", "--limit", "1"
    )
    assert first["total"] == 2 and first["next_offset"] == 1
    second = cli(
        "findings",
        "--run",
        str(run),
        "--site",
        site,
        "--source",
        "JS_COMMENT",
        "--limit",
        "1",
        "--offset",
        "1",
    )
    assert second["next_offset"] is None
    token = first["items"][0]["finding_id"]
    assert token != second["items"][0]["finding_id"]
    context = cli("evidence", "--run", str(run), "--finding", token, "--context-lines", "0")
    assert context["text"] == "// legacy.example.net"
    assert context["line"] == 2 and context["context_first_line"] == 2
    assert context["integrity_ok"] and not context["truncated"]
    assert cli("findings", "--run", str(run), "--domain", "other.example.net")["total"] == 0
    assert cli("findings", "--run", str(run), "--site", "' OR 1=1 --")["total"] == 0
    assert cli("findings", "--run", str(run), "--offset", "999")["items"] == []
    cli("findings", "--run", str(run), "--limit", "501", code=2)
    cli("findings", "--run", str(run), "--offset", "-1", code=2)
    cli("evidence", "--run", str(other), "--finding", token, code=2)
    cli("domains", "--run", "999", code=2)
    after = hashlib.sha256((tmp_path / "discovery.sqlite").read_bytes()).hexdigest()
    assert before == after  # Query commands must not initialize/mutate or export.
    assert not (tmp_path / "results.xlsx").exists()
    missing = tmp_path / "absent"
    cli("domains", "--run", "1", code=2, output=missing)
    assert not missing.exists()
    decoded = tmp_path / context["decoded_text_path"]
    decoded.write_text("tampered")
    assert "hash mismatch" in cli("evidence", "--run", str(run), "--finding", token, code=2)


def test_evidence_long_lines_stale_ids_and_safe_paths(tmp_path):
    store = Store(str(tmp_path))
    run = store.new_run("evidence-test")
    site = "https://business.example/"
    text = "// " + "x " * 3000 + "legacy.example.net" + " x" * 3000
    store.save(run, site, site + "app.js", text.encode(), text, "js")
    store.close()

    def cli(*args, code=0):
        result = subprocess.run(
            ["blacklink-discovery", "--output", str(tmp_path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == code, result.stderr + result.stdout
        return json.loads(result.stdout) if code == 0 else result.stderr

    token = cli("findings", "--run", str(run), "--domain", "legacy.example.net")["items"][0][
        "finding_id"
    ]
    context = cli("evidence", "--run", str(run), "--finding", token, "--max-chars", "100")
    assert len(context["text"]) <= 100 and "legacy.example.net" in context["text"]
    assert context["truncated"]
    store = Store(str(tmp_path))
    replacement = "// replacement.example.net"
    store.save(run, site, site + "app.js", replacement.encode(), replacement, "js")
    store.close()
    assert cli("evidence", "--run", str(run), "--finding", token)["host"] == "legacy.example.net"
    token = cli("findings", "--run", str(run))["items"][0]["finding_id"]
    store = Store(str(tmp_path))
    store.db.execute("UPDATE text_views SET path='../outside'")
    store.db.commit()
    store.close()
    token = cli("findings", "--run", str(run))["items"][0]["finding_id"]
    assert "unsafe" in cli("evidence", "--run", str(run), "--finding", token, code=2)


def test_legacy_cr_position_evidence_stays_readable(tmp_path):
    from blacklink_discovery.results import evidence, findings
    from blacklink_discovery.supervise import verify

    store = Store(str(tmp_path))
    text = "// header\r// legacy.example.net"
    try:
        run = store.new_run("legacy")
        resource = store.save(
            run,
            "https://site.example/",
            "https://site.example/app.js",
            text.encode(),
            text,
            "js",
            collector="legacy",
        )
        store.db.execute("UPDATE findings SET line=1,col=14 WHERE resource_id=?", (resource,))
        store.db.commit()
        token = findings(store, run, None, None, None, 50, 0)["items"][0]["finding_id"]
        assert evidence(store, run, token, 5, 4000)["host"] == "legacy.example.net"
        assert verify(store, run)["integrity_ok"]
    finally:
        store.close()
