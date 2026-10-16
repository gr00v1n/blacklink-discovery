from blacklink_discovery.collect import clean_url, kind_for, references


def test_clean_url_rejects_credentials_and_malformed_authorities():
    assert clean_url("https://safe.example/a", "../b#x") == "https://safe.example/b"
    assert clean_url("https://safe.example/", "https://user:pass@evil.example/") is None
    assert clean_url("https://safe.example/", "http://[broken/") is None


def test_html_tokens_base_and_module_references():
    links = list(
        references(
            '<link REL="preload" href="/app.mjs"><base href="/assets/"><script src="main.js"></script>',
            "https://example.test/dir/",
            "html",
        )
    )
    assert [(item[0], item[1], item[2]) for item in links] == [
        ("https://example.test/app.mjs", True, "link.href"),
        ("https://example.test/assets/main.js", True, "script.src"),
    ]
    assert links[0][3] < links[1][3]
    module = list(
        references(
            "export {x} from './x.js'; @import url(theme.css);",
            "https://example.test/app.mjs",
            "js",
        )
    )
    assert {item[0] for item in module} >= {
        "https://example.test/x.js",
        "https://example.test/theme.css",
    }


def test_mime_normalization_and_malformed_sitemap():
    assert kind_for("https://example.test/file", "Application/JavaScript; charset=UTF-8") == "js"
    assert kind_for("https://example.test/sitemap.xml.gz", "application/gzip") == "xml"
    import pytest

    with pytest.raises(ValueError, match="malformed XML"):
        list(references("<urlset>", "https://example.test/sitemap.xml", "xml"))


def test_authorized_queue_merge_error_evidence_encoding_and_sitemaps(tmp_path, mock_static_http):
    import gzip

    import httpx

    from blacklink_discovery.collect import crawl, enqueue, process
    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import verify

    site = "https://approved.example/"
    seen = []

    def respond(request):
        seen.append(str(request.url))
        if request.url.path == "/":
            return httpx.Response(
                403, text="blocked.example.net", headers={"content-type": "text/html"}
            )
        if request.url.path == "/robots.txt":
            return httpx.Response(
                200, text="Sitemap: /index", headers={"content-type": "text/plain"}
            )
        if request.url.path == "/index":
            return httpx.Response(
                200,
                text="<sitemapindex><sitemap><loc>/part.xml.gz</loc></sitemap></sitemapindex>",
                headers={"content-type": "text/plain"},
            )
        if request.url.path == "/part.xml.gz":
            return httpx.Response(
                200,
                content=gzip.compress(b"<urlset><url><loc>/article</loc></url></urlset>"),
                headers={"content-type": "application/gzip"},
            )
        if request.url.path == "/article":
            return httpx.Response(
                200,
                content='<meta charset="gbk">例子.测试<script>import "./module";</script>'.encode(
                    "gbk"
                ),
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/module":
            return httpx.Response(
                200,
                text="// module.example.net",
                headers={"content-type": "Application/JavaScript"},
            )
        return httpx.Response(200, text="<urlset/>", headers={"content-type": "application/xml"})

    mock_static_http(respond)
    store = Store(str(tmp_path))
    try:
        run = store.new_run("queue")
        enqueue(
            store,
            run,
            "https://not-approved.example/",
            "https://not-approved.example/private",
            0,
            False,
        )
        enqueue(store, run, site, site + "article", 1, False)
        enqueue(store, run, site, site + "article", 8, False, "skipped_depth")
        assert (
            store.db.execute("SELECT state FROM queue WHERE url=?", (site + "article",)).fetchone()[
                0
            ]
            == "pending"
        )
        enqueue(store, run, site, "https://assets.example/loader", 8, False, "skipped_scope")
        process(
            store,
            run,
            site,
            site + "parent",
            b"",
            '<script src="https://assets.example/loader"></script>',
            "html",
            1,
            1,
            {"assets.example"},
        )
        assert store.db.execute(
            "SELECT asset,state FROM queue WHERE url='https://assets.example/loader'"
        ).fetchone()[:] == (1, "pending")
        crawl(store, run, [site], 6, 0, {"assets.example"}, 100000)
        assert not any("not-approved" in url for url in seen)
        assert site + "part.xml.gz" in seen and site + "module" in seen
        assert {"blocked.example.net", "module.example.net", "xn--fsqu00a.xn--0zwm56d"} <= {
            r[0] for r in store.db.execute("SELECT host FROM findings")
        }
        assert verify(store, run)["integrity_ok"]
    finally:
        store.close()


def test_non_target_downloads_are_skipped_but_reference_domains_survive(tmp_path, mock_static_http):
    import httpx

    from blacklink_discovery.collect import crawl
    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import status, verify

    requested = []

    def respond(request):
        requested.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(
                200,
                text="""
                <a href="/report.PDF?download=1">report</a>
                <a href="https://archive.example.net/report.pdf">archive</a>
                <a href="/download">no extension</a>
                <a href="/mislabelled">wrong MIME</a>
                <script src="/app.js"></script>
            """,
                headers={"content-type": "text/html"},
            )
        if request.url.path in {"/download", "/mislabelled"}:
            return httpx.Response(
                200,
                content=b"%PDF-1.6 binary-only.example.net%41",
                headers={
                    "content-type": "application/pdf"
                    if request.url.path == "/download"
                    else "text/plain"
                },
            )
        if request.url.path == "/app.js":
            return httpx.Response(
                200,
                text="""
                // legacy.example.net
                const command = "npm run build && git add package.json";
                const description = "client for browser and node.js";
                import "./module.js?x=1&y=2";
            """,
                headers={"content-type": "application/javascript"},
            )
        return httpx.Response(200, text="<urlset/>" if request.url.path.endswith(".xml") else "")

    mock_static_http(respond)
    store = Store(str(tmp_path))
    try:
        run = store.new_run("binary-regression")
        crawl(store, run, ["https://site.example/"], 3, 0, set(), 100000)
        assert "/report.PDF" not in requested
        assert "/module.js" in requested
        assert not any("npm" in path or "client for" in path for path in requested)
        hosts = {r[0] for r in store.db.execute("SELECT host FROM findings")}
        assert {"archive.example.net", "legacy.example.net"} <= hosts
        assert "binary-only.example.net" not in hosts
        assert not store.db.execute(
            "SELECT 1 FROM resources WHERE url LIKE '%/download' OR url LIKE '%/mislabelled'"
        ).fetchone()
        assert status(store, run)["queue"]["skipped_type"] == 4
        assert status(store, run)["coverage_clear"]
        assert verify(store, run)["integrity_ok"]
    finally:
        store.close()


def test_combined_resume_reuses_linked_browser_evidence_and_saved_ua(
    tmp_path, monkeypatch, mock_static_http
):
    import httpx
    import pytest

    from blacklink_discovery import supervise
    from blacklink_discovery.store import Store

    seen_ua, browser_calls, reports = [], [], []

    def response(request):
        seen_ua.append(request.headers["user-agent"])
        return httpx.Response(
            200, text="<body>static</body>", headers={"content-type": "text/html"}
        )

    mock_static_http(response)

    async def browser(store, url, state, chrome, wait, hosts, *, parent_run, parent_site):
        browser_calls.append(url)
        reports.append(supervise.status(store, parent_run))
        child = store.new_run("anonymous-browser")
        store.db.execute(
            "UPDATE browser_fallbacks SET browser_run_id=? WHERE run_id=? AND site=? AND url=?",
            (child, parent_run, parent_site, url),
        )
        body = b"\r\n<!-- legacy.example.net -->\r\n"
        store.save(parent_run, url, url, body, body.decode(), "html", collector="browser_response")
        store.db.execute(
            "INSERT INTO queue(run_id,site,url,depth,asset,state) VALUES(?,?,?,0,0,'done')",
            (child, url, url),
        )
        store.db.commit()
        return child

    monkeypatch.setattr("blacklink_discovery.browser.collect_browser", browser)
    original_merge = supervise.merge_browser

    def interrupted(*args):
        raise RuntimeError("interrupted before merge")

    monkeypatch.setattr(supervise, "merge_browser", interrupted)
    store = Store(str(tmp_path))
    try:
        run = store.new_run("recovery")
        supervise.save_config(
            store,
            run,
            {
                "sites": ["https://site.example/"],
                "depth": 2,
                "delay": 0,
                "asset_hosts": [],
                "max_bytes": 100000,
                "browser_crawl": True,
                "user_agent": "CompanyScanner/Test",
            },
        )
        with pytest.raises(RuntimeError, match="before merge"):
            supervise.resume(store, run)
        assert not reports[0]["coverage_clear"] and reports[0]["browser_pending"] == 1
        monkeypatch.setattr(supervise, "merge_browser", original_merge)
        supervise.resume(store, run)
        assert browser_calls == ["https://site.example/"]
        assert set(seen_ua) == {"CompanyScanner/Test"}
        assert supervise.verify(store, run)["integrity_ok"]
        assert supervise.status(store, run)["workflow_exhausted"]
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=? AND host='legacy.example.net'",
                (run,),
            ).fetchone()[0]
            == 1
        )
    finally:
        store.close()


def test_resume_bad_sitemap_does_not_poison_remaining_queue(tmp_path, mock_static_http):
    import httpx

    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import resume, save_config, status

    requested = []

    def response(request):
        requested.append(request.url.path)
        body = {
            "/index.html": '<a href="/good.html">next</a>',
            "/sitemap.xml": "not XML",
            "/good.html": "<!-- reached.example.net -->",
        }.get(request.url.path, "")
        return httpx.Response(200, text=body, headers={"content-type": "text/plain"})

    mock_static_http(response)
    store = Store(str(tmp_path))
    try:
        run = store.new_run("bad-sitemap")
        # Use HTML paths so Content-Type is immaterial to page classification.
        save_config(
            store,
            run,
            {
                "sites": ["https://site.example/index.html"],
                "depth": 2,
                "delay": 0,
                "asset_hosts": [],
                "max_bytes": 100000,
            },
        )
        resume(store, run)
        assert "/good.html" in requested
        assert status(store, run)["queue"].get("failed") == 1
        before = len(requested)
        resume(store, run)
        assert len(requested) == before
        assert (
            store.db.execute("SELECT error FROM queue WHERE run_id=? AND state='failed'", (run,))
            .fetchone()[0]
            .startswith("malformed XML:")
        )
    finally:
        store.close()


def test_truncated_gzip_preserved_and_queue_continues(tmp_path, mock_static_http):
    import httpx

    from blacklink_discovery.collect import crawl, enqueue
    from blacklink_discovery.store import Store

    mock_static_http(
        lambda r: httpx.Response(
            200,
            content=b"\x1f\x8b\x08\x00" if r.url.path == "/bad.xml.gz" else b"ok.example.net",
        )
    )
    store = Store(str(tmp_path))
    run = store.new_run("gzip")
    site = "https://site.example/"
    try:
        enqueue(store, run, site, site + "bad.xml.gz", 0, False)
        crawl(store, run, [site], 6, 0, set(), 100000, 0)
        assert (
            store.db.execute(
                "SELECT state FROM queue WHERE url=?", (site + "bad.xml.gz",)
            ).fetchone()[0]
            == "failed"
        )
        row = store.db.execute(
            "SELECT evidence_path FROM resources WHERE url=?", (site + "bad.xml.gz",)
        ).fetchone()
        assert (tmp_path / row[0]).read_bytes() == b"\x1f\x8b\x08\x00"
        assert store.db.execute(
            "SELECT COUNT(*) FROM findings WHERE host='ok.example.net'"
        ).fetchone()[0]
    finally:
        store.close()


def test_source_map_versions_and_bad_source_do_not_hide_later_sources(tmp_path):
    import json

    from blacklink_discovery.collect import process
    from blacklink_discovery.store import Store

    store = Store(str(tmp_path))
    run = store.new_run("maps")
    site = "https://site.example/"
    try:
        for sources in [["\ud800", "// later.example.net"], ["// new.example.net"]]:
            text = json.dumps({"sourcesContent": sources})
            process(store, run, site, site + "app.map", text.encode(), text, "json", 0, 6, set())
        assert {"later.example.net", "new.example.net"} <= {
            r[0] for r in store.db.execute("SELECT host FROM findings")
        }
        assert (
            store.db.execute(
                "SELECT COUNT(DISTINCT parent_resource_id) FROM resources WHERE collector='source_map'"
            ).fetchone()[0]
            == 2
        )
    finally:
        store.close()


def test_403_browser_fallback_once_and_separate_evidence(tmp_path, monkeypatch, mock_static_http):
    import httpx

    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import resume, save_config, status

    calls = []

    async def browser(store, url, state, chrome, wait, hosts, *, parent_run, parent_site):
        calls.append(url)
        run = store.new_run("anonymous-browser")
        store.db.execute(
            "UPDATE browser_fallbacks SET browser_run_id=? WHERE run_id=? AND site=? AND url=?",
            (run, parent_run, parent_site, url),
        )
        store.save(
            run,
            url,
            url,
            b"browser.example.net",
            "browser.example.net",
            "html",
            collector="browser_response",
        )
        store.db.execute(
            "INSERT INTO queue(run_id,site,url,depth,asset,state) VALUES(?,?,?,0,0,'done')",
            (run, url, url),
        )
        store.db.commit()
        return run

    mock_static_http(
        lambda r: httpx.Response(
            403, text="static.example.net", headers={"content-type": "text/html"}
        )
    )
    monkeypatch.setattr("blacklink_discovery.browser.collect_browser", browser)
    store = Store(str(tmp_path))
    run = store.new_run("fallback")
    try:
        save_config(
            store,
            run,
            {
                "sites": ["https://site.example/"],
                "depth": 6,
                "delay": 0,
                "asset_hosts": [],
                "max_bytes": 100000,
                "browser_fallback": True,
            },
        )
        resume(store, run)
        resume(store, run)
        # robots/sitemap are not HTML page fallback targets even with misleading MIME.
        assert calls == ["https://site.example/"]
        assert status(store, run)["browser_fallbacks"][0]["state"] == "captured"
        assert not status(store, run)["coverage_clear"]
        assert (
            store.db.execute(
                "SELECT COUNT(DISTINCT url) FROM resources WHERE run_id=? AND status=403", (run,)
            ).fetchone()[0]
            == 3
        )
    finally:
        store.close()


def test_repeated_url_keeps_every_source_position(tmp_path, mock_static_http):
    import httpx

    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import resume, save_config

    page = '<a href="/same">one</a><a href="/same">two</a><a href="/other">three</a>'
    mock_static_http(
        lambda request: httpx.Response(200, text=page, headers={"content-type": "text/html"})
    )
    store = Store(str(tmp_path))
    try:
        run = store.new_run("positions")
        site = "https://site.example/"
        save_config(
            store,
            run,
            {"sites": [site], "depth": 0, "delay": 0, "asset_hosts": [], "max_bytes": 100000},
        )
        resume(store, run)
        rows = store.db.execute(
            "SELECT start,end FROM edges WHERE run_id=? AND parent=? AND child=? AND relation='a.href' ORDER BY start",
            (run, site, site + "same"),
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][0] < rows[1][0]
        assert rows[0][1] <= rows[1][0]
    finally:
        store.close()


def test_repeated_browser_merge_keeps_one_finding_set(tmp_path):
    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import merge_browser, save_config

    store = Store(str(tmp_path))
    try:
        run = store.new_run("parent")
        site = "https://site.example/"
        save_config(
            store,
            run,
            {"sites": [site], "depth": 6, "delay": 0, "asset_hosts": [], "max_bytes": 100000},
        )
        child = store.new_run("anonymous-browser")
        script = site + "app.js"
        body = b"const host='merged.example.net';"
        store.save(run, site, script, body, body.decode(), "js", collector="browser_response")
        for page in (site, site + "other"):
            store.edge(run, site, page, script, "browser_response")
        merge_browser(store, run, child, site, 0, {"depth": 6, "asset_hosts": []})
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM resources WHERE run_id=? AND collector='browser_response' AND url=?",
                (run, script),
            ).fetchone()[0]
            == 1
        )
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM edges WHERE run_id=? AND child=? AND relation='browser_response'",
                (run, script),
            ).fetchone()[0]
            == 2
        )
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=? AND f.host='merged.example.net'",
                (run,),
            ).fetchone()[0]
            == 1
        )
    finally:
        store.close()
