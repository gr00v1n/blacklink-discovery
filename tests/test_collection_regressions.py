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
    assert links == [
        ("https://example.test/app.mjs", True, "link.href"),
        ("https://example.test/assets/main.js", True, "script.src"),
    ]
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


def test_authorized_queue_merge_error_evidence_encoding_and_sitemaps(tmp_path, monkeypatch):
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

    client = httpx.Client
    monkeypatch.setattr(
        "blacklink_discovery.collect.httpx.Client",
        lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs),
    )
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


def test_truncated_gzip_preserved_and_queue_continues(tmp_path, monkeypatch):
    import httpx

    from blacklink_discovery.collect import crawl, enqueue
    from blacklink_discovery.store import Store

    client = httpx.Client
    monkeypatch.setattr(
        "blacklink_discovery.collect.httpx.Client",
        lambda **kwargs: client(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    200,
                    content=b"\x1f\x8b\x08\x00"
                    if r.url.path == "/bad.xml.gz"
                    else b"ok.example.net",
                )
            ),
            **kwargs,
        ),
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


def test_403_browser_fallback_once_and_separate_evidence(tmp_path, monkeypatch):
    import httpx

    from blacklink_discovery.store import Store
    from blacklink_discovery.supervise import resume, save_config, status

    calls = []

    async def browser(store, url, state, chrome, wait, hosts):
        calls.append(url)
        run = store.new_run("anonymous-browser")
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

    client = httpx.Client
    monkeypatch.setattr(
        "blacklink_discovery.collect.httpx.Client",
        lambda **kwargs: client(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    403, text="static.example.net", headers={"content-type": "text/html"}
                )
            ),
            **kwargs,
        ),
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
