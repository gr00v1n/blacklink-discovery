"""Machine-readable supervision contracts. No network requests in inspection commands."""

import asyncio
import hashlib
import json
from importlib.metadata import version
from urllib.parse import urlsplit

from .collect import crawl, process, record_expansion
from .extract import Mention
from .static_http import DEFAULT_FINGERPRINTS, validate_fingerprints
from .store import Store
from .urls import authorized, canonical_url, normalize_hosts


def require_run(store: Store, run: int):
    row = store.db.execute("SELECT * FROM runs WHERE id=?", (run,)).fetchone()
    if row is None:
        raise ValueError(f"run {run} does not exist")
    return row


def event(store: Store, run: int, name: str, detail: str = ""):
    store.db.execute(
        "INSERT INTO run_events(run_id,event,detail) VALUES(?,?,?)", (run, name, detail)
    )
    store.db.commit()


def save_config(store: Store, run: int, config: dict):
    require_run(store, run)
    config = dict(config, tool_version=version("blacklink-discovery"))
    config.setdefault("user_agent", None)
    config["fingerprints"] = validate_fingerprints(config.get("fingerprints", DEFAULT_FINGERPRINTS))
    store.db.execute("INSERT INTO run_configs VALUES(?,?)", (run, json.dumps(config)))
    store.db.commit()


def load_config(store: Store, run: int) -> dict:
    require_run(store, run)
    row = store.db.execute("SELECT config FROM run_configs WHERE run_id=?", (run,)).fetchone()
    if row is None:
        raise ValueError(
            "no saved static configuration; resume via scan with explicitly authorized sites"
        )
    return json.loads(row[0])


def status(store: Store, run: int) -> dict:
    row = require_run(store, run)
    counts = dict(
        store.db.execute("SELECT state,COUNT(*) FROM queue WHERE run_id=? GROUP BY state", (run,))
    )
    latest = store.db.execute(
        "SELECT time,event,detail FROM run_events WHERE run_id=? ORDER BY id DESC LIMIT 1", (run,)
    ).fetchone()
    config_row = store.db.execute(
        "SELECT config FROM run_configs WHERE run_id=?", (run,)
    ).fetchone()
    tables = {
        item[0] for item in store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    observations = (
        dict(
            store.db.execute(
                "SELECT state,COUNT(*) FROM request_observations WHERE run_id=? GROUP BY state",
                (run,),
            )
        )
        if "request_observations" in tables
        else {}
    )
    fallback = (
        [
            dict(item)
            for item in store.db.execute(
                "SELECT site,url,browser_run_id,state FROM browser_fallbacks WHERE run_id=? ORDER BY site,url",
                (run,),
            )
        ]
        if "browser_fallbacks" in tables
        else []
    )
    config = json.loads(config_row[0]) if config_row else None
    browser_pending = (
        len(browser_candidates(store, run, config))
        if config and (config.get("browser_crawl") or config.get("browser_fallback"))
        else 0
    )
    return {
        "run": dict(row),
        "config": json.loads(config_row[0]) if config_row else None,
        "queue": counts,
        "resources": store.db.execute(
            "SELECT COUNT(*) FROM resources WHERE run_id=?", (run,)
        ).fetchone()[0],
        "findings": store.db.execute(
            "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=?",
            (run,),
        ).fetchone()[0],
        "domains": store.db.execute(
            "SELECT COUNT(DISTINCT f.host) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=? AND f.host_type IN ('dns','ip','single_label')",
            (run,),
        ).fetchone()[0],
        "last_event": dict(latest) if latest else None,
        "request_observations": observations,
        "browser_fallbacks": fallback,
        "browser_pending": browser_pending,
        "static_requests": [
            dict(item)
            for item in store.db.execute(
                "SELECT fingerprint,status,COUNT(*) AS count FROM static_requests WHERE run_id=? GROUP BY fingerprint,status",
                (run,),
            )
        ]
        if "static_requests" in tables
        else [],
        "queue_exhausted": counts.get("pending", 0) == 0,
        "workflow_exhausted": counts.get("pending", 0) == 0 and browser_pending == 0,
        "coverage_clear": bool(counts)
        and all(state in {"done", "skipped_type"} for state in counts)
        and all(item["state"] == "captured" for item in fallback)
        and browser_pending == 0,
        "note": "Queue exhaustion is not a claim of whole-site completeness; process liveness must be checked separately.",
    }


def failures(store: Store, run: int, limit: int, offset: int = 0) -> dict:
    require_run(store, run)
    rows = store.db.execute(
        "SELECT q.site,q.url,q.state,q.error,COALESCE(a.count,0) AS attempts FROM queue q "
        "LEFT JOIN attempts a ON a.run_id=q.run_id AND a.site=q.site AND a.url=q.url "
        "WHERE q.run_id=? AND q.state NOT IN ('done','pending') ORDER BY q.site,q.url LIMIT ? OFFSET ?",
        (run, limit, offset),
    ).fetchall()
    total = store.db.execute(
        "SELECT COUNT(*) FROM queue WHERE run_id=? AND state NOT IN ('done','pending')", (run,)
    ).fetchone()[0]
    return {
        "run_id": run,
        "total": total,
        "items": [dict(row) for row in rows],
        "truncated": total > offset + len(rows),
        "offset": offset,
        "next_offset": offset + len(rows) if offset + len(rows) < total else None,
    }


def retry(store: Store, run: int, max_attempts: int, urls: list[str]) -> dict:
    # Retry only queues requests; resume performs the actual network work.
    load_config(store, run)
    rows = store.db.execute(
        "SELECT q.site,q.url,COALESCE(a.count,0) AS attempts FROM queue q LEFT JOIN attempts a "
        "ON a.run_id=q.run_id AND a.site=q.site AND a.url=q.url WHERE q.run_id=? AND q.state='failed'",
        (run,),
    ).fetchall()
    selected = [
        row
        for row in rows
        if "#sourcesContent/" not in row["url"]
        and row["attempts"] < max_attempts
        and (not urls or row["url"] in urls)
    ]
    for row in selected:
        store.db.execute(
            "UPDATE queue SET state='pending',error=NULL WHERE run_id=? AND site=? AND url=?",
            (run, row["site"], row["url"]),
        )
    event(
        store,
        run,
        "retry_queued",
        json.dumps({"count": len(selected), "max_attempts": max_attempts}),
    )
    return {"run_id": run, "queued": len(selected), "network_started": False}


def merge_browser(store: Store, run: int, browser_run: int, site: str, depth: int, config: dict):
    # Import successful response and DOM evidence into the original site's queue.
    # Failed challenge documents are retained in their browser batch, never expanded.
    rows = store.db.execute(
        "SELECT r.*,t.path AS text_path FROM resources r JOIN text_views t ON t.resource_id=r.id "
        "WHERE r.run_id=? AND r.collector='browser_dom' AND r.status>=200 AND r.status<300",
        (browser_run,),
    ).fetchall()
    for row in rows:
        if not authorized(
            row["url"], site, row["kind"] != "html", normalize_hosts(config["asset_hosts"])
        ):
            continue
        mentions = [
            Mention(*item)
            for item in store.db.execute(
                "SELECT host,registered,host_type,start,end,line,col,source,method,evidence FROM findings WHERE resource_id=?",
                (row["id"],),
            )
        ]
        resource = process(
            store,
            run,
            site,
            row["url"],
            (store.directory / row["evidence_path"]).read_bytes(),
            (store.directory / row["text_path"]).read_bytes().decode("utf-8"),
            row["kind"],
            depth + browser_depth(store, browser_run, row["url"]),
            config["depth"],
            normalize_hosts(config["asset_hosts"]),
            row["status"],
            collector="browser_supplement",
            encoding=row["encoding"],
            mentions=mentions,
            parent_resource_id=0,
        )
        store.edge(
            run, site, row["url"], row["url"], "browser_supplement", parent_resource_id=row["id"]
        )
        event(
            store,
            run,
            "browser_merged",
            json.dumps(
                {
                    "browser_run_id": browser_run,
                    "resource_id": resource,
                    "source_resource_id": row["id"],
                }
            ),
        )


def browser_depth(store: Store, run: int, url: str) -> int:
    row = store.db.execute(
        "SELECT depth FROM browser_depths WHERE run_id=? AND url=?", (run, canonical_url(url))
    ).fetchone()
    return row[0] if row else 0


def replay_expansions(store: Store, run: int, config: dict):
    # A shorter discovered path changes expansion eligibility, not the HTTP request outcome.
    while True:
        rows = store.db.execute(
            "WITH candidates AS (SELECT r.*,t.path AS text_path, "
            "MIN(COALESCE(q.depth,2147483647), "
            "COALESCE(origin.depth+COALESCE(bd.depth,0),2147483647)) AS depth, "
            "e.depth AS expanded_depth FROM resources r "
            "JOIN text_views t ON t.resource_id=r.id "
            "LEFT JOIN queue q ON q.run_id=r.run_id AND q.site=r.site "
            "AND (r.url=q.url OR r.url=q.url||'#dom') "
            "LEFT JOIN resources source ON source.id=r.parent_resource_id "
            "LEFT JOIN browser_fallbacks b ON b.run_id=r.run_id AND b.site=r.site "
            "AND b.browser_run_id=source.run_id "
            "LEFT JOIN queue origin ON origin.run_id=b.run_id AND origin.site=b.site AND origin.url=b.url "
            "LEFT JOIN browser_depths bd ON bd.run_id=source.run_id "
            "AND (source.url=bd.url OR source.url=bd.url||'#dom') "
            "LEFT JOIN expansions e ON e.resource_id=r.id "
            "WHERE r.run_id=? AND r.status>=200 AND r.status<300 "
            "AND r.collector IN ('static','browser_supplement') "
            "AND (q.url IS NOT NULL OR origin.url IS NOT NULL)) "
            "SELECT * FROM candidates WHERE expanded_depth IS NULL OR depth<expanded_depth ORDER BY depth,id",
            (run,),
        ).fetchall()
        if not rows:
            return
        for row in rows:
            try:
                resource = process(
                    store,
                    run,
                    row["site"],
                    row["url"],
                    (store.directory / row["evidence_path"]).read_bytes(),
                    (store.directory / row["text_path"]).read_bytes().decode("utf-8"),
                    row["kind"],
                    row["depth"],
                    config["depth"],
                    normalize_hosts(config["asset_hosts"]),
                    row["status"],
                    collector=row["collector"],
                    encoding=row["encoding"],
                    parent_resource_id=row["parent_resource_id"],
                    mentions=[
                        Mention(*item)
                        for item in store.db.execute(
                            "SELECT host,registered,host_type,start,end,line,col,source,method,evidence FROM findings WHERE resource_id=?",
                            (row["id"],),
                        )
                    ],
                )
                if resource is None:
                    # Old batches may contain binary records; do not replay them forever.
                    record_expansion(store, row["id"], row["depth"])
            except ValueError as error:
                event(
                    store,
                    run,
                    "expansion_failed",
                    json.dumps({"resource_id": row["id"], "error": str(error)}),
                )


def resume(store: Store, run: int, max_urls: int = 0):
    config = load_config(store, run)
    event(store, run, "started", "resume with saved authorization and configuration")
    try:
        used = 0
        while True:
            replay_expansions(store, run, config)
            before = store.db.execute(
                "SELECT COALESCE(SUM(count),0) FROM attempts WHERE run_id=?", (run,)
            ).fetchone()[0]
            crawl(
                store,
                run,
                config["sites"],
                config["depth"],
                config["delay"],
                normalize_hosts(config["asset_hosts"]),
                config["max_bytes"],
                max_urls - used if max_urls else 0,
                config.get("user_agent"),
                config.get("fingerprints", DEFAULT_FINGERPRINTS),
            )
            after = store.db.execute(
                "SELECT COALESCE(SUM(count),0) FROM attempts WHERE run_id=?", (run,)
            ).fetchone()[0]
            used += after - before
            if config.get("browser_fallback") or config.get("browser_crawl"):
                browser_wave(store, run, config)
            replay_expansions(store, run, config)
            if max_urls and used >= max_urls:
                break
            if status(store, run)["queue_exhausted"]:
                break
    except KeyboardInterrupt:
        store.db.rollback()
        event(store, run, "interrupted", "pending queue retained")
        raise
    except Exception:
        store.db.rollback()
        event(store, run, "error", "resume failed; inspect process logs")
        raise
    event(
        store,
        run,
        "queue_exhausted" if status(store, run)["queue_exhausted"] else "paused",
        "check coverage before declaring completion",
    )


def browser_candidates(store: Store, run: int, config: dict):
    approved = {canonical_url(site) for site in config["sites"]}
    rows = store.db.execute(
        "SELECT DISTINCT r.site,r.url,q.depth FROM resources r JOIN queue q ON q.run_id=r.run_id AND q.site=r.site AND q.url=r.url WHERE r.run_id=? AND ((r.status=403 AND q.state='failed') OR (? AND r.status>=200 AND r.status<300)) AND r.kind='html' AND q.state IN ('failed','done') AND q.asset=0 AND NOT EXISTS(SELECT 1 FROM browser_fallbacks b WHERE b.run_id=r.run_id AND b.site=r.site AND b.url=r.url AND b.state!='started') ORDER BY q.depth,r.site,r.url",
        (run, bool(config.get("browser_crawl"))),
    ).fetchall()
    selected = []
    for row in rows:
        path = urlsplit(row["url"]).path.lower()
        if (
            canonical_url(row["site"]) not in approved
            or path.endswith(("robots.txt", ".xml", ".xml.gz"))
            or "sitemap" in path
        ):
            continue
        selected.append(row)
    return selected


def browser_wave(store: Store, run: int, config: dict):
    from .browser import collect_browser

    for row in browser_candidates(store, run, config):
        store.db.execute(
            "INSERT OR IGNORE INTO browser_fallbacks(run_id,site,url,state) VALUES(?,?,?,'started')",
            (run, row["site"], row["url"]),
        )
        event(store, run, "fallback_started", row["url"])
        previous = store.db.execute(
            "SELECT browser_run_id FROM browser_fallbacks WHERE run_id=? AND site=? AND url=?",
            (run, row["site"], row["url"]),
        ).fetchone()[0]
        supplemental = previous or asyncio.run(
            collect_browser(
                store,
                row["url"],
                None,
                config.get("browser_chrome"),
                3,
                normalize_hosts(config["asset_hosts"]),
                parent_run=run,
                parent_site=row["site"],
            )
        )
        result = status(store, supplemental)
        current_depth = store.db.execute(
            "SELECT depth FROM queue WHERE run_id=? AND site=? AND url=?",
            (run, row["site"], row["url"]),
        ).fetchone()[0]
        merge_browser(store, run, supplemental, row["site"], current_depth, config)
        state = "captured" if result["coverage_clear"] else "partial"
        store.db.execute(
            "UPDATE browser_fallbacks SET browser_run_id=?,state=? WHERE run_id=? AND site=? AND url=?",
            (supplemental, state, run, row["site"], row["url"]),
        )
        event(
            store,
            run,
            "fallback_" + state,
            json.dumps({"url": row["url"], "browser_run_id": supplemental}),
        )


def verify(store: Store, run: int) -> dict:
    require_run(store, run)
    issues = []
    checked = 0
    resources = store.db.execute(
        "SELECT r.*,t.path AS text_path FROM resources r LEFT JOIN text_views t ON t.resource_id=r.id WHERE r.run_id=?",
        (run,),
    )
    root = store.directory.resolve()
    for resource in resources:
        checked += 1
        text = None
        for field in ("evidence_path", "text_path"):
            relative = resource[field]
            path = (root / relative).resolve() if relative else None
            if path is None or not path.is_relative_to(root) or not path.is_file():
                issues.append({"resource": resource["id"], "problem": f"missing/unsafe {field}"})
                continue
            data = path.read_bytes()
            expected = path.name.removesuffix(".utf8")
            if hashlib.sha256(data).hexdigest() != expected:
                issues.append({"resource": resource["id"], "problem": f"hash mismatch: {field}"})
            if field == "text_path":
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    issues.append({"resource": resource["id"], "problem": "invalid UTF-8 view"})
        if text is not None:
            from .text import Positions

            positions = Positions(text)
            legacy_positions = (
                Positions(text, legacy=True)
                if dict(resource).get("collector", "legacy") == "legacy"
                else None
            )
            for finding in store.db.execute(
                "SELECT start,end,line,col FROM findings WHERE resource_id=?", (resource["id"],)
            ):
                a, b = finding["start"], finding["end"]
                if (
                    not 0 <= a < b <= len(text)
                    or (
                        finding["line"],
                        finding["col"],
                    )
                    != positions.locate(a)
                    and (
                        legacy_positions is None
                        or (finding["line"], finding["col"]) != legacy_positions.locate(a)
                    )
                ):
                    issues.append(
                        {"resource": resource["id"], "problem": "invalid evidence position"}
                    )
    report = status(store, run)
    return {
        "run_id": run,
        "integrity_ok": not issues,
        "checked_resources": checked,
        "issues": issues,
        "coverage_clear": report["coverage_clear"],
        "queue": report["queue"],
        "note": "Integrity validates stored evidence, not extraction recall, authentication or whole-site coverage.",
    }
