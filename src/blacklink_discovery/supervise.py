"""Machine-readable supervision contracts. No network requests in inspection commands."""

import hashlib
import json
from importlib.metadata import version

from .collect import crawl
from .store import Store


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
            "SELECT COUNT(DISTINCT f.host) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE r.run_id=?",
            (run,),
        ).fetchone()[0],
        "last_event": dict(latest) if latest else None,
        "queue_exhausted": counts.get("pending", 0) == 0,
        "coverage_clear": bool(counts) and all(state == "done" for state in counts),
        "note": "Queue exhaustion is not a claim of whole-site completeness; process liveness must be checked separately.",
    }


def failures(store: Store, run: int, limit: int) -> dict:
    require_run(store, run)
    rows = store.db.execute(
        "SELECT q.site,q.url,q.state,q.error,COALESCE(a.count,0) AS attempts FROM queue q "
        "LEFT JOIN attempts a ON a.run_id=q.run_id AND a.site=q.site AND a.url=q.url "
        "WHERE q.run_id=? AND q.state NOT IN ('done','pending') ORDER BY q.site,q.url LIMIT ?",
        (run, limit),
    ).fetchall()
    total = store.db.execute(
        "SELECT COUNT(*) FROM queue WHERE run_id=? AND state NOT IN ('done','pending')", (run,)
    ).fetchone()[0]
    return {
        "run_id": run,
        "total": total,
        "items": [dict(row) for row in rows],
        "truncated": total > len(rows),
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
        row for row in rows if row["attempts"] < max_attempts and (not urls or row["url"] in urls)
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


def resume(store: Store, run: int, max_urls: int = 0):
    config = load_config(store, run)
    event(store, run, "started", "resume with saved authorization and configuration")
    try:
        crawl(
            store,
            run,
            config["sites"],
            config["depth"],
            config["delay"],
            set(config["asset_hosts"]),
            config["max_bytes"],
            max_urls,
        )
    except KeyboardInterrupt:
        event(store, run, "interrupted", "pending queue retained")
        raise
    except Exception:
        event(store, run, "error", "resume failed; inspect process logs")
        raise
    event(
        store,
        run,
        "queue_exhausted" if status(store, run)["queue_exhausted"] else "paused",
        "check coverage before declaring completion",
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
            for finding in store.db.execute(
                "SELECT start,end,line,col FROM findings WHERE resource_id=?", (resource["id"],)
            ):
                a, b = finding["start"], finding["end"]
                if (
                    not 0 <= a < b <= len(text)
                    or finding["line"] != text.count("\n", 0, a) + 1
                    or finding["col"] != a - text.rfind("\n", 0, a)
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
