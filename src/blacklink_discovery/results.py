"""Bounded, parameterized queries for live findings and immutable evidence files."""

import hashlib

from .extract import normalize
from .store import Store
from .supervise import require_run
from .text import Positions


def filters(run: int, site: str | None, domain: str | None, source: str | None):
    clauses, values = ["r.run_id=?"], [run]
    if site:
        clauses.append("r.site=?")
        values.append(site)
    if domain:
        host = normalize(domain)
        if host is None:
            raise ValueError("invalid domain/host filter")
        clauses.append("f.host=?")
        values.append(host[0])
    if source:
        clauses.append("f.source=?")
        values.append(source.upper())
    return " AND ".join(clauses), values


def finding_id(row: dict) -> str:
    # Include content and occurrence identity so a replaced rowid cannot silently
    # return evidence from a different resource revision.
    identity = tuple(
        row[key]
        for key in ("run_id", "resource_id", "host", "start", "end", "source", "decoded_text_path")
    )
    digest = hashlib.sha256(repr(identity).encode()).hexdigest()[:16]
    return f"{row['row_id']}-{digest}"


def page_result(run: int, items: list[dict], total: int, limit: int, offset: int) -> dict:
    next_offset = offset + len(items)
    return {
        "run_id": run,
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
        "next_offset": next_offset if next_offset < total else None,
        "note": "Live database page, not a frozen snapshot; counts may change during collection.",
    }


def domains(
    store: Store,
    run: int,
    site: str | None,
    domain: str | None,
    source: str | None,
    limit: int,
    offset: int,
) -> dict:
    require_run(store, run)
    where, values = filters(run, site, domain, source)
    where += " AND f.host_type!='file_candidate'"
    grouped = (
        "SELECT r.site,f.host AS domain,f.registered,f.host_type,COUNT(*) AS occurrences,"
        "COUNT(DISTINCT r.id) AS resources FROM findings f JOIN resources r ON r.id=f.resource_id "
        f"WHERE {where} GROUP BY r.site,f.host,f.registered,f.host_type"
    )
    total = store.db.execute(f"SELECT COUNT(*) FROM ({grouped})", values).fetchone()[0]
    rows = store.db.execute(
        grouped + " ORDER BY r.site,f.host LIMIT ? OFFSET ?", [*values, limit, offset]
    ).fetchall()
    return page_result(run, [dict(row) for row in rows], total, limit, offset)


FINDINGS = (
    "SELECT f.rowid AS row_id,r.run_id,r.id AS resource_id,r.site,r.url,f.host,f.registered,"
    "f.host_type,f.line,f.col AS column,f.start,f.end,f.source,f.method,"
    "SUBSTR(f.evidence,1,1000) AS evidence,r.evidence_path,t.path AS decoded_text_path "
    "FROM findings f JOIN resources r ON r.id=f.resource_id "
    "LEFT JOIN text_views t ON t.resource_id=r.id "
)


def findings(
    store: Store,
    run: int,
    site: str | None,
    domain: str | None,
    source: str | None,
    limit: int,
    offset: int,
) -> dict:
    require_run(store, run)
    where, values = filters(run, site, domain, source)
    total = store.db.execute(
        "SELECT COUNT(*) FROM findings f JOIN resources r ON r.id=f.resource_id WHERE " + where,
        values,
    ).fetchone()[0]
    rows = store.db.execute(
        FINDINGS + f"WHERE {where} ORDER BY r.site,r.url,f.start,f.rowid LIMIT ? OFFSET ?",
        [*values, limit, offset],
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["finding_id"] = finding_id(item)
        del item["row_id"]
        items.append(item)
    return page_result(run, items, total, limit, offset)


def evidence(store: Store, run: int, token: str, context_lines: int, max_chars: int) -> dict:
    require_run(store, run)
    try:
        row_id = int(token.split("-", 1)[0])
    except ValueError as error:
        raise ValueError("invalid finding id; obtain it from findings") from error
    row = store.db.execute(FINDINGS + "WHERE r.run_id=? AND f.rowid=?", (run, row_id)).fetchone()
    if row is None or finding_id(dict(row)) != token:
        raise ValueError("finding not found or changed; refresh findings for this run")
    item = dict(row)
    root = store.directory.resolve()
    relative = item["decoded_text_path"]
    path = (root / relative).resolve() if relative else None
    if path is None or not path.is_relative_to(root) or not path.is_file():
        raise ValueError("missing or unsafe evidence text path")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != path.name.removesuffix(".utf8"):
        raise ValueError("evidence hash mismatch; run verify and restore original evidence")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("invalid UTF-8 evidence") from error
    a, b = item["start"], item["end"]
    positions = Positions(text)
    line, column = positions.locate(a)
    if (item["line"], item["column"]) != (line, column):
        columns = {r[1] for r in store.db.execute("PRAGMA table_info(resources)")}
        legacy = (
            "collector" not in columns
            or store.db.execute(
                "SELECT collector FROM resources WHERE id=?", (item["resource_id"],)
            ).fetchone()[0]
            == "legacy"
        )
        if legacy:
            positions = Positions(text, legacy=True)
            line, column = positions.locate(a)
    if not 0 <= a < b <= len(text) or item["line"] != line or item["column"] != column:
        raise ValueError("invalid finding position; run verify")
    first = max(0, line - 1 - context_lines)
    last = min(len(positions.lines), positions.locate(b - 1)[0] + context_lines)
    left = positions.lines[first]
    right = positions.lines[last] if last < len(positions.lines) else len(text)
    while right > b and text[right - 1] in "\r\n\u2028\u2029":
        right -= 1
    full_left, full_right = left, right
    if right - left > max_chars:
        left = max(left, a - max_chars // 4)
        right = min(right, left + max_chars)
    return {
        "run_id": run,
        "finding_id": token,
        "site": item["site"],
        "url": item["url"],
        "host": item["host"],
        "source": item["source"],
        "method": item["method"],
        "line": item["line"],
        "column": item["column"],
        "start": a,
        "end": b,
        "decoded_text_path": relative,
        "integrity_ok": True,
        "context_start": left,
        "context_end": right,
        "context_first_line": positions.locate(left)[0],
        "text": text[left:right],
        "truncated": (left, right) != (full_left, full_right),
    }
