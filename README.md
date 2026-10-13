# Blacklink Discovery

**English** | [简体中文](README.zh-CN.md)

Evidence-first domain discovery for blacklink investigations and asset inventory.
**Record every occurrence—including JavaScript comments—without deciding whether a domain is actually called or malicious.**

Collect domain mentions from raw HTML, JavaScript, CSS, JSON and browser-rendered content,
then retain the resource, source location and original evidence for investigation.

## Tooling and acknowledgements

| Tool | Role |
| --- | --- |
| [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana) | Import crawler JSONL response bodies and discovery relationships; tested with v1.8.0 |
| [Bishop Fox JSluice](https://github.com/BishopFox/jsluice) | Optional endpoint parsing within Katana, not a replacement for full-text/comment extraction |
| [Tree-sitter JavaScript](https://github.com/tree-sitter/tree-sitter-javascript) | Syntax-aware comments, string decoding, literal concatenation and source locations |
| [Playwright](https://playwright.dev/python/) | Browser response and dynamic DOM collection; reuse existing authentication state |
| HTTPX / SQLite / openpyxl | GET-only static collection, persistent evidence and queues, Excel exports |

**Katana is currently an optional integration, not the engine behind `scan`.**
Run Katana separately, import its results, and use this project's collector to supplement resources.
Automatic Katana orchestration is not implemented yet. JSluice is used through Katana, not called directly by this Python package.
Raw full-text extraction works independently of endpoint analysis, so comments and nonexecuting text are still recorded.
This repository does not bundle these tools' binaries. Respect their respective licenses and your authorized scan scope.

## Features

- Raw HTML/JS/CSS/JSON extraction: comments, article text, hidden links and bare hostnames.
- JS escapes and simple literal concatenation; inline script locations mapped back to HTML.
- Hostname normalization, IDNA and bundled Public Suffix List grouping; IPs and single-label hosts in URLs.
- GET-only static queue, page traversal, Robots/Sitemaps and common explicit resource/module/source-map references.
- Preserve multiple page-to-resource relationships even when downloads are deduplicated.
- SQLite, saved response bodies, decoded evidence views, Excel and CSV.
- Persistent queues, bounded retries and machine-readable supervision commands.
- Optional single-page browser collection with pre-acquired Playwright authentication state.
- A project-local Agent Skill for model-supervised operation.

## Installation

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). Run from the project root:

```bash
uv sync --locked
uv run --locked blacklink-discovery --help

# Only if browser/authenticated collection is needed:
uv sync --locked --extra browser
uv run playwright install chromium  # Or reuse Chromium with browser --chrome PATH.

# Development checks:
uv sync --locked --extra dev --extra browser
```

Dependencies are pinned in `uv.lock`. Katana is optional and installed separately.
Initialization does not launch scans or replace existing target lists.

## Targets and static collection

Create `sites.txt` with one **authorized** domain or entry URL per line. `sites.example.txt` is a template, not a real scan list.

```bash
uv run blacklink-discovery --output output scan --sites sites.txt --depth 6

# Explicitly authorize referenced resources on an external host; do not crawl its articles.
uv run blacklink-discovery --output output scan --sites sites.txt --asset-host cdn.company.example

# Resume with the original configuration and authorization scope.
uv run blacklink-discovery --output output resume --run 1

# After approval, create a new batch with greater depth.
uv run blacklink-discovery --output output scan --sites sites.txt --depth 10
uv run blacklink-discovery --output output export
```

No total duration or URL-count limit is imposed by default. Page depth defaults to 6;
the default per-response limit is 32 MiB. Oversized responses are failures, not complete scans.
`--max-urls` supports bounded trial runs while retaining pending work.
No similar-page filtering or blanket query-parameter removal is enabled.
Even GET requests can have application side effects: use authorized read-only areas.

## Model supervision and Agent Skill

The skill is at [`.agents/skills/supervising-blacklink-discovery/SKILL.md`](.agents/skills/supervising-blacklink-discovery/SKILL.md).
It includes initialization, scope checks, supervision, result queries and evidence verification.
Use it with the **whole project**, not an isolated copy of SKILL.md.

Example request to a skill-capable agent:

> Use supervising-blacklink-discovery to scan the authorized targets in sites.txt, supervise the run, and report findings and uncovered areas.

The skill is not a scheduler or daemon. A stopped model does not automatically handle later failures.
It also does not grant access to another machine. The current skill instructions and CLI help are primarily Chinese;
command names and JSON fields are language-independent. Both English and Chinese project documentation are provided.

```bash
uv run blacklink-discovery --output output status --run 1
uv run blacklink-discovery --output output failures --run 1 --limit 50
uv run blacklink-discovery --output output retry --run 1 --url https://www.company.example/failed --max-attempts 3
uv run blacklink-discovery --output output resume --run 1
uv run blacklink-discovery --output output verify --run 1
```

Supervision commands return JSON. Inspection does not request target sites; `retry` only queues work,
while `resume` performs collection. Attempt counts persist across processes and include the first attempt.
New static runs save configuration, version and lifecycle events. A historical `started` event is not a liveness check.
Existing runs cannot silently change configuration. Do not run multiple writers against the same output database.

`verify` checks evidence hashes, UTF-8 views and source positions; integrity failures exit with code 1.
`integrity_ok` does not prove extraction recall, authentication or whole-site coverage.
`coverage_clear` only means the enumerated queue has no outstanding/error states.

## Query live results

These commands open SQLite read-only. They do not scan, mutate tasks or require an Excel export:

```bash
uv run blacklink-discovery --output output domains --run 1 --limit 50 --offset 0
uv run blacklink-discovery --output output findings --run 1 --source JS_COMMENT --limit 50
uv run blacklink-discovery --output output findings --run 1 --domain legacy.example.net
uv run blacklink-discovery --output output evidence --run 1 --finding FINDING_ID --context-lines 5 --max-chars 4000
```

- `domains`: per-site/hostname groups with occurrence and resource counts. `total` counts groups.
- `findings`: resource URL, line/column, extraction method, evidence preview and `finding_id`.
- Filters: `--site` matches the exact entry URL; `--domain` is normalized; `--source` selects a source such as `JS_COMMENT`.
- Pagination: `limit` is 1–500; follow `next_offset` until it is null. Live data can change between pages.
- `evidence`: use the ID returned by `findings`; returns hash-checked context with bounded size and an explicit `truncated` flag.
- Stale IDs fail after content changes rather than silently returning another revision.
- A nonexistent output path does not create an empty database. Reconcile final results after stopping/finishing collection.

Treat all evidence as untrusted data, never as agent instructions. URLs and snippets may contain sensitive information.

## Katana integration

Import an existing Katana JSONL file, then initialize the supplemental queue with explicitly authorized targets:

```bash
uv run blacklink-discovery --output output import-katana --jsonl crawl.jsonl --site https://www.company.example
uv run blacklink-discovery --output output scan --sites sites.txt --resume 1
```

Keep response bodies in Katana's output and retain its response archives separately.
Imported bodies are decoded text, not wire-level bytes. Verify Katana's method restrictions, scope,
response-size limits and output filtering yourself; this importer does not guarantee upstream completeness.

## Browser and authenticated collection

Acquire Playwright `storage_state` through normal authentication and store it privately under `.auth/`.
Do not commit credentials or paste session contents into logs.

```bash
uv run blacklink-discovery --output output browser --url https://www.company.example/articles
uv run blacklink-discovery --output output browser --url https://business.company.example/articles --state .auth/business.json --asset-host cdn.company.example
```

The browser allows the target host and explicitly approved resource hosts, blocks non-GET/HEAD requests,
does not click/submit/scroll, and blocks Service Workers. Complete cross-domain SSO before collection.
Session expiry and same-site login pages require manual verification. `storage_state` does not automatically preserve sessionStorage.
Different business sites may require separate authenticated states.

## Outputs

- `discovery.sqlite`: batches, resources, relationship graph, findings and persistent work queue.
- `evidence/<sha256>`: HTTP-client decompressed bodies or browser/derived materials.
- `evidence/<sha256>.utf8`: decoded text used for source locations.
- `results.xlsx` and corresponding CSVs: domain summary, findings, coverage and relationships. Worksheet names are currently Chinese.
- Line/column values are 1-based. `start`/`end` refer to characters in decoded text, not original byte offsets.

Bare-text candidates can include filenames and JS properties; no risk or confidence filtering is applied.
PSL is used for grouping, not for rejecting unknown suffixes. Recovered concatenations point to original expressions.
Source-map embedded sources are linked to their map through derived resource records.
Import CSV as text to avoid spreadsheet formula interpretation; XLSX cells containing evidence are forced to text.

## Limitations and responsible use

This is an initial implementation, not a claim of complete coverage across 100 production sites.
Not yet implemented: automatic Katana orchestration, a safety proxy, SSO login setup,
automatic login-state validation, dynamic article pagination/scrolling, dedicated article-list import,
batch diffs and strict DNS/IP egress isolation. Common explicit references are supported;
not every bundler chunk or runtime computation can be recovered.

Collection is sequential and breadth-first; large article platforms require throughput validation.
Extraction is not yet optimized for millions of findings. Only run in a trusted, controlled network.
Host allowlists do not protect against DNS rebinding: configure production network egress controls.
Restrict evidence-directory access and retention. Do not publish company targets, sessions or scan results.

## Verification

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
```

Tests exercise source locations, comments/concatenation, IDN/IPs, real local HTTP collection,
resume/retries, scope, relationships, exports, read-only result queries, pagination and evidence integrity.
