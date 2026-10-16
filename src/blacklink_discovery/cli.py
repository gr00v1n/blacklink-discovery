import argparse
import asyncio
import json
from pathlib import Path

from .collect import import_katana
from .results import domains, evidence, findings
from .static_http import DEFAULT_FINGERPRINTS, validate_fingerprints
from .store import Store
from .supervise import failures, load_config, resume, retry, save_config, status, verify
from .urls import canonical_url, normalize_hosts


def main():
    parser = argparse.ArgumentParser(description="黑链排查·域名发现：出现即记录，不做风险判定")
    parser.add_argument("--output", default="output")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="GET-only静态采集，支持续跑")
    scan.add_argument("--sites", required=True)
    scan.add_argument("--depth", type=int, default=6)
    scan.add_argument("--delay", type=float, default=0.5)
    scan.add_argument("--user-agent", help="可选覆盖UA；默认使用指纹配套UA，随批次保存")
    scan.add_argument(
        "--fingerprint", action="append", help="curl_cffi指纹，按传入顺序轮换；可重复指定不同指纹"
    )
    scan.add_argument(
        "--asset-host", action="append", default=[], help="允许获取关联资源的外部主机；可重复"
    )
    scan.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    scan.add_argument(
        "--max-urls", type=int, default=0, help="0表示不设数量上限；停止后pending保留"
    )
    recovery = scan.add_mutually_exclusive_group()
    recovery.add_argument("--resume", type=int)
    recovery.add_argument(
        "--resume-latest",
        action="store_true",
        help="复用最新静态批次，首次运行才创建；配置不一致则拒绝，适合服务重启",
    )
    scan.add_argument("--retry-failed", action="store_true")
    scan.add_argument(
        "--browser-fallback", action="store_true", help="静态页面403后单次只读浏览器补采；单独批次"
    )
    scan.add_argument(
        "--browser-crawl",
        action="store_true",
        help="成功页面及403页面动态补采，站内新链接自动回流队列",
    )
    scan.add_argument("--browser-chrome", help="403补采使用的Chromium路径")
    imported = commands.add_parser("import-katana")
    imported.add_argument("--jsonl", required=True)
    imported.add_argument("--site", required=True)
    browser = commands.add_parser("browser", help="动态页面补采；可加载Playwright认证状态")
    browser.add_argument("--url", required=True)
    browser.add_argument("--state", help="认证状态文件，禁止提交到Git")
    browser.add_argument("--chrome", help="现有Chromium可执行文件路径")
    browser.add_argument("--wait", type=float, default=3)
    browser.add_argument("--asset-host", action="append", default=[])
    browser.add_argument("--max-seconds", type=float, default=120)
    browser.add_argument("--max-responses", type=int, default=500)
    browser.add_argument("--max-total-bytes", type=int, default=128 * 1024 * 1024)
    browser.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    browser.add_argument("--parse-seconds", type=float, default=30)
    for name in ("status", "failures", "verify", "resume", "retry"):
        command = commands.add_parser(name, help="模型监督接口，输出JSON")
        command.add_argument("--run", type=int, required=True)
        if name == "failures":
            command.add_argument("--limit", type=int, default=50)
            command.add_argument("--offset", type=int, default=0)
        elif name == "resume":
            command.add_argument("--max-urls", type=int, default=0)
        elif name == "retry":
            command.add_argument("--max-attempts", type=int, default=3)
            command.add_argument("--url", action="append", default=[])
    for name in ("domains", "findings"):
        command = commands.add_parser(name, help="只读分页查询实时结果，输出JSON")
        command.add_argument("--run", type=int, required=True)
        command.add_argument("--site", help="精确匹配扫描入口URL")
        command.add_argument("--domain", help="精确匹配完整主机名，自动规范化")
        command.add_argument("--source", help="例如JS_COMMENT")
        command.add_argument("--limit", type=int, default=50)
        command.add_argument("--offset", type=int, default=0)
    command = commands.add_parser("evidence", help="按finding_id读取有界原文上下文，输出JSON")
    command.add_argument("--run", type=int, required=True)
    command.add_argument("--finding", required=True)
    command.add_argument("--context-lines", type=int, default=5)
    command.add_argument("--max-chars", type=int, default=4000)
    commands.add_parser("export").add_argument("--run", type=int)
    args = parser.parse_args()
    try:
        store = Store(
            args.output,
            read_only=args.command
            in {"domains", "findings", "evidence", "status", "failures", "verify"},
        )
    except ValueError as error:
        parser.error(str(error))
    try:
        if args.command in {"domains", "findings", "evidence"}:
            if args.command == "evidence":
                if not 0 <= args.context_lines <= 20 or not 1 <= args.max_chars <= 16000:
                    parser.error("context-lines must be 0..20; max-chars must be 1..16000")
                report = evidence(store, args.run, args.finding, args.context_lines, args.max_chars)
            else:
                if not 1 <= args.limit <= 500 or args.offset < 0:
                    parser.error("limit must be 1..500; offset must be nonnegative")
                query = domains if args.command == "domains" else findings
                report = query(
                    store, args.run, args.site, args.domain, args.source, args.limit, args.offset
                )
            print(json.dumps(report, ensure_ascii=False))
            return
        if args.command in {"status", "failures", "verify", "resume", "retry"}:
            if (
                getattr(args, "limit", 1) < 1
                or getattr(args, "max_attempts", 1) < 1
                or getattr(args, "max_urls", 0) < 0
                or getattr(args, "offset", 0) < 0
            ):
                parser.error("limit/max-attempts must be positive; max-urls must be nonnegative")
            if args.command == "resume":
                resume(store, args.run, args.max_urls)
                report = status(store, args.run)
            elif args.command == "retry":
                report = retry(store, args.run, args.max_attempts, args.url)
            elif args.command == "failures":
                report = failures(store, args.run, args.limit, args.offset)
            elif args.command == "verify":
                report = verify(store, args.run)
            else:
                report = status(store, args.run)
            print(json.dumps(report, ensure_ascii=False))
            if args.command == "verify" and not report["integrity_ok"]:
                raise SystemExit(1)
            return
        if args.command == "scan":
            sites = []
            for line in Path(args.sites).read_text(encoding="utf-8-sig").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    site = line if "://" in line else "https://" + line
                    sites.append(canonical_url(site))
            if not sites:
                parser.error("site list is empty")
            if args.depth < 0 or args.delay < 0 or args.max_bytes < 1 or args.max_urls < 0:
                parser.error("depth/delay/max-urls must be nonnegative; max-bytes must be positive")
            latest = (
                store.db.execute(
                    "SELECT id FROM runs WHERE label='anonymous-static' ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if args.resume_latest
                else None
            )
            run = args.resume or (latest[0] if latest else store.new_run("anonymous-static"))
            if not store.db.execute("SELECT 1 FROM runs WHERE id=?", (run,)).fetchone():
                parser.error("resume run does not exist")
            config = {
                "sites": sites,
                "depth": args.depth,
                "delay": args.delay,
                "asset_hosts": sorted(normalize_hosts(args.asset_host)),
                "max_bytes": args.max_bytes,
                "user_agent": args.user_agent,
                "fingerprints": validate_fingerprints(args.fingerprint or DEFAULT_FINGERPRINTS),
                "browser_fallback": args.browser_fallback,
                "browser_crawl": args.browser_crawl,
                "browser_chrome": args.browser_chrome,
            }
            if not store.db.execute("SELECT 1 FROM run_configs WHERE run_id=?", (run,)).fetchone():
                save_config(
                    store,
                    run,
                    config,
                )
            else:
                saved = load_config(store, run)
                if any(
                    saved.get(key, False if key in {"browser_fallback", "browser_crawl"} else None)
                    != value
                    for key, value in config.items()
                ):
                    parser.error(
                        "resume configuration differs; use resume --run with saved configuration or create a new scan"
                    )
            if args.retry_failed:
                retry(store, run, 3, [])
            print(f"run_id={run}; static collection started", flush=True)
            resume(store, run, args.max_urls)
            print(f"run_id={run}; pending/failed are reported, not treated as complete")
        elif args.command == "browser":
            from .browser import BrowserLimits, collect_browser

            if args.wait < 0:
                parser.error("wait must be nonnegative")
            run = asyncio.run(
                collect_browser(
                    store,
                    args.url,
                    args.state,
                    args.chrome,
                    args.wait,
                    set(args.asset_host),
                    BrowserLimits(
                        args.max_seconds,
                        args.max_responses,
                        args.max_total_bytes,
                        args.max_bytes,
                        args.parse_seconds,
                    ),
                )
            )
            print(f"run_id={run}; check business-page authentication manually")
        elif args.command == "import-katana":
            run = store.new_run("katana-import")
            print(f"run_id={run}; import started", flush=True)
            import_katana(store, args.jsonl, args.site, run, 6, set())
            print(f"run_id={run}; imported body is Katana decoded text, not wire bytes")
        if args.command == "export":
            target = store.export(args.run)
            print(
                f"Results: {target / 'results.xlsx'}; manifest: {store.directory / 'current.json'}"
            )
        else:
            print("Saved to SQLite and evidence files; run export when CSV/Excel is needed.")
    except ValueError as error:
        parser.error(str(error))
    finally:
        store.close()
