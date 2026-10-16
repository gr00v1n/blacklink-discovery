"""Bounded single-page browser supplement with fail-closed network interception."""

import asyncio
import hashlib
import json
import sqlite3
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

import httpx

from .collect import clean_url, kind_for, progress
from .extract import Mention
from .store import Store
from .text import decode_body
from .urls import authorized, canonical_url, non_text_response, non_text_url, normalize_hosts


@asynccontextmanager
async def forwarded_response(client, method, url, headers):
    # Use Chrome's exact cookies, never HTTPX's accumulated cookie jar.
    response = await client.send(httpx.Request(method, url, headers=headers), stream=True)
    try:
        yield response
    finally:
        await response.aclose()


@dataclass(frozen=True)
class BrowserLimits:
    seconds: float = 120
    responses: int = 500
    bytes: int = 128 * 1024 * 1024
    response_bytes: int = 32 * 1024 * 1024
    parse_seconds: float = 30


async def parse_response(text: str, kind: str, url: str, seconds: float):
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "blacklink_discovery.worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        output, _errors = await asyncio.wait_for(
            child.communicate(
                json.dumps({"text": text, "kind": kind, "url": url}, ensure_ascii=True).encode()
            ),
            seconds,
        )
        if child.returncode:
            raise ValueError("browser extraction failed (worker error)")
        return json.loads(output)
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()


async def collect_browser(
    store: Store,
    url: str,
    state: str | None,
    chrome: str | None,
    wait: float,
    asset_hosts: set[str],
    limits: BrowserLimits | None = None,
    *,
    parent_run: int | None = None,
    parent_site: str | None = None,
):
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import async_playwright

    url, asset_hosts = canonical_url(url), normalize_hosts(asset_hosts)
    limits = limits or BrowserLimits()
    if (
        min(
            limits.seconds,
            limits.responses,
            limits.bytes,
            limits.response_bytes,
            limits.parse_seconds,
        )
        <= 0
    ):
        raise ValueError("browser limits must be positive")
    run = store.new_run("authenticated-browser" if state else "anonymous-browser")
    # Linked page batches share response bodies in the parent run. The page batch
    # only keeps its own request observations and rendered DOM.
    evidence_run = parent_run if parent_run is not None else run
    if parent_run is not None:
        store.db.execute(
            "UPDATE browser_fallbacks SET browser_run_id=? WHERE run_id=? AND site=? AND url=?",
            (run, parent_run, parent_site, url),
        )
        store.db.commit()
    print(f"run_id={run}; browser supplement started", flush=True)
    progress(store, run, "browser_started")
    pending = asyncio.Queue(maxsize=8)
    active = set()
    errors = []
    receiving = True
    total_bytes, response_count = 0, 0
    semaphore = asyncio.Semaphore(4)
    browser = context = None
    finalized = False

    def observation(request_url, method, resource_type):
        identity = store.db.execute(
            "INSERT INTO request_observations(run_id,site,page,url,method,resource_type,state) VALUES(?,?,?,?,?,?,?)",
            (run, url, url, request_url, method, resource_type, "observed"),
        ).lastrowid
        store.db.commit()
        return identity

    def finish(identity, request_url, outcome, status=None, error="", resource=None):
        if finalized:
            return
        existing = store.db.execute(
            "SELECT state,error,resource_id FROM request_observations WHERE id=?", (identity,)
        ).fetchone()
        if (
            existing
            and existing["state"] in {"blocked_redirect", "blocked", "interrupted"}
            and outcome in {"captured", "failed"}
        ):
            outcome = existing["state"]
            error = error or existing["error"] or ""
        resource = resource or (existing["resource_id"] if existing else None)
        store.db.execute(
            "UPDATE request_observations SET state=?,status=?,error=?,resource_id=? WHERE id=?",
            (outcome, status, error, resource, identity),
        )
        store.db.commit()
        if error:
            errors.append(error)

    async def persist(identity, request_url, body, mime, status):
        text, encoding, warning = decode_body(body, mime)
        kind = kind_for(request_url, mime)
        existing = store.db.execute(
            "SELECT id FROM resources WHERE run_id=? AND url=? AND collector='browser_response' AND status=? AND evidence_path=?",
            (
                evidence_run,
                request_url,
                status,
                f"evidence/{hashlib.sha256(body).hexdigest()}",
            ),
        ).fetchone()
        if existing:
            store.edge(
                evidence_run,
                parent_site or url,
                url,
                request_url,
                "browser_response",
                parent_resource_id=existing[0],
            )
            finish(identity, request_url, "captured", status, warning, existing[0])
            return
        progress(store, run, "browser_parse", request_url)
        parsed = await parse_response(text, kind, request_url, limits.parse_seconds)
        if finalized:
            return
        # Keep the scan entry as site. Response URL is the resource URL, so one
        # script stays one finding set while each page keeps its own edge.
        resource = store.save(
            evidence_run,
            parent_site or url,
            request_url,
            body,
            text,
            kind,
            status,
            warning,
            collector="browser_response",
            encoding=encoding,
            mentions=[Mention(**m) for m in parsed["mentions"]],
        )
        store.edge(
            evidence_run,
            parent_site or url,
            url,
            request_url,
            "browser_response",
            parent_resource_id=resource,
        )
        for child, _, relation, *position in parsed["references"]:
            start, end = (position + [None, None])[:2]
            store.edge(
                evidence_run,
                parent_site or url,
                request_url,
                child,
                relation,
                parent_resource_id=resource,
                start=start,
                end=end,
            )
        for source in parsed["sources"]:
            derived = request_url + f"#sourcesContent/{source['index']}"
            store.save(
                evidence_run,
                parent_site or url,
                derived,
                source["text"].encode(),
                source["text"],
                "js",
                status,
                source["error"],
                collector="source_map",
                parent_resource_id=resource,
                mentions=[Mention(**m) for m in source["mentions"]],
            )
            store.edge(
                evidence_run,
                parent_site or url,
                request_url,
                derived,
                "source_map_content",
                parent_resource_id=resource,
            )
            if source["error"]:
                warning = source["error"]
        error = warning or (f"HTTP {status}: {request_url}" if status >= 400 else "")
        finish(identity, request_url, "failed" if error else "captured", status, error, resource)

    async def consumer():
        while True:
            item = await pending.get()
            try:
                if item is None:
                    return
                try:
                    await persist(*item)
                except (ValueError, TimeoutError, OSError, sqlite3.Error) as error:
                    store.db.rollback()
                    finish(
                        item[0], item[1], "failed", item[4], f"parse failed: {type(error).__name__}"
                    )
            finally:
                pending.task_done()

    async def route_request(route, client):
        nonlocal response_count, total_bytes
        if finalized:
            await route.abort()
            return
        task = asyncio.current_task()
        active.add(task)
        request = route.request
        identity = observation(request.url, request.method, request.resource_type)
        try:
            relative_depth = 0
            try:
                frame = request.frame
                if request.is_navigation_request() and frame == page.main_frame:
                    current_document["status"] = 0
                    current_document["generation"] += 1
                while frame.parent_frame is not None:
                    relative_depth += 1
                    frame = frame.parent_frame
            except PlaywrightError:
                # Worker requests have no frame; URL evidence must still survive.
                pass
            store.db.execute(
                "INSERT INTO browser_depths(run_id,url,depth) VALUES(?,?,?) "
                "ON CONFLICT(run_id,url) DO UPDATE SET depth=MIN(depth,excluded.depth)",
                (run, canonical_url(request.url), relative_depth),
            )
            store.db.commit()
            # URL mentions survive even for blocked requests; duplicates share one evidence resource.
            resource = store.save(
                run,
                url,
                request.url + "#observed-url",
                request.url.encode(),
                request.url,
                "browser_url",
                collector="browser_url",
            )
            store.edge(run, url, url, request.url, "browser_request", parent_resource_id=resource)
            request_url = canonical_url(request.url)
            if (
                not receiving
                or request.method not in {"GET", "HEAD"}
                or not authorized(
                    request_url, url, request.resource_type != "document", asset_hosts
                )
            ):
                finish(
                    identity,
                    request.url,
                    "blocked",
                    error=f"blocked {request.method}: {request.url}",
                )
                await route.abort()
                return
            if non_text_url(request_url):
                finish(identity, request_url, "not_text")
                await route.abort()
                return
            if response_count >= limits.responses:
                finish(
                    identity, request.url, "blocked", error="browser response count limit reached"
                )
                await route.abort()
                return
            response_count += 1
            async with semaphore:
                if not receiving:
                    raise ValueError("browser stopping")
                progress(store, run, "browser_request", request_url)
                # Chrome never follows a redirect: HTTPX receives each request with redirects disabled.
                headers = await request.all_headers()
                headers = {
                    k: v
                    for k, v in headers.items()
                    if k.lower() not in {"host", "connection", "content-length", "accept-encoding"}
                }
                async with forwarded_response(
                    client, request.method, request_url, headers
                ) as response:
                    mime = response.headers.get("content-type", "")
                    if non_text_response(request_url, mime):
                        finish(identity, request_url, "not_text", response.status_code)
                        await route.abort()
                        return
                    parts, size = [], 0
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        if not parts and non_text_response(request_url, mime, chunk[:16]):
                            finish(identity, request_url, "not_text", response.status_code)
                            await route.abort()
                            return
                        size += len(chunk)
                        total_bytes += len(chunk)
                        if size > limits.response_bytes or total_bytes > limits.bytes:
                            raise ValueError("browser byte limit reached")
                        parts.append(chunk)
                    body = b"".join(parts)
                    textual = (
                        not mime
                        or response.status_code >= 400
                        or request.resource_type in {"script", "fetch", "xhr"}
                        or any(
                            token in mime.lower() for token in ("text", "javascript", "json", "xml")
                        )
                        or kind_for(request_url, mime) != "text"
                    )
                    if textual:
                        text, encoding, warning = decode_body(body, mime)
                        received = store.save(
                            evidence_run,
                            parent_site or url,
                            request_url,
                            body,
                            text,
                            kind_for(request_url, mime),
                            response.status_code,
                            warning,
                            collector="browser_received",
                            encoding=encoding,
                            mentions=[],
                        )
                        finish(
                            identity,
                            request_url,
                            "awaiting_parse",
                            response.status_code,
                            resource=received,
                        )
                        await pending.put((identity, request_url, body, mime, response.status_code))
                    else:
                        finish(identity, request_url, "not_text", response.status_code)
                    if response.is_redirect:
                        location = response.headers.get("location", "")
                        target = clean_url(request_url, location)
                        if location:
                            store.save(
                                run,
                                url,
                                request_url + "#location",
                                location.encode(),
                                location,
                                "response_header",
                                response.status_code,
                                collector="browser_header",
                            )
                        if target:
                            store.edge(run, url, request_url, target, "blocked_redirect")
                        errors.append(f"browser redirect not followed: {request_url}")
                        finish(identity, request_url, "blocked_redirect", response.status_code)
                        await route.abort()
                        return
                    forwarded = {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower()
                        not in {
                            "content-encoding",
                            "content-length",
                            "transfer-encoding",
                            "connection",
                            "set-cookie",
                        }
                    }
                    cookies = response.headers.get_list("set-cookie")
                    if cookies:
                        forwarded["set-cookie"] = "\n".join(cookies)
                    await route.fulfill(status=response.status_code, headers=forwarded, body=body)
        except asyncio.CancelledError:
            finish(identity, request.url, "interrupted", error="browser request interrupted")
            raise
        except (ValueError, httpx.HTTPError, PlaywrightError, OSError) as error:
            finish(
                identity,
                request.url,
                "failed",
                error=f"request failed: {type(error).__name__}: {request.url}",
            )
            try:
                await route.abort()
            except PlaywrightError:
                pass
        finally:
            active.discard(task)

    async def block_websocket(socket):
        identity = observation(socket.url, "WEBSOCKET", "websocket")
        store.save(
            run,
            url,
            socket.url + "#observed-url",
            socket.url.encode(),
            socket.url,
            "browser_url",
            collector="browser_url",
        )
        finish(identity, socket.url, "blocked", error="WebSocket blocked by read-only policy")
        await socket.close()

    collector_task = asyncio.create_task(consumer())
    collection_task = asyncio.current_task()

    def consumer_stopped(task):
        if not finalized and not task.cancelled() and task.exception() is not None:
            collection_task.cancel()

    collector_task.add_done_callback(consumer_stopped)
    exits = AsyncExitStack()
    try:
        async with asyncio.timeout(limits.seconds):
            playwright = await exits.enter_async_context(async_playwright())
            client = await exits.enter_async_context(
                httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False)
            )
            try:
                browser = await playwright.chromium.launch(executable_path=chrome)
                context = await browser.new_context(storage_state=state, service_workers="block")
                await context.route("**/*", lambda route: route_request(route, client))
                await context.route_web_socket("**/*", block_websocket)
                page = await context.new_page()
                current_document = {"status": 0, "generation": 0}

                def document_response(response):
                    if (
                        response.request.is_navigation_request()
                        and response.frame == page.main_frame
                    ):
                        current_document["status"] = response.status

                page.on("response", document_response)
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=min(30000, limits.seconds * 1000)
                )
                if response is None or response.status >= 400:
                    errors.append("main document failed; DOM is not successful coverage")
                await page.wait_for_timeout(wait * 1000)
                dom_url = page.url
                generation = current_document["generation"]
                dom = await page.content()
                dom_status = (
                    current_document["status"]
                    if page.url == dom_url and current_document["generation"] == generation
                    else 0
                )
                store.save(
                    run,
                    url,
                    url + "#dom",
                    dom.encode(),
                    dom,
                    "html",
                    status=dom_status,
                    collector="browser_dom_received",
                    mentions=[],
                )
                parsed = await parse_response(dom, "html", dom_url, limits.parse_seconds)
                resource = store.save(
                    run,
                    url,
                    url + "#dom",
                    dom.encode(),
                    dom,
                    "html",
                    status=dom_status,
                    collector="browser_dom",
                    mentions=[Mention(**m) for m in parsed["mentions"]],
                )
                store.edge(run, url, url, url + "#dom", "rendered_dom", parent_resource_id=resource)
            finally:
                receiving = False
            if context:
                await context.close()
            # Supervise producers while they may be waiting on a full queue.
            while active:
                done, _ = await asyncio.wait(
                    {*active, collector_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if collector_task in done:
                    error = collector_task.exception()
                    raise ValueError("browser consumer stopped") from error
            drain = asyncio.create_task(pending.join())
            try:
                done, _ = await asyncio.wait(
                    {drain, collector_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if collector_task in done:
                    raise ValueError("browser consumer stopped") from collector_task.exception()
                await drain
            finally:
                drain.cancel()
            await pending.put(None)
            await collector_task
    except asyncio.CancelledError:
        if collector_task.done() and not collector_task.cancelled() and collector_task.exception():
            errors.append(f"browser consumer failed: {type(collector_task.exception()).__name__}")
        else:
            errors.append("browser incomplete: cancelled")
            raise
    except (TimeoutError, PlaywrightError, ValueError, OSError, sqlite3.Error) as error:
        store.db.rollback()
        errors.append(f"browser incomplete: {type(error).__name__}")
    except Exception as error:
        store.db.rollback()
        errors.append(f"browser unexpected failure: {type(error).__name__}")
        raise
    finally:
        receiving = False
        finalized = True
        for task in tuple(active):
            task.cancel()
        if not collector_task.done():
            collector_task.cancel()

        async def cleanup():
            results = await asyncio.gather(*tuple(active), collector_task, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    errors.append(f"browser cleanup failed: {type(result).__name__}")
            # Playwright's transport must outlive context/browser close operations.
            try:
                if context:
                    await context.close()
            finally:
                try:
                    if browser:
                        await browser.close()
                finally:
                    await exits.aclose()

        cleanup_task = asyncio.create_task(cleanup())
        done, _ = await asyncio.wait({cleanup_task}, timeout=3)
        if cleanup_task not in done:
            cleanup_task.cancel()
            errors.append("browser cleanup deadline reached")
        else:
            result = cleanup_task.exception()
            if result:
                errors.append(f"browser cleanup failed: {type(result).__name__}")
        store.db.execute(
            "UPDATE request_observations SET state='interrupted',error='collection stopped before capture completed' WHERE run_id=? AND state IN ('observed','awaiting_parse')",
            (run,),
        )
        unfinished = store.db.execute(
            "SELECT COUNT(*) FROM request_observations WHERE run_id=? AND state IN ('failed','blocked','blocked_redirect','interrupted')",
            (run,),
        ).fetchone()[0]
        if unfinished:
            errors.append(f"{unfinished} incomplete/blocked requests")
        store.db.execute(
            "INSERT OR REPLACE INTO queue(run_id,site,url,depth,asset,state,error) VALUES(?,?,?,?,?,?,?)",
            (run, url, url, 0, 0, "failed" if errors else "done", "; ".join(errors) or None),
        )
        store.db.commit()
        progress(store, run, "browser_partial" if errors else "browser_finished", "; ".join(errors))
    return run
