"""Optional browser collector; reuse separately acquired authenticated state."""

import asyncio
from urllib.parse import urlsplit

from .collect import kind_for, process
from .store import Store


async def collect_browser(
    store: Store,
    url: str,
    state: str | None,
    chrome: str | None,
    wait: float,
    asset_hosts: set[str],
):
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import async_playwright

    run = store.new_run("authenticated-browser" if state else "anonymous-browser")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(executable_path=chrome)
        context = await browser.new_context(storage_state=state, service_workers="block")
        tasks = []
        errors = []
        request_number = 0

        async def route_request(route):
            nonlocal request_number
            request = route.request
            request_url = request.url
            allowed = urlsplit(request_url).netloc == urlsplit(url).netloc or (
                request.resource_type not in {"document"}
                and urlsplit(request_url).hostname in asset_hosts
            )
            # Preserve URL mentions even when a request is blocked; no usage judgement.
            request_number += 1
            evidence_url = f"{url}#request/{request_number}"
            store.save(run, url, evidence_url, request_url.encode(), request_url, "browser_url")
            if request.method not in {"GET", "HEAD"} or not allowed:
                errors.append(f"blocked {request.method} {request_url}")
                await route.abort()
            else:
                await route.continue_()

        async def capture(response):
            try:
                mime = response.headers.get("content-type", "")
                if any(token in mime for token in ("text", "javascript", "json", "xml")):
                    body = await response.body()
                    if len(body) > 32 * 1024 * 1024:
                        raise ValueError("browser response exceeds 32 MiB")
                    text = body.decode("utf-8", errors="replace")
                    process(
                        store,
                        run,
                        url,
                        response.url,
                        body,
                        text,
                        kind_for(response.url, mime),
                        0,
                        6,
                        asset_hosts,
                        response.status,
                    )
            except (PlaywrightError, ValueError) as error:
                errors.append(f"response unavailable {response.url}: {type(error).__name__}")

        await context.route("**/*", route_request)
        context.on(
            "response", lambda response: tasks.append(asyncio.create_task(capture(response)))
        )
        try:
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(wait * 1000)
            dom = await page.content()
            store.save(run, url, page.url + "#dom", dom.encode(), dom, "html")
            store.db.execute(
                "INSERT OR REPLACE INTO queue(run_id,site,url,depth,asset,state) VALUES(?,?,?,?,?,?)",
                (run, url, page.url + "#dom", 0, 0, "done"),
            )
            await asyncio.gather(*tasks)
            if urlsplit(page.url).netloc != urlsplit(url).netloc:
                errors.append("final page outside site; verify authentication")
        except PlaywrightError as error:
            errors.append(f"navigation failed: {type(error).__name__}")
        finally:
            await asyncio.gather(*tasks)
            await context.close()
            await browser.close()
        for index, error in enumerate(errors):
            store.db.execute(
                "INSERT OR REPLACE INTO queue(run_id,site,url,depth,asset,state,error) VALUES(?,?,?,?,?,?,?)",
                (run, url, f"{url}#browser-error/{index}", 0, 0, "failed", error),
            )
        store.db.commit()
    return run
