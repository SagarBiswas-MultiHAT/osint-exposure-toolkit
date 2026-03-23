"""Google dork query builder with optional DDG checks."""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import quote

import aiohttp

from core.config_loader import AppConfig
from core.constants import DORK_TEMPLATES, USER_AGENT
from core.models import DDGResult, DorkResult, GoogleDorksResult
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")


def _render_templates(domain: str | None, email: str | None) -> list[DorkResult]:
    """Render all dork categories from constant templates."""

    results: list[DorkResult] = []
    for category, templates in DORK_TEMPLATES.items():
        rendered_queries: list[str] = []
        for template in templates:
            if "{domain}" in template and not domain:
                continue
            if "{email}" in template and not email:
                continue
            rendered_queries.append(template.format(domain=domain or "", email=email or ""))

        if rendered_queries:
            results.append(DorkResult(category=category, queries=rendered_queries, ddg_result=DDGResult.NOT_CHECKED))

    return results


def _looks_like_results_found(html: str) -> bool:
    """Heuristic DDG result detection from HTML page."""

    return bool(re.search(r"result__a|result__url|results_links", html, flags=re.IGNORECASE))


async def _ddg_check(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    query: str,
    timeout_seconds: int,
) -> DDGResult:
    """Execute one optional DDG HTML query check."""

    url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
    async with semaphore:
        await limiter.acquire()
        try:
            async with session.get(url, timeout=timeout_seconds, headers={"User-Agent": USER_AGENT}) as response:
                if response.status == 200:
                    body = await response.text()
                    return DDGResult.RESULTS_FOUND if _looks_like_results_found(body) else DDGResult.NO_RESULTS
                if response.status in {202, 429}:
                    LOGGER.warning("DuckDuckGo blocked query check: %s", query)
                    return DDGResult.NOT_CHECKED
                LOGGER.warning("DuckDuckGo non-200 status (%s) for query check.", response.status)
                return DDGResult.NOT_CHECKED
        except (aiohttp.ClientError, TimeoutError):
            LOGGER.warning("DuckDuckGo query check failed due to timeout/network issue.")
            return DDGResult.NOT_CHECKED


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    domain: str | None,
    email: str | None,
    enable_live_check: bool = True,
) -> GoogleDorksResult:
    """Generate passive dorks and optionally verify limited subset via DDG."""

    dork_results = _render_templates(domain, email)
    if not dork_results:
        return GoogleDorksResult(skipped=True, skip_reason="No valid target for dork generation.", score_impact=0)

    checks_performed = 0
    blocked_streak = 0
    limiter = AsyncRateLimiter(config.rate_limits.ddg_delay)

    if enable_live_check:
        for result in dork_results:
            if checks_performed >= config.scan_limits.max_dork_live_checks:
                break
            if blocked_streak >= 2:
                break
            if not result.queries:
                continue

            ddg_result = await _ddg_check(
                session,
                semaphore,
                limiter,
                result.queries[0],
                timeout_seconds=config.general.request_timeout,
            )
            result.ddg_result = ddg_result
            checks_performed += 1

            if ddg_result == DDGResult.NOT_CHECKED:
                blocked_streak += 1
            else:
                blocked_streak = 0

    hits = sum(1 for result in dork_results if result.ddg_result == DDGResult.RESULTS_FOUND)
    return GoogleDorksResult(
        skipped=False,
        results=dork_results,
        ddg_checks_performed=checks_performed,
        score_impact=min(hits, 5),
    )
