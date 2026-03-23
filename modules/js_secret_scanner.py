"""Public JavaScript file secret and leakage scanner."""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from core.config_loader import AppConfig
from core.constants import JS_EXTRA_PATTERNS, SECRET_PATTERNS, USER_AGENT
from core.models import JSSecretFinding, JSSecretResult, RiskSeverity
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")
MAX_JS_FILE_SIZE = 500 * 1024


def _mask_value(value: str) -> str:
    """Mask sensitive values as first4***last4."""

    if len(value) <= 8:
        return "***"
    return f"{value[:4]}***{value[-4:]}"


def _same_domain(base_domain: str, candidate_url: str) -> bool:
    """Check if URL is same-domain as target."""

    parsed = urlparse(candidate_url)
    return parsed.netloc == base_domain


def _collect_js_urls(homepage_url: str, html: str) -> list[str]:
    """Extract same-domain script src URLs from homepage HTML."""

    soup = BeautifulSoup(html, "lxml")
    base_domain = urlparse(homepage_url).netloc

    urls: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        absolute = urljoin(homepage_url, src)
        if _same_domain(base_domain, absolute) and absolute not in urls:
            urls.append(absolute)
    return urls


def _pattern_bank() -> list[tuple[str, re.Pattern[str], bool]]:
    """Return regex pattern tuples with flag for auxiliary hints."""

    patterns: list[tuple[str, re.Pattern[str], bool]] = []
    for name, raw in SECRET_PATTERNS.items():
        patterns.append((name, re.compile(raw), False))
    for name, raw in JS_EXTRA_PATTERNS.items():
        patterns.append((name, re.compile(raw), True))
    return patterns


async def _fetch_text(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
) -> str | None:
    """Fetch URL text content with status checks and pacing."""

    async with semaphore:
        await limiter.acquire()
        try:
            async with session.get(url, headers={"User-Agent": USER_AGENT}) as response:
                if response.status != 200:
                    return None
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_JS_FILE_SIZE:
                    LOGGER.warning("Skipping oversized JS file: %s", url)
                    return None
                data = await response.read()
                if len(data) > MAX_JS_FILE_SIZE:
                    LOGGER.warning("Skipping oversized JS file: %s", url)
                    return None
                return data.decode("utf-8", errors="ignore")
        except (aiohttp.ClientError, TimeoutError):
            return None


def _severity_for_pattern(name: str) -> RiskSeverity:
    """Determine severity level for a matched pattern name."""

    lowered = name.lower()
    if "private key" in lowered or "secret" in lowered or "password" in lowered:
        return RiskSeverity.CRITICAL
    if "token" in lowered or "api key" in lowered:
        return RiskSeverity.HIGH
    if name in JS_EXTRA_PATTERNS:
        return RiskSeverity.LOW
    return RiskSeverity.MEDIUM


def _extract_matches(js_url: str, content: str) -> tuple[list[JSSecretFinding], list[str], list[str]]:
    """Extract secret findings and JS hint artifacts from content."""

    findings: list[JSSecretFinding] = []
    internal_endpoints: list[str] = []
    env_hints: list[str] = []

    for name, pattern, is_hint in _pattern_bank():
        for match in pattern.finditer(content):
            raw_value = match.group(0)
            if name == "AWS Secret Access Key" and match.lastindex:
                raw_value = match.group(match.lastindex)

            masked = _mask_value(raw_value)
            if is_hint:
                if name == "Internal Path Hint" and raw_value not in internal_endpoints:
                    internal_endpoints.append(raw_value)
                if name == "Environment Flag" and raw_value not in env_hints:
                    env_hints.append(raw_value)

            findings.append(
                JSSecretFinding(
                    js_file_url=js_url,
                    pattern_type=name,
                    masked_value=masked,
                    severity=_severity_for_pattern(name),
                )
            )

    return findings, internal_endpoints, env_hints


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    domain: str | None,
) -> JSSecretResult:
    """Run same-domain JS secret scanning for target domain."""

    if not domain:
        return JSSecretResult(
            skipped=True,
            skip_reason="No domain provided — JS scan requires a domain.",
            score_impact=0,
        )

    limiter = AsyncRateLimiter(config.rate_limits.github_delay)
    homepage_url = f"https://{domain}"
    homepage = await _fetch_text(session, semaphore, limiter, homepage_url)
    if homepage is None:
        return JSSecretResult(domain=domain, skipped=False, js_files_scanned=0, score_impact=0)

    js_urls = _collect_js_urls(homepage_url, homepage)[: config.scan_limits.max_js_files]

    all_findings: list[JSSecretFinding] = []
    internal_endpoints: list[str] = []
    env_hints: list[str] = []

    for js_url in js_urls:
        content = await _fetch_text(session, semaphore, limiter, js_url)
        if content is None:
            continue
        findings, endpoints, hints = _extract_matches(js_url, content)
        all_findings.extend(findings)
        for endpoint in endpoints:
            if endpoint not in internal_endpoints:
                internal_endpoints.append(endpoint)
        for hint in hints:
            if hint not in env_hints:
                env_hints.append(hint)

    base = min(len(all_findings) * 5, 15)
    if internal_endpoints:
        base += 3
    if env_hints:
        base += 2

    return JSSecretResult(
        skipped=False,
        domain=domain,
        js_files_scanned=len(js_urls),
        secrets_found=all_findings,
        internal_endpoints_found=internal_endpoints,
        environment_hints=env_hints,
        score_impact=min(base, 20),
    )
