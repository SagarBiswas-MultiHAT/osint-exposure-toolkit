"""Shodan passive host and service reconnaissance module."""

from __future__ import annotations

import asyncio
import logging
import re

import aiohttp
import dns.resolver

from core.config_loader import AppConfig
from core.constants import (
    SHODAN_ADMIN_TITLES,
    SHODAN_CRITICAL_PORTS,
    SHODAN_HIGH_PORTS,
    SHODAN_HOST_URL,
    SHODAN_LEGACY_PROTOCOLS,
    SHODAN_MEDIUM_PORTS,
    USER_AGENT,
)
from core.models import ShodanHostResult, ShodanReconResult, ShodanService
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")


def _severity_rank(level: str) -> int:
    """Return numeric rank for severity string."""

    ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return ranks.get(level, 1)


def _extract_banner_excerpt(raw_banner: str | None) -> str | None:
    """Extract sanitized 200-char banner excerpt."""

    if not raw_banner:
        return None
    printable = "".join(ch for ch in raw_banner if ch.isprintable())
    return printable[:200]


def _classify_service(item: dict, host_vulns: list[str], tags: list[str]) -> str:
    """Classify one service finding severity."""

    port = int(item.get("port", 0) or 0)
    product = str(item.get("product") or "")
    version = str(item.get("version") or "")
    ssl_info = item.get("ssl") or {}
    http_title = str((item.get("http") or {}).get("title") or "")

    if port == 22 and "openssh" in product.lower():
        version_match = re.search(r"(\d+)\.(\d+)", version)
        if version_match:
            major = int(version_match.group(1))
            if major < 7:
                return "CRITICAL"

    if port in SHODAN_CRITICAL_PORTS and not ssl_info:
        return "CRITICAL"

    if host_vulns:
        return "HIGH"

    expires = str(((ssl_info.get("cert") or {}).get("expires")) or "")
    if expires and "20" in expires:
        pass

    subject = str((((ssl_info.get("cert") or {}).get("subject")) or {}).get("CN") or "")
    issuer = str((((ssl_info.get("cert") or {}).get("issuer")) or {}).get("CN") or "")
    if subject and issuer and subject == issuer:
        return "HIGH"

    if port in SHODAN_HIGH_PORTS or port in SHODAN_LEGACY_PROTOCOLS:
        return "HIGH"

    if port in SHODAN_MEDIUM_PORTS:
        return "MEDIUM"

    if any(tag.lower() == "tor" for tag in tags):
        return "MEDIUM"

    for title in SHODAN_ADMIN_TITLES:
        if title.lower() in http_title.lower():
            return "MEDIUM"

    if port in {25, 465, 587} and "starttls" not in str(item).lower():
        return "MEDIUM"

    return "LOW"


def _score(critical_count: int, high_count: int, medium_count: int, cve_count: int) -> int:
    """Compute score impact for Shodan module."""

    base = min(critical_count * 8 + high_count * 4 + medium_count * 2, 20)
    if cve_count > 0:
        base += min(cve_count * 2, 5)
    return min(base, 25)


async def _resolve_ips(domain: str, max_ips: int) -> list[str]:
    """Resolve domain A records into unique IP list."""

    resolver = dns.resolver.Resolver(configure=True)
    try:
        answers = await asyncio.get_running_loop().run_in_executor(None, resolver.resolve, domain, "A")
    except Exception:
        return []

    ips: list[str] = []
    for record in answers:
        ip = str(record)
        if ip not in ips:
            ips.append(ip)
        if len(ips) >= max_ips:
            break
    return ips


async def _fetch_host(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    key: str,
    ip: str,
) -> tuple[int, dict | None]:
    """Fetch Shodan host data for one IP with retry on 429."""

    url = SHODAN_HOST_URL.format(ip=ip)
    params = {"key": key}

    for attempt in range(2):
        async with semaphore:
            await limiter.acquire()
            try:
                async with session.get(url, params=params, headers={"User-Agent": USER_AGENT}) as response:
                    if response.status == 429 and attempt == 0:
                        await asyncio.sleep(5)
                        continue
                    if response.status >= 400:
                        return response.status, None
                    payload = await response.json()
                    return 200, payload if isinstance(payload, dict) else None
            except (aiohttp.ClientError, TimeoutError):
                if attempt == 1:
                    return 0, None

    return 429, None


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    target_domain: str | None,
) -> ShodanReconResult:
    """Run passive Shodan recon for target domain."""

    if not target_domain:
        return ShodanReconResult(
            skipped=True,
            skip_reason="No domain provided — Shodan requires a domain target.",
            score_impact=0,
        )

    shodan_key = config.api_keys.shodan.strip()
    if not shodan_key:
        LOGGER.warning("Shodan scan skipped — no API key configured. Add a free key to config.yaml.")
        return ShodanReconResult(
            skipped=True,
            skip_reason="Shodan scan skipped — no API key configured. Add a free key to config.yaml.",
            score_impact=0,
        )

    resolved_ips = await _resolve_ips(target_domain, config.scan_limits.max_shodan_ips)
    if not resolved_ips:
        LOGGER.warning("Shodan scan skipped — DNS resolution failed for %s", target_domain)
        return ShodanReconResult(
            skipped=True,
            skip_reason="DNS resolution failed for target domain.",
            target_domain=target_domain,
            score_impact=0,
        )

    limiter = AsyncRateLimiter(config.rate_limits.shodan_delay)

    hosts: list[ShodanHostResult] = []
    unique_cves: list[str] = []
    critical_count = 0
    high_count = 0
    medium_count = 0

    for ip in resolved_ips:
        status, payload = await _fetch_host(session, semaphore, limiter, shodan_key, ip)

        if status in {401, 403}:
            LOGGER.warning("Shodan API key invalid.")
            return ShodanReconResult(
                skipped=True,
                skip_reason="Shodan API key invalid.",
                target_domain=target_domain,
                resolved_ips=resolved_ips,
                score_impact=0,
            )
        if status == 404:
            continue
        if status == 429:
            LOGGER.warning("Shodan lookup for %s skipped after rate-limit retry.", ip)
            continue
        if status >= 400 and status != 0:
            LOGGER.warning("Shodan lookup failed for %s (status %s).", ip, status)
            continue
        if payload is None:
            continue

        data_rows = payload.get("data", []) if isinstance(payload.get("data"), list) else []
        vulns_map = payload.get("vulns") or {}
        if isinstance(vulns_map, dict):
            vulns = sorted(str(key) for key in vulns_map.keys())
        elif isinstance(vulns_map, list):
            vulns = sorted(str(item) for item in vulns_map)
        else:
            vulns = []

        tags = [str(item) for item in payload.get("tags", [])] if isinstance(payload.get("tags"), list) else []

        services: list[ShodanService] = []
        host_severity = "LOW"

        for row in data_rows:
            severity = _classify_service(row, vulns, tags)
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1

            service = ShodanService(
                port=int(row.get("port", 0) or 0),
                transport=str(row.get("transport") or "tcp"),
                product=row.get("product"),
                version=row.get("version"),
                banner_excerpt=_extract_banner_excerpt(row.get("data")),
                cpe=[str(item) for item in row.get("cpe", [])] if isinstance(row.get("cpe"), list) else [],
                ssl_subject=str((((row.get("ssl") or {}).get("cert") or {}).get("subject") or {}).get("CN") or "") or None,
                http_title=(row.get("http") or {}).get("title"),
                severity=severity,
            )
            services.append(service)
            if _severity_rank(severity) > _severity_rank(host_severity):
                host_severity = severity

        for cve in vulns:
            if cve not in unique_cves:
                unique_cves.append(cve)

        if vulns and _severity_rank("HIGH") > _severity_rank(host_severity):
            host_severity = "HIGH"

        host = ShodanHostResult(
            ip_str=str(payload.get("ip_str") or ip),
            hostnames=[str(item) for item in payload.get("hostnames", [])] if isinstance(payload.get("hostnames"), list) else [],
            org=payload.get("org"),
            country_name=payload.get("country_name"),
            isp=payload.get("isp"),
            last_update=payload.get("last_update"),
            open_ports=sorted({int(item.port) for item in services}),
            services=services,
            vulns=vulns,
            tags=tags,
            overall_severity=host_severity,
        )
        hosts.append(host)

    total_open_ports = sum(len(host.open_ports) for host in hosts)
    total_cves = len(unique_cves)
    score_impact = _score(critical_count, high_count, medium_count, total_cves)

    overall = "LOW"
    if critical_count > 0:
        overall = "CRITICAL"
    elif high_count > 0:
        overall = "HIGH"
    elif medium_count > 0:
        overall = "MEDIUM"

    return ShodanReconResult(
        skipped=False,
        target_domain=target_domain,
        resolved_ips=resolved_ips,
        hosts=hosts,
        total_open_ports=total_open_ports,
        total_cves=total_cves,
        unique_cves=unique_cves,
        critical_findings=critical_count,
        high_findings=high_count,
        medium_findings=medium_count,
        overall_severity=overall,
        score_impact=score_impact,
    )
