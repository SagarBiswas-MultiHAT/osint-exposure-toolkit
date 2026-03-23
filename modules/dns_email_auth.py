"""DNS email authentication analysis module."""

from __future__ import annotations

import asyncio
import logging
import re

import aiohttp
import dns.resolver

from core.config_loader import AppConfig
from core.constants import DKIM_SELECTORS, SPOOFABILITY_WEIGHTS, USER_AGENT
from core.models import DKIMStatus, DMARCStatus, EmailAuthResult, MTASTSStatus, SPFStatus

LOGGER = logging.getLogger("osint_exposure_toolkit")


def _decode_txt(answer: dns.rrset.RRset) -> str:
    """Decode DNS TXT record value."""

    return "".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings)


async def _resolve_txt(name: str) -> list[str]:
    """Resolve TXT records for a DNS name."""

    resolver = dns.resolver.Resolver(configure=True)
    try:
        answers = await asyncio.get_running_loop().run_in_executor(None, resolver.resolve, name, "TXT")
    except Exception:
        return []
    return [_decode_txt(answer) for answer in answers]


async def _check_spf(domain: str) -> SPFStatus:
    """Check SPF presence and strength."""

    txt_records = await _resolve_txt(domain)
    for record in txt_records:
        lowered = record.lower()
        if not lowered.startswith("v=spf1"):
            continue

        mechanisms = re.findall(r"\b(?:include|a|mx|ptr|exists):", lowered)
        over_limit = len(mechanisms) > 10
        if "+all" in lowered:
            strength = "OPEN"
        elif "~all" in lowered:
            strength = "SOFTFAIL"
        elif "-all" in lowered:
            strength = "STRICT"
        else:
            strength = "PARTIAL"

        return SPFStatus(
            present=True,
            record=record,
            strength=strength,
            over_lookup_limit=over_limit,
        )

    return SPFStatus(present=False, record=None, strength="MISSING", over_lookup_limit=False)


async def _check_dmarc(domain: str) -> DMARCStatus:
    """Check DMARC record."""

    records = await _resolve_txt(f"_dmarc.{domain}")
    for record in records:
        lowered = record.lower()
        if not lowered.startswith("v=dmarc1"):
            continue

        values: dict[str, str] = {}
        for part in record.split(";"):
            chunk = part.strip()
            if "=" in chunk:
                key, value = chunk.split("=", maxsplit=1)
                values[key.strip().lower()] = value.strip()

        return DMARCStatus(
            present=True,
            record=record,
            policy=values.get("p"),
            rua=values.get("rua"),
            ruf=values.get("ruf"),
            aspf=values.get("aspf"),
            adkim=values.get("adkim"),
        )

    return DMARCStatus(present=False)


async def _check_dkim(domain: str, concurrency: int) -> DKIMStatus:
    """Probe DKIM selectors from constants list."""

    semaphore = asyncio.Semaphore(concurrency)

    async def probe(selector: str) -> str | None:
        query_name = f"{selector}._domainkey.{domain}"
        async with semaphore:
            records = await _resolve_txt(query_name)
        if records:
            return selector
        return None

    results = await asyncio.gather(*(probe(selector) for selector in DKIM_SELECTORS))
    selectors = [item for item in results if item]

    return DKIMStatus(selectors_found=selectors, weak_selectors=[])


async def _check_mta_sts(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    domain: str,
    timeout_seconds: int,
) -> MTASTSStatus:
    """Check MTA-STS TXT and policy endpoint."""

    txt_records = await _resolve_txt(f"_mta-sts.{domain}")
    txt_present = any(record.lower().startswith("v=stsv1") for record in txt_records)
    if not txt_present:
        return MTASTSStatus(present=False, mode=None)

    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    async with semaphore:
        try:
            async with session.get(
                policy_url,
                timeout=timeout_seconds,
                headers={"User-Agent": USER_AGENT},
            ) as response:
                if response.status != 200:
                    return MTASTSStatus(present=True, mode=None)
                body = await response.text()
        except (aiohttp.ClientError, TimeoutError):
            return MTASTSStatus(present=True, mode=None)

    mode_match = re.search(r"^mode:\s*(\w+)$", body, flags=re.IGNORECASE | re.MULTILINE)
    mode = mode_match.group(1).lower() if mode_match else None
    return MTASTSStatus(present=True, mode=mode)


def _spoofability_score(spf: SPFStatus, dmarc: DMARCStatus, dkim: DKIMStatus) -> int:
    """Compute spoofability score from SPF/DMARC/DKIM states."""

    if not spf.present and not dmarc.present and not dkim.selectors_found:
        return 10

    score = 0

    if not spf.present:
        score += SPOOFABILITY_WEIGHTS["SPF_MISSING"]
    elif spf.strength in {"OPEN", "SOFTFAIL"}:
        score += SPOOFABILITY_WEIGHTS["SPF_WEAK"]

    if not dmarc.present:
        score += SPOOFABILITY_WEIGHTS["DMARC_MISSING"]
    elif (dmarc.policy or "").lower() == "none":
        score += SPOOFABILITY_WEIGHTS["DMARC_NONE"]

    if not dkim.selectors_found:
        score += SPOOFABILITY_WEIGHTS["DKIM_MISSING"]

    return min(score, 10)


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    domain: str | None,
) -> EmailAuthResult:
    """Run DNS email authentication analysis.

    Args:
        session: Shared aiohttp session.
        semaphore: Shared global concurrency semaphore.
        config: AppConfig object.
        domain: Target domain.

    Returns:
        EmailAuthResult typed model.
    """

    if not domain:
        return EmailAuthResult(skipped=True, skip_reason="No domain provided.", score_impact=0)

    try:
        spf = await _check_spf(domain)
        dmarc = await _check_dmarc(domain)
        dkim = await _check_dkim(domain, config.rate_limits.dns_concurrent)
        mta_sts = await _check_mta_sts(
            session,
            semaphore,
            domain,
            timeout_seconds=config.general.request_timeout,
        )
    except Exception:
        LOGGER.warning("DNS auth checks returned partial result for %s", domain)
        spf = SPFStatus(present=False)
        dmarc = DMARCStatus(present=False)
        dkim = DKIMStatus(selectors_found=[], weak_selectors=[])
        mta_sts = MTASTSStatus(present=False)

    spoof = _spoofability_score(spf, dmarc, dkim)
    return EmailAuthResult(
        domain=domain,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        mta_sts=mta_sts,
        spoofability_score=spoof,
        score_impact=min(spoof * 2, 20),
    )
