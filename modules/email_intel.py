"""Email intelligence module (format, MX, provider, disposable, SPF, SMTP VRFY)."""

from __future__ import annotations

import asyncio
import logging
import re
import smtplib

import aiohttp
import dns.resolver

from core.config_loader import AppConfig
from core.constants import DISPOSABLE_DOMAINS, MAIL_PROVIDERS
from core.models import EmailIntelResult, SMTPStatus

LOGGER = logging.getLogger("osint_exposure_toolkit")
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _detect_provider(mx_records: list[str]) -> str:
    """Identify mail provider from MX hostname substring mapping."""

    lowered_records = [entry.lower() for entry in mx_records]
    for needle, provider in MAIL_PROVIDERS.items():
        if any(needle in record for record in lowered_records):
            return provider
    return "Custom / Unknown"


def _smtp_check_sync(mx_host: str, email: str) -> SMTPStatus:
    """Perform blocking SMTP VRFY check."""

    try:
        with smtplib.SMTP(mx_host, 25, timeout=5) as server:
            server.helo()
            code, _ = server.verify(email)
            if 200 <= code < 300:
                return SMTPStatus.VERIFIED
            if 500 <= code < 600:
                return SMTPStatus.NOT_VERIFIED
            return SMTPStatus.UNKNOWN
    except (ConnectionRefusedError, TimeoutError, smtplib.SMTPException, OSError):
        return SMTPStatus.UNKNOWN


async def _get_mx_records(domain: str) -> list[str]:
    """Resolve MX records for email domain."""

    resolver = dns.resolver.Resolver(configure=True)
    try:
        answers = await asyncio.get_running_loop().run_in_executor(None, resolver.resolve, domain, "MX")
        return sorted(str(record.exchange).rstrip(".") for record in answers)
    except Exception:
        return []


async def _has_spf_record(domain: str) -> bool:
    """Check if domain has an SPF TXT record."""

    resolver = dns.resolver.Resolver(configure=True)
    try:
        answers = await asyncio.get_running_loop().run_in_executor(None, resolver.resolve, domain, "TXT")
    except Exception:
        return False

    for answer in answers:
        text = "".join(part.decode() if isinstance(part, bytes) else str(part) for part in answer.strings)
        if text.lower().startswith("v=spf1"):
            return True
    return False


def _score_impact(format_valid: bool, mx_records: list[str], is_disposable: bool, smtp: SMTPStatus) -> int:
    """Compute Email Intel score impact from spec rules."""

    if not format_valid or not mx_records:
        return 0
    if is_disposable:
        return 5
    if smtp == SMTPStatus.VERIFIED:
        return 3
    return 1


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
) -> EmailIntelResult:
    """Run email intelligence checks.

    Args:
        session: Shared aiohttp session (unused, for signature consistency).
        semaphore: Shared global semaphore (unused, for signature consistency).
        config: AppConfig object.
        email: Target email.

    Returns:
        EmailIntelResult.
    """

    _ = (session, semaphore, config)

    if not email:
        return EmailIntelResult(skipped=True, skip_reason="No email provided.", score_impact=0)

    format_valid = bool(EMAIL_REGEX.match(email))
    if not format_valid:
        return EmailIntelResult(
            email=email,
            domain=email.split("@")[-1] if "@" in email else None,
            format_valid=False,
            mx_records=[],
            mail_provider=None,
            is_disposable=False,
            spf_present=False,
            smtp_verified=SMTPStatus.UNKNOWN,
            score_impact=0,
        )

    domain = email.split("@", maxsplit=1)[1].lower()
    mx_records = await _get_mx_records(domain)
    mail_provider = _detect_provider(mx_records)
    is_disposable = domain in set(DISPOSABLE_DOMAINS)
    spf_present = await _has_spf_record(domain)

    smtp_verified = SMTPStatus.UNKNOWN
    if mx_records:
        mx_host = mx_records[0]
        smtp_verified = await asyncio.get_running_loop().run_in_executor(
            None,
            _smtp_check_sync,
            mx_host,
            email,
        )

    return EmailIntelResult(
        email=email,
        domain=domain,
        format_valid=True,
        mx_records=mx_records,
        mail_provider=mail_provider,
        is_disposable=is_disposable,
        spf_present=spf_present,
        smtp_verified=smtp_verified,
        score_impact=_score_impact(True, mx_records, is_disposable, smtp_verified),
    )
