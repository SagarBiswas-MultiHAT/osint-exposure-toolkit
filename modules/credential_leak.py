"""Credential leak detection module (HIBP Free, Premium, Demo)."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import aiohttp

from core.config_loader import AppConfig
from core.constants import USER_AGENT
from core.models import BreachEntry, CredentialLeakResult, HIBPMode, PasteEntry, RiskSeverity
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_BREACHED_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_PASTE_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"


def classify_breach_severity(data_classes: list[str]) -> RiskSeverity:
    """Classify breach severity from HIBP DataClasses."""

    classes = {item.lower() for item in data_classes}

    has_passwords = "passwords" in classes
    has_identity = "email addresses" in classes or "usernames" in classes
    if has_passwords and has_identity:
        return RiskSeverity.CRITICAL

    if "password hints" in classes or "security questions and answers" in classes:
        return RiskSeverity.HIGH

    medium_markers = {"phone numbers", "addresses", "dates of birth"}
    if classes.intersection(medium_markers):
        return RiskSeverity.MEDIUM

    return RiskSeverity.LOW


def calculate_score_impact(total_breaches: int, overall_severity: RiskSeverity, mode: HIBPMode) -> int:
    """Calculate module score impact from spec formula."""

    if mode == HIBPMode.FREE:
        return 0

    base = min(total_breaches * 5, 20)
    if overall_severity == RiskSeverity.CRITICAL:
        base += 10
    elif overall_severity == RiskSeverity.HIGH:
        base += 5
    elif overall_severity == RiskSeverity.MEDIUM:
        base += 3

    return min(base, 30)


def _overall_severity(breaches: list[BreachEntry]) -> RiskSeverity:
    """Return highest severity present across breach entries."""

    if not breaches:
        return RiskSeverity.INFO

    levels = {
        RiskSeverity.CRITICAL: 4,
        RiskSeverity.HIGH: 3,
        RiskSeverity.MEDIUM: 2,
        RiskSeverity.LOW: 1,
        RiskSeverity.INFO: 0,
    }
    return max((entry.severity for entry in breaches), key=lambda item: levels[item])


def _fixture_path() -> Path:
    """Return path to shared HIBP fixture file."""

    return Path("tests/fixtures/hibp_mock.json")


def _load_fixture_payload() -> dict[str, Any]:
    """Load local fixture payload for demo mode."""

    fixture = _fixture_path()
    if not fixture.exists():
        return {"breaches": [], "pastes": []}

    try:
        return json.loads(fixture.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        LOGGER.warning("HIBP fixture unreadable; using empty demo payload.")
        return {"breaches": [], "pastes": []}


def _build_breach_entries(raw_entries: list[dict[str, Any]]) -> list[BreachEntry]:
    """Convert raw HIBP breach entries to typed models with computed severity."""

    breaches: list[BreachEntry] = []
    for item in raw_entries:
        try:
            entry = BreachEntry.model_validate(item)
            entry.severity = classify_breach_severity(entry.data_classes)
            breaches.append(entry)
        except Exception:
            LOGGER.warning("Skipped malformed HIBP breach entry.")
    return breaches


def _build_paste_entries(raw_entries: list[dict[str, Any]]) -> list[PasteEntry]:
    """Convert raw HIBP paste entries to typed models."""

    pastes: list[PasteEntry] = []
    for item in raw_entries:
        try:
            pastes.append(PasteEntry.model_validate(item))
        except Exception:
            LOGGER.warning("Skipped malformed HIBP paste entry.")
    return pastes


async def _fetch_hibp_json(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch HIBP endpoint and return JSON list response."""

    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    async with semaphore:
        await limiter.acquire()
        try:
            async with session.get(url, headers=request_headers) as response:
                if response.status == 404:
                    return []
                if response.status >= 400:
                    LOGGER.warning("HIBP request failed (%s) for %s", response.status, url)
                    return []
                payload = await response.json()
                return payload if isinstance(payload, list) else []
        except (aiohttp.ClientError, TimeoutError):
            LOGGER.warning("HIBP request timeout/network error for %s", url)
            return []


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
    mode: HIBPMode,
) -> CredentialLeakResult:
    """Execute HIBP scan in Free, Premium (Live), or Demo mode.

    Args:
        session: Shared aiohttp session.
        semaphore: Shared global concurrency semaphore.
        config: Application config.
        email: Target email when provided.
        mode: Selected HIBP mode.

    Returns:
        CredentialLeakResult with typed output.
    """

    if mode == HIBPMode.FREE or not email:
        limiter = AsyncRateLimiter(config.rate_limits.hibp_delay)
        breach_payload = await _fetch_hibp_json(session, semaphore, limiter, HIBP_BREACHES_URL)
        breaches = _build_breach_entries(breach_payload)
        total_pwned_accounts = sum(item.pwn_count for item in breaches)

        return CredentialLeakResult(
            email=email,
            mode=HIBPMode.FREE,
            demo_mode=False,
            hibp_source="api",
            total_breaches=len(breaches),
            total_pastes=0,
            total_pwned_accounts=total_pwned_accounts,
            breaches=breaches,
            pastes=[],
            overall_severity=RiskSeverity.INFO,
            note=(
                "Your target was not individually checked in Free mode. Switch to Premium "
                "HIBP mode for per-email breach lookup."
            ),
            score_impact=0,
        )

    hibp_key = config.api_keys.hibp.strip()
    use_demo = mode == HIBPMode.DEMO or not hibp_key

    if use_demo:
        payload = _load_fixture_payload()
        breaches = _build_breach_entries(payload.get("breaches", []))
        pastes = _build_paste_entries(payload.get("pastes", []))
        overall = _overall_severity(breaches)

        return CredentialLeakResult(
            email=email,
            mode=HIBPMode.DEMO,
            demo_mode=True,
            hibp_source="fixture",
            total_breaches=len(breaches),
            total_pastes=len(pastes),
            total_pwned_accounts=sum(item.pwn_count for item in breaches),
            breaches=breaches,
            pastes=pastes,
            overall_severity=overall,
            note="Demo Mode — fixture data loaded because HIBP API key is not configured.",
            score_impact=calculate_score_impact(len(breaches), overall, HIBPMode.DEMO),
        )

    limiter = AsyncRateLimiter(config.rate_limits.hibp_delay)
    headers = {"hibp-api-key": hibp_key}

    breach_payload = await _fetch_hibp_json(
        session,
        semaphore,
        limiter,
        HIBP_BREACHED_ACCOUNT_URL.format(email=email),
        headers=headers,
    )
    paste_payload = await _fetch_hibp_json(
        session,
        semaphore,
        limiter,
        HIBP_PASTE_ACCOUNT_URL.format(email=email),
        headers=headers,
    )

    breaches = _build_breach_entries(breach_payload)
    pastes = _build_paste_entries(paste_payload)
    overall = _overall_severity(breaches)

    return CredentialLeakResult(
        email=email,
        mode=HIBPMode.LIVE,
        demo_mode=False,
        hibp_source="api",
        total_breaches=len(breaches),
        total_pastes=len(pastes),
        total_pwned_accounts=sum(item.pwn_count for item in breaches),
        breaches=breaches,
        pastes=pastes,
        overall_severity=overall,
        score_impact=calculate_score_impact(len(breaches), overall, HIBPMode.LIVE),
    )
