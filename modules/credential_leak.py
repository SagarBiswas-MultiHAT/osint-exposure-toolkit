"""Credential leak detection module with LeakCheck default and HIBP opt-in."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import aiohttp

from core.config_loader import AppConfig
from core.constants import (
    LEAKCHECK_AUTH_URL,
    LEAKCHECK_PASSWORD_TYPES_CRITICAL,
    LEAKCHECK_PUBLIC_URL,
    LEAKCHECK_SEVERITY_FIELDS,
    USER_AGENT,
)
from core.models import BreachEntry, CredentialLeakResult, HIBPMode, PasteEntry, RiskSeverity
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_BREACHED_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
HIBP_PASTE_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"


def select_engine_choice(choice: str | None) -> str:
    """Resolve engine from user input with LeakCheck default behavior."""

    normalized = (choice or "").strip().lower()
    if normalized in {"", "1", "leakcheck"}:
        return "leakcheck"
    if normalized in {"2", "hibp"}:
        return "hibp"
    return "leakcheck"


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


def _calculate_score_impact(total: int, overall_severity: RiskSeverity, free_mode: bool = False) -> int:
    """Calculate score impact using shared max-30 formula."""

    if free_mode:
        return 0

    base = min(total * 5, 20)
    if overall_severity == RiskSeverity.CRITICAL:
        base += 10
    elif overall_severity == RiskSeverity.HIGH:
        base += 5
    elif overall_severity == RiskSeverity.MEDIUM:
        base += 3

    return min(base, 30)


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


def _classify_leakcheck_source(source: dict[str, Any]) -> RiskSeverity:
    """Classify LeakCheck source severity."""

    password_type = str(source.get("passwordtype") or "").lower()
    fields = [str(item).lower() for item in source.get("fields", [])]

    if password_type in LEAKCHECK_PASSWORD_TYPES_CRITICAL or "password" in fields:
        return RiskSeverity.CRITICAL

    for item in fields:
        mapped = LEAKCHECK_SEVERITY_FIELDS.get(item)
        if mapped == "HIGH":
            return RiskSeverity.HIGH
    for item in fields:
        mapped = LEAKCHECK_SEVERITY_FIELDS.get(item)
        if mapped == "MEDIUM":
            return RiskSeverity.MEDIUM

    return RiskSeverity.LOW


async def _fetch_leakcheck_json(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
    headers: dict[str, str] | None = None,
    retries_on_429: int = 1,
    retry_wait_seconds: int = 10,
) -> tuple[int, dict[str, Any] | None]:
    """Fetch LeakCheck JSON payload with optional 429 retry handling."""

    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    attempts = retries_on_429 + 1
    for index in range(attempts):
        async with semaphore:
            await limiter.acquire()
            try:
                async with session.get(url, headers=request_headers) as response:
                    if response.status == 429 and index < retries_on_429:
                        await asyncio.sleep(retry_wait_seconds)
                        continue
                    if response.status >= 400:
                        try:
                            payload = await response.json()
                            return response.status, payload if isinstance(payload, dict) else None
                        except Exception:
                            return response.status, None
                    payload = await response.json()
                    return response.status, payload if isinstance(payload, dict) else {}
            except (aiohttp.ClientError, TimeoutError):
                if index == attempts - 1:
                    return 0, None

    return 429, None


async def _run_leakcheck(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
) -> CredentialLeakResult:
    """Run LeakCheck in authenticated or public mode."""

    if not email:
        return CredentialLeakResult(
            email=None,
            engine="leakcheck",
            mode=None,
            leakcheck_mode="public",
            leakcheck_sources=[],
            leakcheck_found=0,
            demo_mode=False,
            hibp_source=None,
            total_breaches=0,
            total_pastes=0,
            breaches=[],
            pastes=[],
            overall_severity=RiskSeverity.LOW,
            note="No email provided — credential scan limited to domain pastes.",
            score_impact=0,
        )

    api_key = config.api_keys.leakcheck.strip()
    auth_limiter = AsyncRateLimiter(config.rate_limits.leakcheck_auth_delay)
    public_limiter = AsyncRateLimiter(config.rate_limits.leakcheck_public_delay)

    leakcheck_mode = "public"
    payload: dict[str, Any] | None = None
    auth_fallback_reason: str | None = None

    if api_key:
        status, auth_payload = await _fetch_leakcheck_json(
            session,
            semaphore,
            auth_limiter,
            LEAKCHECK_AUTH_URL.format(email=email),
            headers={"X-API-Key": api_key},
            retries_on_429=1,
            retry_wait_seconds=10,
        )

        if status in {401, 403}:
            error_text = str((auth_payload or {}).get("error") or "").strip()
            auth_fallback_reason = f"auth_rejected_{status}"
            if status == 403 or "active plan required" in error_text.lower():
                LOGGER.warning(
                    "LeakCheck Pro API access denied (status %s). Free accounts use public mode; Pro plan is required for authenticated endpoint.",
                    status,
                )
            elif "invalid x-api-key" in error_text.lower():
                LOGGER.warning(
                    "LeakCheck authenticated endpoint rejected API key (status %s: %s); falling back to public mode.",
                    status,
                    error_text,
                )
            else:
                LOGGER.warning(
                    "LeakCheck authenticated endpoint rejected API access (status %s%s); falling back to public mode.",
                    status,
                    f": {error_text}" if error_text else "",
                )
        elif status == 429 and auth_payload is None:
            auth_fallback_reason = "auth_rate_limited"
            LOGGER.warning("LeakCheck authenticated endpoint rate-limited after retry; skipping auth mode.")
        elif status >= 400 and status != 0:
            auth_fallback_reason = f"auth_http_{status}"
            LOGGER.warning("LeakCheck authenticated request failed (%s).", status)
        elif auth_payload is not None:
            payload = auth_payload
            leakcheck_mode = "authenticated"

    if payload is None:
        status, public_payload = await _fetch_leakcheck_json(
            session,
            semaphore,
            public_limiter,
            LEAKCHECK_PUBLIC_URL.format(email=email),
            retries_on_429=1,
            retry_wait_seconds=10,
        )
        if status == 429 and public_payload is None:
            LOGGER.warning("LeakCheck public endpoint rate-limited after retry.")
            public_payload = {"success": True, "found": 0, "sources": []}
        elif status >= 400 and status != 0:
            LOGGER.warning("LeakCheck public request failed (%s).", status)
            public_payload = {"success": True, "found": 0, "sources": []}
        payload = public_payload or {"success": True, "found": 0, "sources": []}
        leakcheck_mode = "public"

    raw_sources = payload.get("sources", []) if isinstance(payload, dict) else []
    auth_results = payload.get("result", []) if isinstance(payload, dict) else []
    normalized_sources: list[dict[str, Any]] = []

    if leakcheck_mode == "public":
        for source_name in raw_sources if isinstance(raw_sources, list) else []:
            if isinstance(source_name, dict):
                source_value = str(source_name.get("name", "Unknown"))
                source_date = source_name.get("date")
            else:
                source_value = str(source_name)
                source_date = None
            source_obj = {
                "name": source_value,
                "date": source_date,
                "unverified": False,
                "passwordtype": "unknown",
                "fields": [],
            }
            severity = _classify_leakcheck_source(source_obj)
            source_obj["severity"] = severity.value
            normalized_sources.append(source_obj)
    else:
        if isinstance(raw_sources, list) and raw_sources:
            for source in raw_sources:
                source_obj = {
                    "name": str(source.get("name", "Unknown")),
                    "date": source.get("date"),
                    "unverified": bool(source.get("unverified", False)),
                    "passwordtype": str(source.get("passwordtype") or "unknown"),
                    "fields": [str(item) for item in source.get("fields", [])],
                }
                severity = _classify_leakcheck_source(source_obj)
                source_obj["severity"] = severity.value
                normalized_sources.append(source_obj)
        elif isinstance(auth_results, list):
            for row in auth_results:
                source_meta = row.get("source", {}) if isinstance(row, dict) else {}
                row_fields = [str(item) for item in row.get("fields", [])] if isinstance(row, dict) else []
                source_obj = {
                    "name": str(source_meta.get("name", "Unknown")),
                    "date": source_meta.get("breach_date") or source_meta.get("date"),
                    "unverified": bool(source_meta.get("unverified", False)),
                    "passwordtype": "unknown",
                    "fields": row_fields,
                }
                severity = _classify_leakcheck_source(source_obj)
                source_obj["severity"] = severity.value
                normalized_sources.append(source_obj)

    severities = [item.get("severity", "LOW") for item in normalized_sources]
    if "CRITICAL" in severities:
        overall = RiskSeverity.CRITICAL
    elif "HIGH" in severities:
        overall = RiskSeverity.HIGH
    elif "MEDIUM" in severities:
        overall = RiskSeverity.MEDIUM
    else:
        overall = RiskSeverity.LOW

    found = int(payload.get("found", 0)) if isinstance(payload, dict) else len(normalized_sources)
    note = None
    if leakcheck_mode == "public":
        if api_key and auth_fallback_reason:
            note = (
                "LeakCheck Public Mode — Authenticated Pro API access was rejected for this key/account, "
                "so results are from the public endpoint with limited detail."
            )
        else:
            note = (
                "LeakCheck Public Mode — Add a LeakCheck API key to config.yaml for full breach "
                "detail including field types and dates."
            )

    return CredentialLeakResult(
        email=email,
        engine="leakcheck",
        mode=None,
        leakcheck_mode=leakcheck_mode,
        leakcheck_sources=normalized_sources,
        leakcheck_found=found,
        demo_mode=False,
        hibp_source=None,
        total_breaches=0,
        total_pastes=0,
        breaches=[],
        pastes=[],
        overall_severity=overall,
        note=note,
        score_impact=_calculate_score_impact(found, overall, free_mode=False) if found > 0 else 0,
    )


async def _run_hibp(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
    mode: HIBPMode,
) -> CredentialLeakResult:
    """Run HIBP branch (Free, Demo, Live)."""

    if mode == HIBPMode.FREE or not email:
        limiter = AsyncRateLimiter(config.rate_limits.hibp_delay)
        breach_payload = await _fetch_hibp_json(session, semaphore, limiter, HIBP_BREACHES_URL)
        breaches = _build_breach_entries(breach_payload)
        total_pwned_accounts = sum(item.pwn_count for item in breaches)

        return CredentialLeakResult(
            email=email,
            engine="hibp",
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
            engine="hibp",
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
            score_impact=_calculate_score_impact(len(breaches), overall),
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
        engine="hibp",
        mode=HIBPMode.LIVE,
        demo_mode=False,
        hibp_source="api",
        total_breaches=len(breaches),
        total_pastes=len(pastes),
        total_pwned_accounts=sum(item.pwn_count for item in breaches),
        breaches=breaches,
        pastes=pastes,
        overall_severity=overall,
        score_impact=_calculate_score_impact(len(breaches), overall),
    )


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
    mode: HIBPMode,
    engine: str = "leakcheck",
) -> CredentialLeakResult:
    """Run credential leak scan using selected engine."""

    if engine == "hibp":
        return await _run_hibp(session, semaphore, config, email, mode)
    return await _run_leakcheck(session, semaphore, config, email)
