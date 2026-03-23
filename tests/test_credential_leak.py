"""Tests for credential leak module."""

from __future__ import annotations

import asyncio
from collections import deque
from unittest.mock import MagicMock

from core.models import HIBPMode, RiskSeverity
from modules import credential_leak
from modules.credential_leak import classify_breach_severity, run, select_engine_choice


async def test_demo_mode_uses_fixture(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(
        session=session,
        semaphore=semaphore,
        config=mock_config,
        email="demo@example.com",
        mode=HIBPMode.DEMO,
        engine="hibp",
    )

    assert result.mode == HIBPMode.DEMO
    assert result.total_breaches == 4
    assert result.overall_severity == RiskSeverity.CRITICAL


async def test_live_mode_without_key_falls_back_to_demo(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(
        session=session,
        semaphore=semaphore,
        config=mock_config,
        email="demo@example.com",
        mode=HIBPMode.LIVE,
        engine="hibp",
    )

    assert result.mode == HIBPMode.DEMO
    assert result.demo_mode is True


def test_passwords_and_email_is_critical() -> None:
    severity = classify_breach_severity(["Email addresses", "Passwords"])
    assert severity == RiskSeverity.CRITICAL


async def test_leakcheck_authenticated_breach_found(mock_config, leakcheck_auth_fixture, monkeypatch) -> None:
    mock_config.api_keys.leakcheck = "lk_valid"

    async def fake_fetch(*args, **kwargs):
        return 200, leakcheck_auth_fixture

    monkeypatch.setattr(credential_leak, "_fetch_leakcheck_json", fake_fetch)
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "demo@example.com", HIBPMode.FREE, engine="leakcheck")

    assert result.engine == "leakcheck"
    assert result.leakcheck_mode == "authenticated"
    assert result.leakcheck_found == 2
    assert result.overall_severity == RiskSeverity.CRITICAL
    assert result.score_impact > 0


async def test_leakcheck_public_breach_found(mock_config, leakcheck_public_fixture, monkeypatch) -> None:
    mock_config.api_keys.leakcheck = ""

    async def fake_fetch(*args, **kwargs):
        return 200, leakcheck_public_fixture

    monkeypatch.setattr(credential_leak, "_fetch_leakcheck_json", fake_fetch)
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "demo@example.com", HIBPMode.FREE, engine="leakcheck")

    assert result.leakcheck_mode == "public"
    assert result.leakcheck_found == 1
    assert all(source["fields"] == [] for source in result.leakcheck_sources)


async def test_leakcheck_not_found(mock_config, monkeypatch) -> None:
    async def fake_fetch(*args, **kwargs):
        return 200, {"success": True, "found": 0, "sources": []}

    monkeypatch.setattr(credential_leak, "_fetch_leakcheck_json", fake_fetch)
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "demo@example.com", HIBPMode.FREE, engine="leakcheck")

    assert result.leakcheck_found == 0
    assert result.score_impact == 0
    assert result.overall_severity == RiskSeverity.LOW


async def test_leakcheck_429_retry_then_skip(mock_config, monkeypatch) -> None:
    async def fake_fetch(*args, **kwargs):
        return 429, None

    monkeypatch.setattr(credential_leak, "_fetch_leakcheck_json", fake_fetch)
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "demo@example.com", HIBPMode.FREE, engine="leakcheck")

    assert result.leakcheck_found == 0
    assert result.score_impact == 0


async def test_leakcheck_fallback_to_public_on_401(mock_config, leakcheck_public_fixture, monkeypatch) -> None:
    mock_config.api_keys.leakcheck = "lk_invalid"
    queue = deque([(401, None), (200, leakcheck_public_fixture)])

    async def fake_fetch(*args, **kwargs):
        return queue.popleft()

    monkeypatch.setattr(credential_leak, "_fetch_leakcheck_json", fake_fetch)
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "demo@example.com", HIBPMode.FREE, engine="leakcheck")

    assert result.leakcheck_mode == "public"
    assert result.leakcheck_found == 1


def test_engine_default_is_leakcheck() -> None:
    assert select_engine_choice("") == "leakcheck"
    assert select_engine_choice("1") == "leakcheck"
