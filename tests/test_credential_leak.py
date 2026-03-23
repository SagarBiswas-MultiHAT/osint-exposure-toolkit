"""Tests for credential leak module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from core.models import HIBPMode, RiskSeverity
from modules.credential_leak import classify_breach_severity, run


async def test_demo_mode_uses_fixture(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(
        session=session,
        semaphore=semaphore,
        config=mock_config,
        email="demo@example.com",
        mode=HIBPMode.DEMO,
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
    )

    assert result.mode == HIBPMode.DEMO
    assert result.demo_mode is True


def test_passwords_and_email_is_critical() -> None:
    severity = classify_breach_severity(["Email addresses", "Passwords"])
    assert severity == RiskSeverity.CRITICAL
