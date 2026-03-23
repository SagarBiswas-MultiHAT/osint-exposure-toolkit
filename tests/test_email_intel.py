"""Tests for email intelligence module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from core.models import SMTPStatus
from modules import email_intel
from modules.email_intel import run


async def test_invalid_email_returns_zero_score(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "not-an-email")

    assert result.format_valid is False
    assert result.score_impact == 0


async def test_disposable_domain_detection(monkeypatch, mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    async def mock_mx(_: str) -> list[str]:
        return ["mx.mailinator.com"]

    async def mock_spf(_: str) -> bool:
        return False

    monkeypatch.setattr(email_intel, "_get_mx_records", mock_mx)
    monkeypatch.setattr(email_intel, "_has_spf_record", mock_spf)
    monkeypatch.setattr(email_intel, "_smtp_check_sync", lambda *_: SMTPStatus.UNKNOWN)

    result = await run(session, semaphore, mock_config, "test@mailinator.com")

    assert result.is_disposable is True
    assert result.score_impact == 5
