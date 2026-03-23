"""Tests for DNS email auth module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from core.models import DKIMStatus, DMARCStatus, SPFStatus
from modules.dns_email_auth import _spoofability_score, run


def test_spoofability_max_when_all_missing() -> None:
    spf = SPFStatus(present=False)
    dmarc = DMARCStatus(present=False)
    dkim = DKIMStatus(selectors_found=[], weak_selectors=[])
    assert _spoofability_score(spf, dmarc, dkim) == 10


async def test_skip_without_domain(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, None)

    assert result.skipped is True
    assert result.score_impact == 0
