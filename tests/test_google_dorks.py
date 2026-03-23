"""Tests for Google dorks module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from modules.google_dorks import run


async def test_generate_categories_with_domain(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, domain="example.com", email=None, enable_live_check=False)

    assert result.skipped is False
    assert len(result.results) >= 1
    assert result.score_impact == 0
