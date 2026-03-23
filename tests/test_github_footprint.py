"""Tests for GitHub footprint module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from modules.github_footprint import run


async def test_skip_when_missing_github_key(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, domain="example.com")

    assert result.skipped is True
    assert result.score_impact == 0
