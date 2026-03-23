"""Tests for metadata extractor module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from modules.metadata_extractor import run


async def test_skip_without_domain(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, None)

    assert result.skipped is True
    assert result.score_impact == 0
