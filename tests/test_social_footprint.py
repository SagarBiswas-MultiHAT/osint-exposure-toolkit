"""Tests for social footprint module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from modules.social_footprint import _username_variants, run


def test_username_variant_generation() -> None:
    variants = _username_variants("john.doe@example.com")
    assert variants == ["johndoe", "john.doe", "john_doe", "john-doe"]


async def test_skip_without_email(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, None)

    assert result.skipped is True
    assert result.score_impact == 0
