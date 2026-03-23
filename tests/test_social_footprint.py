"""Tests for social footprint module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from core.models import PlatformStatus
from modules.social_footprint import _status_from_http, _username_variants, run


def test_username_variant_generation() -> None:
    variants = _username_variants("john.doe@example.com")
    assert variants[:4] == ["johndoe", "john.doe", "john_doe", "john-doe"]
    assert "john-doe" in variants
    assert len(variants) <= 10


def test_hybrid_status_mapping() -> None:
    assert _status_from_http(200, "https://example.com") == PlatformStatus.EXPOSED
    assert _status_from_http(404, "https://example.com") == PlatformStatus.NOT_FOUND
    assert _status_from_http(401, "https://example.com") == PlatformStatus.EXPOSED
    assert _status_from_http(403, "https://example.com") == PlatformStatus.EXPOSED
    assert _status_from_http(429, "https://example.com") == PlatformStatus.EXPOSED
    assert _status_from_http(503, "https://example.com") == PlatformStatus.UNKNOWN
    assert _status_from_http(999, "https://example.com") == PlatformStatus.UNKNOWN


async def test_skip_without_email(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, None)

    assert result.skipped is True
    assert result.score_impact == 0
