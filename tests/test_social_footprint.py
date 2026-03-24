"""Tests for social footprint module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from core.models import PlatformStatus
from modules.social_footprint import _status_from_http, _username_variants, run


def test_username_variant_generation() -> None:
    variants = _username_variants("john.doe@example.com")
    assert variants[:4] == ["john.doe", "johndoe", "john-doe", "john_doe"]
    assert "john-doe" in variants
    assert len(variants) <= 10


def test_username_hint_prioritized_in_variants() -> None:
    variants = _username_variants("john.doe@example.com", "John-Doe")
    assert variants[0] == "john-doe"
    assert "john_doe" in variants
    assert "johndoe" in variants


def test_hybrid_status_mapping() -> None:
    assert _status_from_http(200, "https://example.com") == PlatformStatus.EXPOSED
    assert _status_from_http(404, "https://example.com") == PlatformStatus.NOT_FOUND
    assert _status_from_http(401, "https://example.com") == PlatformStatus.UNKNOWN
    assert _status_from_http(403, "https://example.com") == PlatformStatus.UNKNOWN
    assert _status_from_http(429, "https://example.com") == PlatformStatus.UNKNOWN
    assert _status_from_http(503, "https://example.com") == PlatformStatus.UNKNOWN
    assert _status_from_http(999, "https://example.com") == PlatformStatus.UNKNOWN


def test_content_aware_not_found_mapping() -> None:
    assert (
        _status_from_http(
            200,
            "https://gitlab.com/nonexistent-user",
            platform_name="GitLab",
            response_text="404 Page Not Found",
        )
        == PlatformStatus.NOT_FOUND
    )
    assert (
        _status_from_http(
            200,
            "https://www.npmjs.com/~nonexistent-user",
            platform_name="NPM",
            response_text="This user does not exist",
        )
        == PlatformStatus.NOT_FOUND
    )
    assert (
        _status_from_http(
            200,
            "https://x.com/nonexistent-user",
            platform_name="Twitter/X",
            response_text="This account doesn't exist",
        )
        == PlatformStatus.NOT_FOUND
    )
    assert (
        _status_from_http(
            200,
            "https://medium.com/@nonexistent-user",
            platform_name="Medium",
            response_text="Sorry, we couldn't find that page",
        )
        == PlatformStatus.NOT_FOUND
    )


def test_challenge_page_mapping() -> None:
    assert (
        _status_from_http(
            200,
            "https://pypi.org/user/some-user/",
            platform_name="PyPI",
            response_text="Client Challenge ... Please enable JavaScript to proceed",
        )
        == PlatformStatus.UNKNOWN
    )


async def test_skip_without_email(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, None, None)

    assert result.skipped is True
    assert result.score_impact == 0
