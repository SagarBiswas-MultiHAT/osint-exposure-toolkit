"""Shared pytest fixtures for the OSINT toolkit test suite."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.config_loader import (
    APIKeysConfig,
    AppConfig,
    GeneralConfig,
    ModulesConfig,
    RateLimitsConfig,
    ScanLimitsConfig,
)
from core.constants import TOOL_NAME, TOOL_VERSION
from core.models import (
    CredentialLeakResult,
    EmailAuthResult,
    EmailIntelResult,
    ExposureScoreResult,
    GitHubFootprintResult,
    GoogleDorksResult,
    JSSecretResult,
    MetadataResult,
    PasteResult,
    ReportContext,
    SocialFootprintResult,
)


@pytest.fixture
def mock_config() -> AppConfig:
    """Minimal valid AppConfig for all tests with empty API keys."""

    return AppConfig(
        general=GeneralConfig(
            output_dir="./output",
            log_level="INFO",
            request_timeout=15,
            max_concurrent_requests=3,
            output_formats=["html", "json", "md"],
        ),
        api_keys=APIKeysConfig(hibp="", github=""),
        modules=ModulesConfig(),
        rate_limits=RateLimitsConfig(),
        scan_limits=ScanLimitsConfig(),
    )


@pytest.fixture
def hibp_fixture_data() -> dict:
    """Load the shared HIBP mock fixture payload."""

    fixture_file = Path("tests/fixtures/hibp_mock.json")
    return json.loads(fixture_file.read_text(encoding="utf-8"))


@pytest.fixture
def mock_aiohttp_session() -> MagicMock:
    """Return a mock aiohttp session object with async methods."""

    session = MagicMock()
    session.get = AsyncMock()
    session.head = AsyncMock()
    return session


@pytest.fixture
def mock_all_results(tmp_path: Path) -> ReportContext:
    """Provide a complete report context object for report smoke tests."""

    return ReportContext(
        target_email="demo@example.com",
        target_domain="example.com",
        generated_at=datetime.now(UTC),
        tool_name=TOOL_NAME,
        tool_version=TOOL_VERSION,
        output_dir=tmp_path,
        credential_leak=CredentialLeakResult(email="demo@example.com", mode="demo", demo_mode=True),
        github_footprint=GitHubFootprintResult(),
        email_intel=EmailIntelResult(email="demo@example.com", domain="example.com"),
        social_footprint=SocialFootprintResult(email="demo@example.com"),
        paste_monitor=PasteResult(mode="premium"),
        js_secret_scanner=JSSecretResult(domain="example.com"),
        dns_email_auth=EmailAuthResult(domain="example.com"),
        metadata_extractor=MetadataResult(domain="example.com"),
        google_dorks=GoogleDorksResult(),
        exposure_score=ExposureScoreResult(),
    )
