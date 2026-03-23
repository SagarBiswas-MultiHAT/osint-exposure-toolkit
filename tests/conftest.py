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
    ShodanReconResult,
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
def leakcheck_auth_fixture() -> dict:
    """Mock authenticated LeakCheck payload."""

    return {
        "success": True,
        "found": 2,
        "sources": [
            {
                "name": "AuthBreachCritical",
                "date": "2020-01",
                "unverified": False,
                "passwordtype": "plaintext",
                "fields": ["email", "password"],
            },
            {
                "name": "AuthBreachMedium",
                "date": "2021-06",
                "unverified": False,
                "passwordtype": "unknown",
                "fields": ["email", "phone"],
            },
        ],
    }


@pytest.fixture
def leakcheck_public_fixture() -> dict:
    """Mock public LeakCheck payload."""

    return {
        "success": True,
        "found": 1,
        "sources": ["PublicLeakBreach"],
    }


@pytest.fixture
def shodan_host_fixture() -> dict:
    """Mock Shodan host payload with mixed-risk services and one CVE."""

    return {
        "ip_str": "1.2.3.4",
        "hostnames": ["edge.example.com"],
        "org": "Example Org",
        "country_name": "United States",
        "isp": "Example ISP",
        "last_update": "2026-01-01T00:00:00.000000",
        "tags": ["cloud"],
        "vulns": {"CVE-2021-44228": {}},
        "data": [
            {
                "port": 80,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.24.0",
                "data": "HTTP banner",
                "http": {"title": "Welcome"},
                "cpe": ["cpe:/a:nginx:nginx:1.24.0"],
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.24.0",
                "data": "HTTPS banner",
                "http": {"title": "Secure"},
                "ssl": {"cert": {"subject": {"CN": "example.com"}, "issuer": {"CN": "Example CA"}}},
                "cpe": [],
            },
            {
                "port": 3306,
                "transport": "tcp",
                "product": "MySQL",
                "version": "8.0",
                "data": "MySQL banner",
                "cpe": ["cpe:/a:mysql:mysql:8.0"],
            },
        ],
    }


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
        shodan=ShodanReconResult(target_domain="example.com"),
        exposure_score=ExposureScoreResult(),
    )
