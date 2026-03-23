"""Tests for shodan recon module."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from modules import shodan_recon
from modules.shodan_recon import run


async def test_shodan_skipped_no_domain(mock_config) -> None:
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, None)

    assert result.skipped is True
    assert result.score_impact == 0


async def test_shodan_skipped_no_api_key(mock_config) -> None:
    mock_config.api_keys.shodan = ""
    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "example.com")

    assert result.skipped is True
    assert result.score_impact == 0


async def test_shodan_critical_db_port_exposed(mock_config, shodan_host_fixture, monkeypatch) -> None:
    mock_config.api_keys.shodan = "shodankey"

    async def fake_resolve(*args, **kwargs):
        return ["1.2.3.4"]

    async def fake_fetch(*args, **kwargs):
        return 200, shodan_host_fixture

    monkeypatch.setattr(shodan_recon, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(shodan_recon, "_fetch_host", fake_fetch)

    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "example.com")

    assert result.critical_findings >= 1
    assert result.overall_severity == "CRITICAL"
    assert result.score_impact > 0


async def test_shodan_cve_found(mock_config, shodan_host_fixture, monkeypatch) -> None:
    mock_config.api_keys.shodan = "shodankey"

    async def fake_resolve(*args, **kwargs):
        return ["1.2.3.4"]

    async def fake_fetch(*args, **kwargs):
        return 200, shodan_host_fixture

    monkeypatch.setattr(shodan_recon, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(shodan_recon, "_fetch_host", fake_fetch)

    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "example.com")

    assert result.unique_cves == ["CVE-2021-44228"]
    assert result.total_cves == 1
    assert result.high_findings >= 1


async def test_shodan_host_not_found_404(mock_config, monkeypatch) -> None:
    mock_config.api_keys.shodan = "shodankey"

    async def fake_resolve(*args, **kwargs):
        return ["1.2.3.4"]

    async def fake_fetch(*args, **kwargs):
        return 404, None

    monkeypatch.setattr(shodan_recon, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(shodan_recon, "_fetch_host", fake_fetch)

    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "example.com")

    assert result.hosts == []
    assert result.score_impact == 0


async def test_shodan_invalid_key_401(mock_config, monkeypatch) -> None:
    mock_config.api_keys.shodan = "shodankey"

    async def fake_resolve(*args, **kwargs):
        return ["1.2.3.4"]

    async def fake_fetch(*args, **kwargs):
        return 401, None

    monkeypatch.setattr(shodan_recon, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(shodan_recon, "_fetch_host", fake_fetch)

    session = MagicMock()
    semaphore = asyncio.Semaphore(1)

    result = await run(session, semaphore, mock_config, "example.com")

    assert result.skipped is True


def test_shodan_banner_truncated() -> None:
    service = shodan_recon.ShodanService(port=80, transport="tcp", banner_excerpt="A" * 300)
    assert len(service.banner_excerpt or "") <= 200


def test_shodan_score_formula() -> None:
    score = shodan_recon._score(2, 1, 0, 0)
    assert score == 20
