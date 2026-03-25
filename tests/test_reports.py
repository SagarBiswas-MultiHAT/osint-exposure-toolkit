"""Smoke tests for report generators and exposure graph."""

from __future__ import annotations

import json

from graph import exposure_graph
from reporting import html_report, json_report, markdown_report


async def test_html_report_smoke(mock_all_results) -> None:
    output_file = await html_report.generate(mock_all_results)

    assert output_file.exists()
    assert output_file.stat().st_size > 0

    content = output_file.read_text(encoding="utf-8")
    assert "DIGITAL EXPOSURE REPORT" in content
    for section_name in [
        "Executive Summary",
        "Credential Leaks",
        "GitHub Exposure",
        "Email Intelligence",
        "Social Footprint",
        "Paste Site Exposure",
        "JS File Secrets",
        "Email Authentication",
        "Document Metadata",
        "Google Dork Recipe",
        "Shodan Recon",
        "Risk Summary & Recommendations",
        "Appendix",
    ]:
        assert section_name in content
    assert "const breachRows =" in content


async def test_json_report_smoke(mock_all_results) -> None:
    output_file = await json_report.generate(mock_all_results)

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    payload = json.loads(content)

    assert "meta" in payload
    assert isinstance(payload["meta"].get("score"), int)


async def test_markdown_report_smoke(mock_all_results) -> None:
    output_file = await markdown_report.generate(mock_all_results)

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")

    assert content.startswith("# Digital Exposure Report")
    assert "## Executive Summary" in content
    assert "## Findings Summary" in content


async def test_exposure_graph_smoke(mock_all_results) -> None:
    output_file = await exposure_graph.generate(mock_all_results)

    assert output_file.exists()
    assert output_file.stat().st_size > 0

    content = output_file.read_text(encoding="utf-8").lower()
    assert "<html" in content
    assert "exposuredetailpanel" in content
    assert "copynodesummary" in content
    assert "copynodeurl" in content
    assert "network.on(\"click\"" in content
