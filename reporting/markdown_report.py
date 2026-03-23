"""Markdown report generator."""

from __future__ import annotations

from pathlib import Path

import aiofiles

from core.models import ReportContext


def _fmt_num(value: int) -> str:
    """Format integer with comma separators."""

    return f"{value:,}"


def _kv_row(key: str, value: str) -> str:
    """Render markdown key-value row."""

    return f"- **{key}:** {value}"


async def generate(context: ReportContext) -> Path:
    """Generate Markdown report from shared context payload."""

    output_dir = Path(context.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "report.md"

    mode_label = "Demo" if context.credential_leak.demo_mode else str(context.credential_leak.mode).title()

    lines: list[str] = [
        "# Digital Exposure Report",
        "",
        f"**Target:** {context.target_email or 'N/A'} / {context.target_domain or 'N/A'}",
        f"**Date:** {context.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Tool:** {context.tool_name} v{context.tool_version}",
        f"**Mode:** {mode_label}",
        "",
        "## Executive Summary",
        "",
        f"- **Exposure Score:** {context.exposure_score.score} / 100 — {context.exposure_score.label}",
        f"- **Credential Breaches:** {_fmt_num(context.credential_leak.total_breaches)}",
        f"- **GitHub Secrets:** {_fmt_num(len(context.github_footprint.secrets_found))}",
        f"- **Social Profiles Exposed:** {_fmt_num(context.social_footprint.total_exposure_count)}",
        f"- **Email Spoofability:** {context.dns_email_auth.spoofability_score} / 10",
        "",
        "## Credential Leaks",
        "",
        "| Breach Name | Date | Records | Data Classes | Severity |",
        "|---|---|---:|---|---|",
    ]

    for breach in context.credential_leak.breaches:
        data_classes = ", ".join(breach.data_classes)
        lines.append(
            f"| {breach.name} | {breach.breach_date} | {_fmt_num(breach.pwn_count)} | {data_classes} | {breach.severity} |"
        )

    if not context.credential_leak.breaches:
        lines.append("| — | — | — | — | — |")

    lines.extend(
        [
            "",
            "## GitHub Exposure",
            "",
            _kv_row("Repositories Scanned", str(len(context.github_footprint.repositories))),
            _kv_row("Secret Findings", str(len(context.github_footprint.secrets_found))),
            "",
            "## Email Intelligence",
            "",
            _kv_row("Provider", context.email_intel.mail_provider or "Unknown"),
            _kv_row("Disposable", str(context.email_intel.is_disposable)),
            _kv_row("SMTP", str(context.email_intel.smtp_verified)),
            _kv_row("SPF", str(context.email_intel.spf_present)),
            "",
            "## Social Footprint",
            "",
            "| Platform | Status | Positive Signal |",
            "|---|---|---|",
        ]
    )

    for profile in context.social_footprint.profiles:
        lines.append(
            f"| {profile.platform} | {profile.status} | {'Yes' if profile.is_positive_signal else 'No'} |"
        )

    if not context.social_footprint.profiles:
        lines.append("| — | — | — |")

    lines.extend(
        [
            "",
            "## Paste Site Exposure",
            "",
            _kv_row("Mode", context.paste_monitor.mode),
            _kv_row("Total Pastes", str(context.paste_monitor.total_pastes)),
            "",
            "## JS File Secrets",
            "",
            _kv_row("JS Files Scanned", str(context.js_secret_scanner.js_files_scanned)),
            _kv_row("Findings", str(len(context.js_secret_scanner.secrets_found))),
            "",
            "## Email Authentication",
            "",
            _kv_row("SPF Present", str(context.dns_email_auth.spf.present)),
            _kv_row("DMARC Present", str(context.dns_email_auth.dmarc.present)),
            _kv_row("DKIM Selectors", str(len(context.dns_email_auth.dkim.selectors_found))),
            _kv_row("MTA-STS", str(context.dns_email_auth.mta_sts.present)),
            _kv_row("Spoofability", f"{context.dns_email_auth.spoofability_score} / 10"),
            "",
            "## Document Metadata",
            "",
            _kv_row("Documents Found", str(context.metadata_extractor.documents_found)),
            _kv_row("Findings", str(len(context.metadata_extractor.findings))),
            "",
            "## Google Dork Queries",
            "",
        ]
    )

    for dork in context.google_dorks.results:
        lines.append(f"### {dork.category}")
        lines.append("")
        lines.append("```text")
        lines.extend(dork.queries)
        lines.append("```")
        lines.append("")

    lines.extend(
        [
            "## Findings Summary",
            "",
            "| ID | Category | Risk | Score Impact | Recommendation |",
            "|---|---|---|---:|---|",
        ]
    )

    for finding in context.exposure_score.findings:
        lines.append(
            f"| {finding.id} | {finding.category} | {finding.risk} | {finding.score_impact} | {finding.recommendation} |"
        )

    if not context.exposure_score.findings:
        lines.append("| — | — | — | 0 | — |")

    lines.extend(
        [
            "",
            "## Recommendations",
            "",
            "1. Rotate exposed credentials and enforce MFA.",
            "2. Harden SPF, DMARC, DKIM, and monitor spoofing.",
            "3. Remove secret material from public repositories and JS assets.",
            "4. Sanitize metadata from downloadable documents.",
            "5. Review public profile visibility and search indexing footprints.",
            "",
            "---",
            f"*Generated by {context.tool_name} v{context.tool_version} — Passive OSINT assessment.*",
        ]
    )

    async with aiofiles.open(output_file, "w", encoding="utf-8") as file:
        await file.write("\n".join(lines) + "\n")

    return output_file
