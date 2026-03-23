"""Exposure score aggregation and finding generation module."""

from __future__ import annotations

from collections import defaultdict

from core.constants import FINDING_PREFIXES, SEVERITY_LABELS
from core.models import (
    CredentialLeakResult,
    EmailAuthResult,
    EmailIntelResult,
    ExposureScoreResult,
    FindingItem,
    GitHubFootprintResult,
    GoogleDorksResult,
    JSSecretResult,
    MetadataResult,
    PasteResult,
    RiskSeverity,
    SocialFootprintResult,
)


def _label_for_score(score: int) -> str:
    """Resolve exposure label from score ranges."""

    for score_range, label in SEVERITY_LABELS.items():
        lower_text, upper_text = score_range.split("-", maxsplit=1)
        lower, upper = int(lower_text), int(upper_text)
        if lower <= score <= upper:
            return label
    return "CRITICAL EXPOSURE"


def _module_severity(score_impact: int) -> RiskSeverity:
    """Map module score impact to coarse severity."""

    if score_impact >= 20:
        return RiskSeverity.CRITICAL
    if score_impact >= 10:
        return RiskSeverity.HIGH
    if score_impact >= 5:
        return RiskSeverity.MEDIUM
    if score_impact > 0:
        return RiskSeverity.LOW
    return RiskSeverity.INFO


def _add_finding(
    findings: list[FindingItem],
    counters: dict[str, int],
    module_key: str,
    category: str,
    score_impact: int,
    title: str,
    description: str,
    recommendation: str,
    references: list[str],
) -> None:
    """Append one deterministic finding entry using module prefix counters."""

    prefix = FINDING_PREFIXES[module_key]
    counters[module_key] += 1
    finding_id = f"{prefix}-{counters[module_key]:03d}"

    findings.append(
        FindingItem(
            id=finding_id,
            module=module_key,
            category=category,
            risk=_module_severity(score_impact),
            title=title,
            description=description,
            recommendation=recommendation,
            score_impact=score_impact,
            references=references,
        )
    )


def run(
    credential_leak: CredentialLeakResult,
    github_footprint: GitHubFootprintResult,
    email_intel: EmailIntelResult,
    social_footprint: SocialFootprintResult,
    paste_monitor: PasteResult,
    js_secret_scanner: JSSecretResult,
    dns_email_auth: EmailAuthResult,
    metadata_extractor: MetadataResult,
    google_dorks: GoogleDorksResult,
) -> ExposureScoreResult:
    """Aggregate module score impacts and emit normalized findings."""

    module_scores = {
        "credential_leak": credential_leak.score_impact,
        "github_footprint": github_footprint.score_impact,
        "email_intel": email_intel.score_impact,
        "social_footprint": social_footprint.score_impact,
        "paste_monitor": paste_monitor.score_impact,
        "js_secret_scanner": js_secret_scanner.score_impact,
        "dns_email_auth": dns_email_auth.score_impact,
        "metadata_extractor": metadata_extractor.score_impact,
        "google_dorks": google_dorks.score_impact,
    }

    total_score = min(sum(module_scores.values()), 100)
    findings: list[FindingItem] = []
    counters: dict[str, int] = defaultdict(int)

    if credential_leak.total_breaches > 0:
        _add_finding(
            findings,
            counters,
            "credential_leak",
            "Credential Leak",
            credential_leak.score_impact,
            "Breaches associated with target",
            f"Found {credential_leak.total_breaches} breach records linked to the credential source.",
            "Reset passwords and enforce MFA for all affected accounts.",
            ["https://haveibeenpwned.com/"],
        )

    if github_footprint.secrets_found:
        _add_finding(
            findings,
            counters,
            "github_footprint",
            "GitHub Exposure",
            github_footprint.score_impact,
            "Potential secrets in public repositories",
            f"Detected {len(github_footprint.secrets_found)} secret-like patterns in scanned public repositories.",
            "Rotate exposed credentials and add secret scanning/commit hooks.",
            ["https://docs.github.com/en/code-security/secret-scanning"],
        )

    if email_intel.score_impact > 0:
        _add_finding(
            findings,
            counters,
            "email_intel",
            "Email Intelligence",
            email_intel.score_impact,
            "Mailbox exposure indicators",
            "Email validation and SMTP behavior indicate exposure-relevant mailbox posture.",
            "Use monitored inboxes, anti-abuse rules, and stricter onboarding controls.",
            [],
        )

    if social_footprint.total_exposure_count > 0:
        _add_finding(
            findings,
            counters,
            "social_footprint",
            "Social Footprint",
            social_footprint.score_impact,
            "Public profile exposure",
            f"Detected {social_footprint.total_exposure_count} exposed non-positive-signal social profiles.",
            "Review profile privacy and remove unnecessary public identifiers.",
            [],
        )

    if paste_monitor.total_pastes > 0:
        _add_finding(
            findings,
            counters,
            "paste_monitor",
            "Paste Exposure",
            paste_monitor.score_impact,
            "Credential references in public pastes",
            f"Found {paste_monitor.total_pastes} public paste references tied to the target.",
            "Perform credential rotation and monitor paste sites continuously.",
            [],
        )

    if js_secret_scanner.secrets_found:
        _add_finding(
            findings,
            counters,
            "js_secret_scanner",
            "JavaScript Secrets",
            js_secret_scanner.score_impact,
            "Sensitive patterns in client-side JavaScript",
            f"Detected {len(js_secret_scanner.secrets_found)} secret/hint patterns in public JS assets.",
            "Move sensitive logic server-side and remove secrets from static assets.",
            [],
        )

    if dns_email_auth.score_impact > 0:
        _add_finding(
            findings,
            counters,
            "dns_email_auth",
            "Email Authentication",
            dns_email_auth.score_impact,
            "Spoofability risk",
            f"Domain spoofability score is {dns_email_auth.spoofability_score}/10.",
            "Enforce SPF -all, DMARC reject/quarantine, and operational DKIM selectors.",
            [],
        )

    if metadata_extractor.findings:
        _add_finding(
            findings,
            counters,
            "metadata_extractor",
            "Document Metadata",
            metadata_extractor.score_impact,
            "Metadata disclosure in public documents",
            f"Detected metadata findings across {metadata_extractor.documents_scanned} scanned documents.",
            "Sanitize metadata before publishing internal documents.",
            [],
        )

    if google_dorks.score_impact > 0:
        _add_finding(
            findings,
            counters,
            "google_dorks",
            "Search Engine Exposure",
            google_dorks.score_impact,
            "Public search result exposure signals",
            "DuckDuckGo checks found potentially indexed exposure-relevant results.",
            "Review indexed content and harden access/robots directives where appropriate.",
            [],
        )

    return ExposureScoreResult(findings=findings, score=total_score, label=_label_for_score(total_score))
