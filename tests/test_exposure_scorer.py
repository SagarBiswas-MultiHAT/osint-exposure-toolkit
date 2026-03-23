"""Tests for exposure scorer module."""

from __future__ import annotations

from core.models import (
    CredentialLeakResult,
    EmailAuthResult,
    EmailIntelResult,
    GitHubFootprintResult,
    GoogleDorksResult,
    JSSecretResult,
    MetadataResult,
    PasteResult,
    ShodanReconResult,
    SocialFootprintResult,
)
from modules.exposure_scorer import run


def test_zero_findings_score_zero() -> None:
    result = run(
        credential_leak=CredentialLeakResult(mode="free"),
        github_footprint=GitHubFootprintResult(),
        email_intel=EmailIntelResult(),
        social_footprint=SocialFootprintResult(),
        paste_monitor=PasteResult(mode="free"),
        js_secret_scanner=JSSecretResult(),
        dns_email_auth=EmailAuthResult(),
        metadata_extractor=MetadataResult(),
        google_dorks=GoogleDorksResult(),
        shodan_recon=ShodanReconResult(),
    )

    assert result.score == 0
    assert result.label == "MINIMAL EXPOSURE"
