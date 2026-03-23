"""Paste monitor module as a wrapper over credential leak results."""

from __future__ import annotations

from core.models import CredentialLeakResult, HIBPMode, PasteResult


def run(credential_result: CredentialLeakResult) -> PasteResult:
    """Build paste exposure result from credential leak module output only."""

    is_premium_mode = credential_result.mode in {HIBPMode.LIVE, HIBPMode.DEMO}
    if not is_premium_mode:
        return PasteResult(
            mode="free",
            total_pastes=0,
            pastes=[],
            message="Paste lookup requires Premium HIBP mode.",
            score_impact=0,
        )

    total_pastes = len(credential_result.pastes)
    return PasteResult(
        mode="premium",
        total_pastes=total_pastes,
        pastes=credential_result.pastes,
        message=None,
        score_impact=15 if total_pastes > 0 else 0,
    )
