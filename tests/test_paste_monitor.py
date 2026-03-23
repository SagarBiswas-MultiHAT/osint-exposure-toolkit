"""Tests for paste monitor wrapper."""

from __future__ import annotations

from core.models import CredentialLeakResult, HIBPMode
from modules.paste_monitor import run


def test_free_mode_returns_zero() -> None:
    result = run(CredentialLeakResult(mode=HIBPMode.FREE))
    assert result.mode == "free"
    assert result.total_pastes == 0
    assert result.score_impact == 0
