"""Tests for config loading and normalization."""

from __future__ import annotations

from pathlib import Path

from core.config_loader import load_config


def test_load_defaults_when_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"
    config = load_config(missing_path)
    assert config.api_keys.hibp == ""
    assert config.api_keys.github == ""


def test_output_formats_normalization(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
        general:
          output_formats: "html,json"
        """,
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.general.output_formats == ["html", "json"]


def test_unknown_field_ignored(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        """
        unknown_field: true
        api_keys:
          hibp: ""
        """,
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.api_keys.hibp == ""
