"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class GeneralConfig(BaseModel):
    """General runtime configuration."""

    output_dir: str = "./output"
    log_level: str = "INFO"
    request_timeout: int = 15
    max_concurrent_requests: int = 3
    output_formats: list[str] = Field(default_factory=lambda: ["html", "json", "md"])


class APIKeysConfig(BaseModel):
    """API key configuration."""

    hibp: str = ""
    leakcheck: str = ""
    github: str = ""
    shodan: str = ""


class ModulesConfig(BaseModel):
    """Module enablement switches."""

    credential_leak: bool = True
    github_footprint: bool = True
    email_intel: bool = True
    social_footprint: bool = True
    paste_monitor: bool = True
    metadata_extractor: bool = True
    google_dorks: bool = True
    js_secret_scanner: bool = True
    dns_email_auth: bool = True
    shodan_recon: bool = True
    exposure_graph: bool = True


class RateLimitsConfig(BaseModel):
    """Per-source rate limiting values."""

    hibp_delay: float = 1.5
    leakcheck_auth_delay: float = 1.0
    leakcheck_public_delay: float = 2.0
    github_delay: float = 1.0
    shodan_delay: float = 1.0
    social_check_delay: float = 0.5
    ddg_delay: float = 5.0
    dns_concurrent: int = 5


class ScanLimitsConfig(BaseModel):
    """Per-module scan bounds."""

    max_github_repos: int = 10
    max_github_files: int = 5
    max_workflow_files: int = 3
    max_js_files: int = 10
    max_docs_to_fetch: int = 5
    max_social_platforms: int = 15
    max_dork_live_checks: int = 3
    max_shodan_ips: int = 5


class AppConfig(BaseModel):
    """Root configuration model."""

    model_config = ConfigDict(extra="ignore")

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    api_keys: APIKeysConfig = Field(default_factory=APIKeysConfig)
    modules: ModulesConfig = Field(default_factory=ModulesConfig)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    scan_limits: ScanLimitsConfig = Field(default_factory=ScanLimitsConfig)


def _normalize_output_formats(raw: Any) -> list[str]:
    """Normalize output format values to a lowercase list."""

    if raw is None:
        return ["html", "json", "md"]

    if isinstance(raw, str):
        values = [item.strip().lower() for item in raw.split(",") if item.strip()]
        return values or ["html", "json", "md"]

    if isinstance(raw, list):
        values = [str(item).strip().lower() for item in raw if str(item).strip()]
        return values or ["html", "json", "md"]

    return ["html", "json", "md"]


def _prepare_raw_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Apply pre-validation normalization to raw YAML mapping."""

    general = raw.get("general", {})
    general["output_formats"] = _normalize_output_formats(general.get("output_formats"))
    raw["general"] = general
    return raw


def load_config(config_path: str | Path = "config.yaml") -> AppConfig:
    """Load and validate application configuration from YAML.

    Args:
        config_path: Path to configuration file.

    Returns:
        Validated AppConfig object.
    """

    path = Path(config_path)
    if not path.exists():
        return AppConfig()

    with path.open("r", encoding="utf-8") as file:
        raw_config = yaml.safe_load(file) or {}

    if not isinstance(raw_config, dict):
        return AppConfig()

    normalized = _prepare_raw_config(raw_config)
    return AppConfig.model_validate(normalized)
