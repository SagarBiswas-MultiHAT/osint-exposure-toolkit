"""Typed data models for all toolkit modules."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskSeverity(StrEnum):
    """Risk severity labels used across module findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class HIBPMode(StrEnum):
    """Credential leak scan modes."""

    LIVE = "live"
    DEMO = "demo"
    FREE = "free"


class PlatformStatus(StrEnum):
    """Social profile discovery status values."""

    EXPOSED = "EXPOSED"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"


class SMTPStatus(StrEnum):
    """SMTP verification outcomes."""

    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    UNKNOWN = "UNKNOWN"


class DDGResult(StrEnum):
    """DuckDuckGo query-check outcomes."""

    RESULTS_FOUND = "RESULTS_FOUND"
    NO_RESULTS = "NO_RESULTS"
    NOT_CHECKED = "NOT_CHECKED"


class BreachEntry(BaseModel):
    """Normalized HIBP breach entry."""

    model_config = ConfigDict(use_enum_values=True)

    name: str = Field(alias="Name")
    title: str = Field(alias="Title")
    domain: str = Field(alias="Domain")
    breach_date: str = Field(alias="BreachDate")
    added_date: str = Field(alias="AddedDate")
    modified_date: str = Field(alias="ModifiedDate")
    pwn_count: int = Field(alias="PwnCount")
    description: str = Field(alias="Description")
    logo_path: str = Field(alias="LogoPath")
    data_classes: list[str] = Field(alias="DataClasses")
    is_verified: bool = Field(alias="IsVerified")
    is_fabricated: bool = Field(alias="IsFabricated")
    is_sensitive: bool = Field(alias="IsSensitive")
    is_retired: bool = Field(alias="IsRetired")
    is_spam_list: bool = Field(alias="IsSpamList")
    is_malware: bool = Field(alias="IsMalware")
    severity: RiskSeverity = RiskSeverity.INFO


class PasteEntry(BaseModel):
    """HIBP paste entry."""

    source: str = Field(alias="Source")
    identifier: str = Field(alias="Id")
    title: str = Field(alias="Title")
    date: str = Field(alias="Date")
    email_count: int = Field(alias="EmailCount")


class CredentialLeakResult(BaseModel):
    """Module 1 output."""

    model_config = ConfigDict(use_enum_values=True)

    email: str | None = None
    engine: str = "hibp"
    mode: str | None = None
    leakcheck_mode: str | None = None
    leakcheck_sources: list[dict[str, object]] = Field(default_factory=list)
    leakcheck_found: int = 0
    skipped: bool = False
    demo_mode: bool = False
    hibp_source: str | None = None
    total_breaches: int = 0
    total_pastes: int = 0
    total_pwned_accounts: int = 0
    breaches: list[BreachEntry] = Field(default_factory=list)
    pastes: list[PasteEntry] = Field(default_factory=list)
    overall_severity: RiskSeverity = RiskSeverity.INFO
    note: str | None = None
    score_impact: int = 0


class GitHubRepoEntry(BaseModel):
    """Discovered public repository metadata."""

    name: str
    description: str | None = None
    language: str | None = None
    stars: int = 0
    forks: int = 0
    last_pushed: str | None = None
    active: bool = False
    has_pages: bool = False
    html_url: str | None = None
    commit_hash: str | None = None


class SecretFinding(BaseModel):
    """Secret-like value discovered in a public artifact."""

    model_config = ConfigDict(use_enum_values=True)

    repo: str
    file_path: str
    pattern_type: str
    masked_value: str
    severity: RiskSeverity


class GitHubFootprintResult(BaseModel):
    """Module 2 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    query: str | None = None
    discovered_entities: list[str] = Field(default_factory=list)
    repositories: list[GitHubRepoEntry] = Field(default_factory=list)
    secrets_found: list[SecretFinding] = Field(default_factory=list)
    overall_severity: RiskSeverity = RiskSeverity.INFO
    score_impact: int = 0


class EmailIntelResult(BaseModel):
    """Module 3 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    email: str | None = None
    domain: str | None = None
    format_valid: bool = False
    mx_records: list[str] = Field(default_factory=list)
    mail_provider: str | None = None
    is_disposable: bool = False
    spf_present: bool = False
    smtp_verified: SMTPStatus = SMTPStatus.UNKNOWN
    score_impact: int = 0


class SocialProfileEntry(BaseModel):
    """Social profile probe outcome."""

    model_config = ConfigDict(use_enum_values=True)

    platform: str
    url: str
    status: PlatformStatus
    status_reason: str | None = None
    username_tried: str | None = None
    is_positive_signal: bool = False


class SocialFootprintResult(BaseModel):
    """Module 4 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    email: str | None = None
    username_variants: list[str] = Field(default_factory=list)
    profiles: list[SocialProfileEntry] = Field(default_factory=list)
    total_exposure_count: int = 0
    positive_signal_count: int = 0
    score_impact: int = 0


class PasteResult(BaseModel):
    """Module 5 output."""

    mode: str
    total_pastes: int = 0
    pastes: list[PasteEntry] = Field(default_factory=list)
    message: str | None = None
    score_impact: int = 0


class JSSecretFinding(BaseModel):
    """JavaScript secret scanner finding."""

    model_config = ConfigDict(use_enum_values=True)

    js_file_url: str
    pattern_type: str
    masked_value: str
    severity: RiskSeverity


class JSSecretResult(BaseModel):
    """Module 6 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    domain: str | None = None
    js_files_scanned: int = 0
    secrets_found: list[JSSecretFinding] = Field(default_factory=list)
    internal_endpoints_found: list[str] = Field(default_factory=list)
    environment_hints: list[str] = Field(default_factory=list)
    score_impact: int = 0


class SPFStatus(BaseModel):
    """SPF analysis details."""

    present: bool = False
    record: str | None = None
    strength: str = "MISSING"
    over_lookup_limit: bool = False


class DMARCStatus(BaseModel):
    """DMARC analysis details."""

    present: bool = False
    record: str | None = None
    policy: str | None = None
    rua: str | None = None
    ruf: str | None = None
    aspf: str | None = None
    adkim: str | None = None


class DKIMStatus(BaseModel):
    """DKIM selector probing details."""

    selectors_found: list[str] = Field(default_factory=list)
    weak_selectors: list[str] = Field(default_factory=list)


class MTASTSStatus(BaseModel):
    """MTA-STS status information."""

    present: bool = False
    mode: str | None = None


class EmailAuthResult(BaseModel):
    """Module 7 output."""

    domain: str | None = None
    skipped: bool = False
    skip_reason: str | None = None
    spf: SPFStatus = Field(default_factory=SPFStatus)
    dmarc: DMARCStatus = Field(default_factory=DMARCStatus)
    dkim: DKIMStatus = Field(default_factory=DKIMStatus)
    mta_sts: MTASTSStatus = Field(default_factory=MTASTSStatus)
    spoofability_score: int = 0
    score_impact: int = 0


class DorkResult(BaseModel):
    """Single dork category output."""

    model_config = ConfigDict(use_enum_values=True)

    category: str
    queries: list[str] = Field(default_factory=list)
    ddg_result: DDGResult = DDGResult.NOT_CHECKED


class GoogleDorksResult(BaseModel):
    """Module 8 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    results: list[DorkResult] = Field(default_factory=list)
    ddg_checks_performed: int = 0
    score_impact: int = 0


class MetadataFinding(BaseModel):
    """Extracted document metadata finding."""

    model_config = ConfigDict(use_enum_values=True)

    document_url: str
    field_name: str
    value: str
    severity: RiskSeverity


class MetadataResult(BaseModel):
    """Module 9 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    domain: str | None = None
    documents_found: int = 0
    documents_scanned: int = 0
    findings: list[MetadataFinding] = Field(default_factory=list)
    unique_authors: list[str] = Field(default_factory=list)
    internal_software: list[str] = Field(default_factory=list)
    score_impact: int = 0


class ShodanService(BaseModel):
    """Per-service details parsed from Shodan host data."""

    port: int
    transport: str
    product: str | None = None
    version: str | None = None
    banner_excerpt: str | None = None
    cpe: list[str] = Field(default_factory=list)
    ssl_subject: str | None = None
    http_title: str | None = None
    severity: str = "LOW"

    @field_validator("banner_excerpt")
    @classmethod
    def truncate_banner(cls, value: str | None) -> str | None:
        """Cap stored banner excerpts to 200 characters."""

        if not value:
            return value
        return value[:200]


class ShodanHostResult(BaseModel):
    """Shodan host-level result for a resolved IP."""

    ip_str: str
    hostnames: list[str] = Field(default_factory=list)
    org: str | None = None
    country_name: str | None = None
    isp: str | None = None
    last_update: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    services: list[ShodanService] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    overall_severity: str = "LOW"


class ShodanReconResult(BaseModel):
    """Module 11 output."""

    model_config = ConfigDict(use_enum_values=True)

    skipped: bool = False
    skip_reason: str | None = None
    target_domain: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    hosts: list[ShodanHostResult] = Field(default_factory=list)
    total_open_ports: int = 0
    total_cves: int = 0
    unique_cves: list[str] = Field(default_factory=list)
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    overall_severity: str = "LOW"
    score_impact: int = 0


class FindingItem(BaseModel):
    """Normalized finding item emitted by the scorer."""

    model_config = ConfigDict(use_enum_values=True)

    id: str
    module: str
    category: str
    risk: RiskSeverity
    title: str
    description: str
    recommendation: str
    score_impact: int
    references: list[str] = Field(default_factory=list)


class ExposureScoreResult(BaseModel):
    """Module 10 output."""

    findings: list[FindingItem] = Field(default_factory=list)
    score: int = 0
    label: str = "MINIMAL EXPOSURE"


class ReportContext(BaseModel):
    """Unified report payload shared by all report writers."""

    model_config = ConfigDict(use_enum_values=True)

    target_email: str | None = None
    target_domain: str | None = None
    generated_at: datetime
    tool_name: str
    tool_version: str
    output_dir: Path
    credential_leak: CredentialLeakResult
    github_footprint: GitHubFootprintResult
    email_intel: EmailIntelResult
    social_footprint: SocialFootprintResult
    paste_monitor: PasteResult
    js_secret_scanner: JSSecretResult
    dns_email_auth: EmailAuthResult
    metadata_extractor: MetadataResult
    google_dorks: GoogleDorksResult
    shodan: ShodanReconResult
    exposure_score: ExposureScoreResult
