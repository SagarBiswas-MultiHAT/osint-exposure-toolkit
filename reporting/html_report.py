"""HTML report generator."""

from __future__ import annotations

from pathlib import Path

import aiofiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import ReportContext


def _environment() -> Environment:
    """Build Jinja environment for HTML report template loading."""

    return Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )


async def generate(context: ReportContext) -> Path:
    """Render and write the HTML report."""

    output_dir = Path(context.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "report.html"

    score = context.exposure_score.score
    if score <= 30:
        gauge_color = "#2ecc71"
    elif score <= 50:
        gauge_color = "#f39c12"
    elif score <= 70:
        gauge_color = "#ff4d4f"
    else:
        gauge_color = "#ff0000"

    findings = [item.model_dump(mode="json") for item in context.exposure_score.findings]
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        risk = str(finding.get("risk", "INFO")).upper()
        if risk in severity_counts:
            severity_counts[risk] += 1

    credential_leak = context.credential_leak.model_dump(mode="json")
    credential_leak["summary_count"] = (
        credential_leak.get("leakcheck_found", 0)
        if credential_leak.get("engine") == "leakcheck"
        else credential_leak.get("total_breaches", 0)
    )

    github = context.github_footprint.model_dump(mode="json")
    github["total_repos"] = len(github.get("repositories", []))
    github["active_repos_30d"] = sum(1 for repo in github.get("repositories", []) if repo.get("active"))
    github["secret_count"] = len(github.get("secrets_found", []))

    email_intel = context.email_intel.model_dump(mode="json")
    social = context.social_footprint.model_dump(mode="json")
    pastes = context.paste_monitor.model_dump(mode="json")
    js_secrets = context.js_secret_scanner.model_dump(mode="json")
    dns_auth = context.dns_email_auth.model_dump(mode="json")
    metadata = context.metadata_extractor.model_dump(mode="json")
    google_dorks = context.google_dorks.model_dump(mode="json")
    dorks = google_dorks.get("results", [])
    shodan = context.shodan.model_dump(mode="json")

    template = _environment().get_template("report.html.jinja")
    rendered = template.render(
        target_email=context.target_email,
        target_domain=context.target_domain,
        generated_at=context.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        tool_name=context.tool_name,
        tool_version=context.tool_version,
        credential_leak=credential_leak,
        github_footprint=github,
        email_intel=email_intel,
        social_footprint=social,
        paste_monitor=pastes,
        js_secret_scanner=js_secrets,
        dns_email_auth=dns_auth,
        metadata_extractor=metadata,
        google_dorks=google_dorks,
        github=github,
        social=social,
        pastes=pastes,
        js_secrets=js_secrets,
        dns_auth=dns_auth,
        metadata=metadata,
        dorks=dorks,
        shodan=shodan,
        score=score,
        label=context.exposure_score.label,
        findings=findings,
        gauge_color=gauge_color,
        severity_counts=severity_counts,
    )

    async with aiofiles.open(output_file, "w", encoding="utf-8") as file:
        await file.write(rendered)

    return output_file
