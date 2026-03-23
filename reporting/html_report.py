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

    template = _environment().get_template("report.html.jinja")
    rendered = template.render(
        target_email=context.target_email,
        target_domain=context.target_domain,
        generated_at=context.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        tool_name=context.tool_name,
        tool_version=context.tool_version,
        credential_leak=context.credential_leak.model_dump(mode="json"),
        github_footprint=context.github_footprint.model_dump(mode="json"),
        email_intel=context.email_intel.model_dump(mode="json"),
        social_footprint=context.social_footprint.model_dump(mode="json"),
        paste_monitor=context.paste_monitor.model_dump(mode="json"),
        js_secret_scanner=context.js_secret_scanner.model_dump(mode="json"),
        dns_email_auth=context.dns_email_auth.model_dump(mode="json"),
        metadata_extractor=context.metadata_extractor.model_dump(mode="json"),
        google_dorks=context.google_dorks.model_dump(mode="json"),
        score=context.exposure_score.score,
        label=context.exposure_score.label,
        findings=[item.model_dump(mode="json") for item in context.exposure_score.findings],
    )

    async with aiofiles.open(output_file, "w", encoding="utf-8") as file:
        await file.write(rendered)

    return output_file
