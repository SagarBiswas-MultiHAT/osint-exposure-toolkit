"""JSON report generator."""

from __future__ import annotations

import json
from pathlib import Path

import aiofiles

from core.models import ReportContext


async def generate(context: ReportContext) -> Path:
    """Generate JSON report from shared context payload."""

    output_dir = Path(context.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "report.json"

    payload = {
        "meta": {
            "tool_name": context.tool_name,
            "tool_version": context.tool_version,
            "generated_at": context.generated_at.isoformat(),
            "target_email": context.target_email,
            "target_domain": context.target_domain,
            "score": context.exposure_score.score,
            "label": context.exposure_score.label,
        },
        "credential_leak": context.credential_leak.model_dump(mode="json"),
        "github_footprint": context.github_footprint.model_dump(mode="json"),
        "email_intel": context.email_intel.model_dump(mode="json"),
        "social_footprint": context.social_footprint.model_dump(mode="json"),
        "paste_monitor": context.paste_monitor.model_dump(mode="json"),
        "js_secret_scanner": context.js_secret_scanner.model_dump(mode="json"),
        "dns_email_auth": context.dns_email_auth.model_dump(mode="json"),
        "metadata_extractor": context.metadata_extractor.model_dump(mode="json"),
        "google_dorks": context.google_dorks.model_dump(mode="json"),
        "findings": [item.model_dump(mode="json") for item in context.exposure_score.findings],
    }

    async with aiofiles.open(output_file, "w", encoding="utf-8") as file:
        await file.write(json.dumps(payload, indent=2, ensure_ascii=False))

    return output_file
