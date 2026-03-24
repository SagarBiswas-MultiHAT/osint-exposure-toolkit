"""CLI entrypoint for OSINT Exposure Toolkit."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiohttp
import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from core.config_loader import AppConfig, load_config
from core.constants import TOOL_NAME, TOOL_VERSION, USER_AGENT
from core.logger import setup_logger
from core.models import (
    CredentialLeakResult,
    EmailAuthResult,
    EmailIntelResult,
    GitHubFootprintResult,
    GoogleDorksResult,
    HIBPMode,
    JSSecretResult,
    MetadataResult,
    PasteResult,
    ReportContext,
    ShodanReconResult,
    SocialFootprintResult,
)
from graph.exposure_graph import generate as generate_graph
from modules.credential_leak import run as run_credential_leak
from modules.credential_leak import select_engine_choice
from modules.dns_email_auth import run as run_dns_email_auth
from modules.email_intel import run as run_email_intel
from modules.exposure_scorer import run as run_exposure_scorer
from modules.github_footprint import run as run_github_footprint
from modules.google_dorks import run as run_google_dorks
from modules.js_secret_scanner import run as run_js_secret_scanner
from modules.metadata_extractor import run as run_metadata_extractor
from modules.paste_monitor import run as run_paste_monitor
from modules.shodan_recon import run as run_shodan_recon
from modules.social_footprint import run as run_social_footprint
from reporting.html_report import generate as generate_html_report
from reporting.json_report import generate as generate_json_report
from reporting.markdown_report import generate as generate_markdown_report

CONSOLE = Console()

MODULE_ALIASES: dict[str, str] = {
    "cred": "credential_leak",
    "github": "github_footprint",
    "email": "email_intel",
    "social": "social_footprint",
    "pastes": "paste_monitor",
    "js": "js_secret_scanner",
    "dns": "dns_email_auth",
    "metadata": "metadata_extractor",
    "dorks": "google_dorks",
    "shodan": "shodan_recon",
}


def _parse_csv(value: str | None) -> list[str]:
    """Parse comma-separated CLI values into normalized list."""

    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _banner() -> None:
    """Render startup banner."""

    CONSOLE.print(
        Panel.fit(
            f"[bold cyan]{TOOL_NAME}[/bold cyan] v{TOOL_VERSION}\n"
            "Passive OSINT | Ethical | Non-Destructive",
            border_style="cyan",
        )
    )


def _select_hibp_mode(email: str | None, free_hibp: bool, demo_mode: bool) -> HIBPMode:
    """Resolve HIBP mode according to CLI flags and interactive prompt rules."""

    if demo_mode:
        return HIBPMode.DEMO
    if free_hibp:
        return HIBPMode.FREE
    if not email:
        return HIBPMode.FREE

    CONSOLE.print("[cyan]Select HIBP scan mode:[/cyan]")
    CONSOLE.print("  [1] Free HIBP    — No API key required. Shows breach landscape only.")
    CONSOLE.print("  [2] Premium HIBP — Per-email breach lookup. Requires API key in config.yaml.")

    first = Prompt.ask("Enter choice [1/2]", default="1").strip()
    if first == "1":
        return HIBPMode.FREE
    if first == "2":
        return HIBPMode.LIVE

    second = Prompt.ask(
        "Invalid choice. Please enter 1 for Free HIBP or 2 for Premium HIBP",
        default="1",
    ).strip()
    if second == "2":
        return HIBPMode.LIVE
    if second == "1":
        return HIBPMode.FREE

    return HIBPMode.FREE


def _select_credential_engine(
    email: str | None,
    use_hibp: bool,
    free_hibp: bool,
    demo_mode: bool,
) -> str:
    """Select credential leak engine with LeakCheck as default."""

    if free_hibp or demo_mode or use_hibp:
        return "hibp"
    if not email:
        return "leakcheck"

    CONSOLE.print("[cyan]Select credential leak engine:[/cyan]")
    CONSOLE.print("  [1] LeakCheck  (default) — Per-email breach lookup. API key optional.")
    CONSOLE.print("  [2] HIBP       — Free / Premium / Demo modes available.")

    first = Prompt.ask(
        "Press Enter or type 1 to use LeakCheck, type 2 for HIBP",
        default="1",
    )
    engine = select_engine_choice(first)
    if first.strip().lower() not in {"", "1", "2", "hibp", "leakcheck"}:
        second = Prompt.ask(
            "Invalid choice. Enter 1 for LeakCheck or 2 for HIBP",
            default="1",
        )
        engine = select_engine_choice(second)
    return engine


def _is_module_enabled(config: AppConfig, module_key: str, selected_modules: set[str]) -> bool:
    """Evaluate module enablement from config and CLI filters."""

    if selected_modules and module_key not in selected_modules:
        return False

    if module_key == "credential_leak":
        return config.modules.credential_leak
    if module_key == "github_footprint":
        return config.modules.github_footprint
    if module_key == "email_intel":
        return config.modules.email_intel
    if module_key == "social_footprint":
        return config.modules.social_footprint
    if module_key == "paste_monitor":
        return config.modules.paste_monitor
    if module_key == "js_secret_scanner":
        return config.modules.js_secret_scanner
    if module_key == "dns_email_auth":
        return config.modules.dns_email_auth
    if module_key == "metadata_extractor":
        return config.modules.metadata_extractor
    if module_key == "google_dorks":
        return config.modules.google_dorks
    if module_key == "shodan_recon":
        return config.modules.shodan_recon
    return True


def _module_summary_rows(
    credential_leak: CredentialLeakResult,
    github_footprint: GitHubFootprintResult,
    email_intel: EmailIntelResult,
    social_footprint: SocialFootprintResult,
    paste_monitor: PasteResult,
    js_secret_scanner: JSSecretResult,
    dns_email_auth: EmailAuthResult,
    metadata_extractor: MetadataResult,
    google_dorks: GoogleDorksResult,
    shodan_recon: ShodanReconResult,
) -> list[tuple[str, int, str, int]]:
    """Build summary rows for Rich completion table."""

    credential_findings = (
        credential_leak.leakcheck_found if credential_leak.engine == "leakcheck" else credential_leak.total_breaches
    )

    return [
        ("credential_leak", credential_findings, str(credential_leak.overall_severity), credential_leak.score_impact),
        ("github_footprint", len(github_footprint.secrets_found), str(github_footprint.overall_severity), github_footprint.score_impact),
        ("email_intel", 1 if email_intel.format_valid else 0, "INFO", email_intel.score_impact),
        ("social_footprint", social_footprint.total_exposure_count, "INFO", social_footprint.score_impact),
        ("paste_monitor", paste_monitor.total_pastes, "INFO", paste_monitor.score_impact),
        ("js_secret_scanner", len(js_secret_scanner.secrets_found), "INFO", js_secret_scanner.score_impact),
        ("dns_email_auth", dns_email_auth.spoofability_score, "INFO", dns_email_auth.score_impact),
        ("metadata_extractor", len(metadata_extractor.findings), "INFO", metadata_extractor.score_impact),
        ("google_dorks", len(google_dorks.results), "INFO", google_dorks.score_impact),
        ("shodan_recon", shodan_recon.total_open_ports, shodan_recon.overall_severity, shodan_recon.score_impact),
    ]


async def _run(
    email: str | None,
    username: str | None,
    domain: str | None,
    use_hibp: bool,
    free_hibp: bool,
    demo_mode: bool,
    skip_pastes: bool,
    modules: str | None,
    output: str | None,
    no_graph: bool,
    config_path: str,
) -> None:
    """Async runtime orchestrator."""

    started = datetime.now(UTC)
    config = load_config(config_path)

    selected_modules = {
        MODULE_ALIASES[item]
        for item in _parse_csv(modules)
        if item in MODULE_ALIASES
    }

    output_formats = _parse_csv(output) or config.general.output_formats

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M")
    output_dir = Path(config.general.output_dir) / f"target_{timestamp}"
    logger = setup_logger(config.general.log_level, str(output_dir))

    engine = _select_credential_engine(email, use_hibp, free_hibp, demo_mode)
    hibp_mode = _select_hibp_mode(email, free_hibp, demo_mode) if engine == "hibp" else HIBPMode.FREE
    if not email:
        logger.info("No email provided — credential scan limited to domain pastes.")
    if engine == "leakcheck":
        logger.info("Credential engine: LeakCheck")
    else:
        logger.info("Credential engine: HIBP (%s)", hibp_mode.value)

    timeout = aiohttp.ClientTimeout(total=config.general.request_timeout)
    semaphore = asyncio.Semaphore(config.general.max_concurrent_requests)

    credential_leak = CredentialLeakResult(mode=HIBPMode.FREE, engine=engine)
    paste_monitor = PasteResult(mode="free", score_impact=0)
    github_footprint = GitHubFootprintResult(skipped=True, skip_reason="Not selected")
    email_intel = EmailIntelResult(skipped=True, skip_reason="Not selected")
    dns_email_auth = EmailAuthResult(skipped=True, skip_reason="Not selected")
    social_footprint = SocialFootprintResult(skipped=True, skip_reason="Not selected")
    js_secret_scanner = JSSecretResult(skipped=True, skip_reason="Not selected")
    metadata_extractor = MetadataResult(skipped=True, skip_reason="Not selected")
    google_dorks = GoogleDorksResult(skipped=True, skip_reason="Not selected")
    shodan_recon = ShodanReconResult(skipped=True, skip_reason="Not selected")

    async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": USER_AGENT}) as session:
        if _is_module_enabled(config, "credential_leak", selected_modules):
            try:
                credential_leak = await run_credential_leak(
                    session,
                    semaphore,
                    config,
                    email,
                    hibp_mode,
                    engine=engine,
                )
            except Exception:
                logger.exception("credential_leak failed")

        if not skip_pastes and _is_module_enabled(config, "paste_monitor", selected_modules):
            paste_monitor = run_paste_monitor(credential_leak)

        async def run_github() -> GitHubFootprintResult:
            if not _is_module_enabled(config, "github_footprint", selected_modules):
                return GitHubFootprintResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_github_footprint(session, semaphore, config, domain, domain)
            except Exception:
                logger.exception("github_footprint failed")
                return GitHubFootprintResult(skipped=True, skip_reason="Execution error")

        async def run_email() -> EmailIntelResult:
            if not _is_module_enabled(config, "email_intel", selected_modules):
                return EmailIntelResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_email_intel(session, semaphore, config, email)
            except Exception:
                logger.exception("email_intel failed")
                return EmailIntelResult(skipped=True, skip_reason="Execution error")

        async def run_dns() -> EmailAuthResult:
            if not _is_module_enabled(config, "dns_email_auth", selected_modules):
                return EmailAuthResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_dns_email_auth(session, semaphore, config, domain)
            except Exception:
                logger.exception("dns_email_auth failed")
                return EmailAuthResult(skipped=True, skip_reason="Execution error")

        async def run_shodan() -> ShodanReconResult:
            if not _is_module_enabled(config, "shodan_recon", selected_modules):
                return ShodanReconResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_shodan_recon(session, semaphore, config, domain)
            except Exception:
                logger.exception("shodan_recon failed")
                return ShodanReconResult(skipped=True, skip_reason="Execution error")

        github_footprint, email_intel, dns_email_auth, shodan_recon = await asyncio.gather(
            run_github(), run_email(), run_dns(), run_shodan()
        )

        async def run_social() -> SocialFootprintResult:
            if not _is_module_enabled(config, "social_footprint", selected_modules):
                return SocialFootprintResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_social_footprint(session, semaphore, config, email, username)
            except Exception:
                logger.exception("social_footprint failed")
                return SocialFootprintResult(skipped=True, skip_reason="Execution error")

        async def run_js() -> JSSecretResult:
            if not _is_module_enabled(config, "js_secret_scanner", selected_modules):
                return JSSecretResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_js_secret_scanner(session, semaphore, config, domain)
            except Exception:
                logger.exception("js_secret_scanner failed")
                return JSSecretResult(skipped=True, skip_reason="Execution error")

        async def run_metadata() -> MetadataResult:
            if not _is_module_enabled(config, "metadata_extractor", selected_modules):
                return MetadataResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_metadata_extractor(session, semaphore, config, domain)
            except Exception:
                logger.exception("metadata_extractor failed")
                return MetadataResult(skipped=True, skip_reason="Execution error")

        async def run_dorks() -> GoogleDorksResult:
            if not _is_module_enabled(config, "google_dorks", selected_modules):
                return GoogleDorksResult(skipped=True, skip_reason="Not selected")
            try:
                return await run_google_dorks(session, semaphore, config, domain, email, enable_live_check=True)
            except Exception:
                logger.exception("google_dorks failed")
                return GoogleDorksResult(skipped=True, skip_reason="Execution error")

        social_footprint, js_secret_scanner, metadata_extractor, google_dorks = await asyncio.gather(
            run_social(), run_js(), run_metadata(), run_dorks()
        )

        score_result = run_exposure_scorer(
            credential_leak=credential_leak,
            github_footprint=github_footprint,
            email_intel=email_intel,
            social_footprint=social_footprint,
            paste_monitor=paste_monitor,
            js_secret_scanner=js_secret_scanner,
            dns_email_auth=dns_email_auth,
            metadata_extractor=metadata_extractor,
            google_dorks=google_dorks,
            shodan_recon=shodan_recon,
        )

        context = ReportContext(
            target_email=email,
            target_domain=domain,
            generated_at=datetime.now(UTC),
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            output_dir=output_dir,
            credential_leak=credential_leak,
            github_footprint=github_footprint,
            email_intel=email_intel,
            social_footprint=social_footprint,
            paste_monitor=paste_monitor,
            js_secret_scanner=js_secret_scanner,
            dns_email_auth=dns_email_auth,
            metadata_extractor=metadata_extractor,
            google_dorks=google_dorks,
            shodan=shodan_recon,
            exposure_score=score_result,
        )

        report_tasks: list[Any] = []
        if "html" in output_formats:
            report_tasks.append(generate_html_report(context))
        if "json" in output_formats:
            report_tasks.append(generate_json_report(context))
        if "md" in output_formats:
            report_tasks.append(generate_markdown_report(context))

        if report_tasks:
            await asyncio.gather(*report_tasks)

        if not no_graph and config.modules.exposure_graph:
            await generate_graph(context)

    summary = Table(title="Module Summary")
    summary.add_column("Module", style="cyan")
    summary.add_column("Findings", justify="right")
    summary.add_column("Severity", style="yellow")
    summary.add_column("Score Impact", justify="right", style="red")

    for module_name, count, severity, score_impact in _module_summary_rows(
        credential_leak,
        github_footprint,
        email_intel,
        social_footprint,
        paste_monitor,
        js_secret_scanner,
        dns_email_auth,
        metadata_extractor,
        google_dorks,
        shodan_recon,
    ):
        summary.add_row(module_name, str(count), severity, str(score_impact))

    CONSOLE.print(summary)
    CONSOLE.print(
        Panel.fit(
            f"Final Exposure Score: [bold]{score_result.score}[/bold] / 100\n"
            f"Label: [bold]{score_result.label}[/bold]",
            border_style="magenta",
        )
    )

    elapsed = datetime.now(UTC) - started
    CONSOLE.print(f"[cyan]Output directory:[/cyan] {output_dir}")
    CONSOLE.print(f"[cyan]Elapsed:[/cyan] {elapsed}")


@click.command()
@click.option("--email", type=str, default=None, help="Email to investigate")
@click.option("--username", type=str, default=None, help="Preferred username to probe across social platforms")
@click.option("--domain", type=str, default=None, help="Domain to investigate")
@click.option("--use-hibp", is_flag=True, help="Use HIBP engine instead of default LeakCheck")
@click.option("--free-hibp", is_flag=True, help="Skip prompt and force Free HIBP mode")
@click.option("--demo-mode", is_flag=True, help="Skip prompt and force Demo mode")
@click.option("--skip-pastes", is_flag=True, help="Skip paste monitor module")
@click.option("--modules", type=str, default=None, help="Comma-separated module aliases")
@click.option("--output", type=str, default=None, help="Comma-separated output formats")
@click.option("--no-graph", is_flag=True, help="Disable exposure graph generation")
@click.option("--config", "config_path", default="config.yaml", type=str, help="Config file path")
def main(
    email: str | None,
    username: str | None,
    domain: str | None,
    use_hibp: bool,
    free_hibp: bool,
    demo_mode: bool,
    skip_pastes: bool,
    modules: str | None,
    output: str | None,
    no_graph: bool,
    config_path: str,
) -> None:
    """Run the OSINT Digital Exposure Toolkit CLI."""

    if not email and not domain and not username:
        raise click.UsageError("At least one of --email, --domain, or --username is required.")
    if use_hibp and (free_hibp or demo_mode):
        raise click.UsageError(
            "--use-hibp is redundant when --free-hibp or --demo-mode is set. Use only one HIBP flag."
        )

    _banner()
    asyncio.run(
        _run(
            email=email,
            username=username,
            domain=domain,
            use_hibp=use_hibp,
            free_hibp=free_hibp,
            demo_mode=demo_mode,
            skip_pastes=skip_pastes,
            modules=modules,
            output=output,
            no_graph=no_graph,
            config_path=config_path,
        )
    )


if __name__ == "__main__":
    main()
