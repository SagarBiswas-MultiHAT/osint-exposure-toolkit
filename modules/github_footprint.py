"""GitHub footprint and secret scanning module."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp

from core.config_loader import AppConfig
from core.constants import CONFIG_FILES_TO_SCAN, SECRET_PATTERNS, USER_AGENT
from core.models import GitHubFootprintResult, GitHubRepoEntry, RiskSeverity, SecretFinding
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")


GITHUB_API = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"


def _mask_secret(value: str) -> str:
    """Mask secret values as first4***last4."""

    if len(value) <= 8:
        return "***"
    return f"{value[:4]}***{value[-4:]}"


def _severity_from_secret_count(secret_count: int) -> RiskSeverity:
    """Map number of secrets to overall severity."""

    if secret_count >= 3:
        return RiskSeverity.CRITICAL
    if secret_count == 2:
        return RiskSeverity.HIGH
    if secret_count == 1:
        return RiskSeverity.MEDIUM
    return RiskSeverity.INFO


def _score_impact(secret_count: int, severity: RiskSeverity) -> int:
    """Compute score impact for GitHub module."""

    base = min(secret_count * 5, 15)
    if severity == RiskSeverity.CRITICAL:
        base += 10
    elif severity == RiskSeverity.HIGH:
        base += 5
    elif severity == RiskSeverity.MEDIUM:
        base += 3
    return min(base, 25)


async def _get_json(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
    headers: dict[str, str],
) -> Any:
    """Perform a GitHub API GET request and decode JSON safely."""

    async with semaphore:
        await limiter.acquire()
        try:
            async with session.get(url, headers=headers) as response:
                if response.status >= 400:
                    return None
                return await response.json()
        except (aiohttp.ClientError, TimeoutError):
            LOGGER.warning("GitHub request failed: %s", url)
            return None


async def _get_text(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
    headers: dict[str, str],
) -> str | None:
    """Perform HTTP GET and return text body."""

    async with semaphore:
        await limiter.acquire()
        try:
            async with session.get(url, headers=headers) as response:
                if response.status >= 400:
                    return None
                return await response.text()
        except (aiohttp.ClientError, TimeoutError):
            return None


def _compile_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Compile secret regex patterns."""

    compiled: list[tuple[str, re.Pattern[str]]] = []
    for name, pattern in SECRET_PATTERNS.items():
        compiled.append((name, re.compile(pattern)))
    return compiled


def _extract_matches(repo: str, file_path: str, content: str) -> list[SecretFinding]:
    """Extract masked secret findings from file content."""

    findings: list[SecretFinding] = []
    for name, pattern in _compile_patterns():
        for match in pattern.finditer(content):
            raw_value = match.group(0)
            findings.append(
                SecretFinding(
                    repo=repo,
                    file_path=file_path,
                    pattern_type=name,
                    masked_value=_mask_secret(raw_value),
                    severity=RiskSeverity.HIGH if "key" in name.lower() else RiskSeverity.MEDIUM,
                )
            )
    return findings


def _is_recent(last_pushed: str | None) -> bool:
    """Check if repo was pushed in last 30 days."""

    if not last_pushed:
        return False
    try:
        pushed = datetime.fromisoformat(last_pushed.replace("Z", "+00:00"))
    except ValueError:
        return False
    return pushed >= datetime.now(UTC) - timedelta(days=30)


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    domain: str | None,
    target_hint: str | None = None,
) -> GitHubFootprintResult:
    """Run GitHub footprint and secret scan.

    Args:
        session: Shared aiohttp session.
        semaphore: Shared global concurrency semaphore.
        config: Application config.
        domain: Target domain.
        target_hint: Optional search hint.

    Returns:
        GitHubFootprintResult with typed module output.
    """

    github_key = config.api_keys.github.strip()
    if not github_key:
        LOGGER.warning("GitHub scan skipped — no API key configured. Add a free PAT to config.yaml.")
        return GitHubFootprintResult(
            skipped=True,
            skip_reason="GitHub scan skipped — no API key configured.",
            score_impact=0,
        )

    limiter = AsyncRateLimiter(config.rate_limits.github_delay)
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_key}",
        "User-Agent": USER_AGENT,
    }

    query = (target_hint or domain or "").strip()
    if not query or "@" in query:
        return GitHubFootprintResult(
            skipped=True,
            skip_reason="GitHub scan skipped — invalid query target.",
            score_impact=0,
        )

    search_url = f"{GITHUB_API}/search/users?q={query}"
    search_payload = await _get_json(session, semaphore, limiter, search_url, headers)
    items = search_payload.get("items", []) if isinstance(search_payload, dict) else []

    repos: list[GitHubRepoEntry] = []
    findings: list[SecretFinding] = []
    discovered_entities: list[str] = []
    repo_limit = config.scan_limits.max_github_repos
    file_limit = config.scan_limits.max_github_files
    workflow_limit = config.scan_limits.max_workflow_files

    for user_item in items:
        login = str(user_item.get("login", "")).strip()
        if not login or "@" in login:
            continue

        discovered_entities.append(login)
        repos_url = f"{GITHUB_API}/users/{login}/repos"
        repos_payload = await _get_json(session, semaphore, limiter, repos_url, headers)
        if not isinstance(repos_payload, list):
            continue

        for repo_obj in repos_payload:
            if len(repos) >= repo_limit:
                break

            repo_name = str(repo_obj.get("name", ""))
            owner_login = str(repo_obj.get("owner", {}).get("login", login))
            default_branch = str(repo_obj.get("default_branch", "main"))

            repo_entry = GitHubRepoEntry(
                name=repo_name,
                description=repo_obj.get("description"),
                language=repo_obj.get("language"),
                stars=int(repo_obj.get("stargazers_count", 0) or 0),
                forks=int(repo_obj.get("forks_count", 0) or 0),
                last_pushed=repo_obj.get("pushed_at"),
                active=_is_recent(repo_obj.get("pushed_at")),
                has_pages=bool(repo_obj.get("has_pages", False)),
                html_url=repo_obj.get("html_url"),
                commit_hash=repo_obj.get("pushed_at") and repo_obj.get("id") and str(repo_obj.get("id")),
            )
            repos.append(repo_entry)

            scanned_files = 0
            for file_path in CONFIG_FILES_TO_SCAN:
                if scanned_files >= file_limit:
                    break
                raw_url = f"{RAW_BASE}/{owner_login}/{repo_name}/{default_branch}/{file_path}"
                text = await _get_text(session, semaphore, limiter, raw_url, headers={"User-Agent": USER_AGENT})
                if text is None:
                    continue

                scanned_files += 1
                findings.extend(_extract_matches(repo_name, file_path, text))

            workflow_url = f"{GITHUB_API}/repos/{owner_login}/{repo_name}/contents/.github/workflows"
            workflows = await _get_json(session, semaphore, limiter, workflow_url, headers)
            if isinstance(workflows, list):
                workflow_files = [
                    item for item in workflows if str(item.get("name", "")).endswith((".yml", ".yaml"))
                ][:workflow_limit]
                for workflow_file in workflow_files:
                    file_name = str(workflow_file.get("name", ""))
                    raw_url = (
                        f"{RAW_BASE}/{owner_login}/{repo_name}/{default_branch}/.github/workflows/{file_name}"
                    )
                    text = await _get_text(
                        session,
                        semaphore,
                        limiter,
                        raw_url,
                        headers={"User-Agent": USER_AGENT},
                    )
                    if text is None:
                        continue
                    findings.extend(_extract_matches(repo_name, f".github/workflows/{file_name}", text))

        if len(repos) >= repo_limit:
            break

    overall = _severity_from_secret_count(len(findings))
    return GitHubFootprintResult(
        skipped=False,
        query=query,
        discovered_entities=discovered_entities,
        repositories=repos,
        secrets_found=findings,
        overall_severity=overall,
        score_impact=_score_impact(len(findings), overall),
    )
