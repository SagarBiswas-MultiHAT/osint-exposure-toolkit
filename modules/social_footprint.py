"""Social and web footprint discovery module."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re

import aiohttp

from core.config_loader import AppConfig
from core.constants import POSITIVE_SIGNAL_PLATFORMS, SOCIAL_PLATFORMS, USER_AGENT
from core.models import PlatformStatus, SocialFootprintResult, SocialProfileEntry
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")


def _username_variants(email: str) -> list[str]:
    """Generate username variants from local part."""

    local_part = email.split("@", maxsplit=1)[0].strip().lower()
    normalized = re.sub(r"[^a-z0-9]", "", local_part)
    dotted = local_part.replace("_", ".").replace("-", ".")
    tokens = [token for token in dotted.split(".") if token]

    variants = [
        normalized,
        local_part,
        local_part.replace(".", "_"),
        local_part.replace(".", "-"),
        local_part.replace("_", ""),
        local_part.replace("-", ""),
    ]

    if len(tokens) >= 2:
        variants.extend(
            [
                "".join(tokens),
                f"{tokens[0]}{tokens[-1]}",
                "_".join(tokens),
                "-".join(tokens),
            ]
        )

    ordered: list[str] = []
    for candidate in variants:
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered[:10]


def _status_from_http(status_code: int, url: str) -> PlatformStatus:
    """Map HTTP status code to social profile status (hybrid policy)."""

    if status_code == 200:
        return PlatformStatus.EXPOSED
    if status_code == 404:
        return PlatformStatus.NOT_FOUND
    if status_code == 999:
        LOGGER.info("LinkedIn returned HTTP 999 for %s; marking UNKNOWN.", url)
        return PlatformStatus.UNKNOWN
    if status_code in {401, 403, 429}:
        return PlatformStatus.EXPOSED
    if status_code >= 500:
        return PlatformStatus.UNKNOWN
    return PlatformStatus.UNKNOWN


async def _check_url(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
) -> PlatformStatus:
    """Check profile URL existence via HTTP HEAD with GET fallback."""

    headers = {"User-Agent": USER_AGENT}
    async with semaphore:
        await limiter.acquire()
        try:
            async with session.head(url, timeout=5, headers=headers, allow_redirects=True) as response:
                return _status_from_http(response.status, url)
        except (aiohttp.ClientError, TimeoutError):
            try:
                async with session.get(url, timeout=5, headers=headers, allow_redirects=True) as response:
                    return _status_from_http(response.status, url)
            except (aiohttp.ClientError, TimeoutError):
                return PlatformStatus.UNKNOWN


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
) -> SocialFootprintResult:
    """Run social/web footprint checks from email-derived username variants."""

    if not email:
        return SocialFootprintResult(
            skipped=True,
            skip_reason="No email provided — username derivation requires email local part.",
            score_impact=0,
        )

    limiter = AsyncRateLimiter(config.rate_limits.social_check_delay)
    variants = _username_variants(email)

    profiles: list[SocialProfileEntry] = []
    max_platforms = config.scan_limits.max_social_platforms

    for platform_name, template in list(SOCIAL_PLATFORMS.items())[:max_platforms]:
        selected_variant = variants[0] if variants else None
        url = template.format(username=selected_variant)
        status = await _check_url(session, semaphore, limiter, url)
        status_rank = {
            PlatformStatus.EXPOSED: 3,
            PlatformStatus.UNKNOWN: 2,
            PlatformStatus.NOT_FOUND: 1,
        }

        best_variant = selected_variant
        best_url = url
        best_status = status

        for variant in variants[1:]:
            if best_status == PlatformStatus.EXPOSED:
                break
            candidate_url = template.format(username=variant)
            candidate_status = await _check_url(session, semaphore, limiter, candidate_url)
            if status_rank[candidate_status] > status_rank[best_status]:
                best_variant = variant
                best_url = candidate_url
                best_status = candidate_status

        selected_variant = best_variant
        url = best_url
        status = best_status
        positive = platform_name in POSITIVE_SIGNAL_PLATFORMS and status == PlatformStatus.EXPOSED

        profiles.append(
            SocialProfileEntry(
                platform=platform_name,
                url=url,
                status=status,
                username_tried=selected_variant,
                is_positive_signal=positive,
            )
        )

    gravatar_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()  # noqa: S324
    gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
    gravatar_status = await _check_url(session, semaphore, limiter, gravatar_url)
    profiles.append(
        SocialProfileEntry(
            platform="Gravatar",
            url=gravatar_url,
            status=gravatar_status,
            username_tried=None,
            is_positive_signal=False,
        )
    )

    exposure_count = sum(
        1
        for profile in profiles
        if profile.status == PlatformStatus.EXPOSED and not profile.is_positive_signal
    )
    positive_signals = sum(1 for profile in profiles if profile.is_positive_signal)

    return SocialFootprintResult(
        skipped=False,
        email=email,
        username_variants=variants,
        profiles=profiles,
        total_exposure_count=exposure_count,
        positive_signal_count=positive_signals,
        score_impact=min(exposure_count, 10),
    )
