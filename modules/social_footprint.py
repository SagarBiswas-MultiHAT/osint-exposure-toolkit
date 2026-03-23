"""Social and web footprint discovery module."""

from __future__ import annotations

import asyncio
import hashlib
import logging

import aiohttp

from core.config_loader import AppConfig
from core.constants import POSITIVE_SIGNAL_PLATFORMS, SOCIAL_PLATFORMS, USER_AGENT
from core.models import PlatformStatus, SocialFootprintResult, SocialProfileEntry
from core.rate_limiter import AsyncRateLimiter

LOGGER = logging.getLogger("osint_exposure_toolkit")


def _username_variants(email: str) -> list[str]:
    """Generate username variants from local part."""

    local_part = email.split("@", maxsplit=1)[0].strip().lower()
    normalized = local_part.replace(".", "")
    variants = [normalized, local_part, local_part.replace(".", "_"), local_part.replace(".", "-")]

    ordered: list[str] = []
    for candidate in variants:
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered[:4]


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
                if response.status == 200:
                    return PlatformStatus.EXPOSED
                if response.status == 404:
                    return PlatformStatus.NOT_FOUND
                if response.status == 999:
                    LOGGER.info("LinkedIn returned HTTP 999 for %s; marking UNKNOWN.", url)
                    return PlatformStatus.UNKNOWN
                return PlatformStatus.UNKNOWN
        except (aiohttp.ClientError, TimeoutError):
            try:
                async with session.get(url, timeout=5, headers=headers, allow_redirects=True) as response:
                    if response.status == 200:
                        return PlatformStatus.EXPOSED
                    if response.status == 404:
                        return PlatformStatus.NOT_FOUND
                    if response.status == 999:
                        LOGGER.info("LinkedIn returned HTTP 999 for %s; marking UNKNOWN.", url)
                        return PlatformStatus.UNKNOWN
                    return PlatformStatus.UNKNOWN
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
        positive = platform_name in POSITIVE_SIGNAL_PLATFORMS and status == PlatformStatus.EXPOSED

        if platform_name not in POSITIVE_SIGNAL_PLATFORMS:
            for variant in variants[1:]:
                if status == PlatformStatus.EXPOSED:
                    break
                candidate_url = template.format(username=variant)
                candidate_status = await _check_url(session, semaphore, limiter, candidate_url)
                if candidate_status == PlatformStatus.EXPOSED:
                    url = candidate_url
                    selected_variant = variant
                    status = candidate_status
                    break

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
