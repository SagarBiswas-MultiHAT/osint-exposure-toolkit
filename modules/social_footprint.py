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

_PLATFORM_NOT_FOUND_MARKERS: dict[str, tuple[str, ...]] = {
    "gitlab": (
        "404 page not found",
        "the page could not be found",
        "page not found",
    ),
    "npm": (
        "this user does not exist",
        "user not found",
        "404 not found",
    ),
    "pypi": (
        "no user by that name",
        "does not exist",
        "404 not found",
    ),
    "twitter": (
        "this account doesn't exist",
        "this account doesn\u2019t exist",
        "this account doesn&#39;t exist",
        "page doesn\u2019t exist",
        "page doesn't exist",
    ),
    "medium": (
        "sorry, we couldn't find that page",
        "page not found",
        "404",
    ),
    "hackernews": (
        "no such user",
    ),
    "linkedin": (
        "page not found",
        "profile unavailable",
        "an exact match for",
    ),
    "github": (
        "not found",
        "there isn\u2019t a github user",
    ),
    "keybase": (
        "user not found",
        "not found",
    ),
    "dockerhub": (
        "page not found",
        "404",
    ),
}

_GLOBAL_NOT_FOUND_MARKERS: tuple[str, ...] = (
    "not found",
    "page not found",
    "this page could not be found",
    "doesn't exist",
    "does not exist",
    "no such user",
)

_CHALLENGE_OR_BLOCK_MARKERS: tuple[str, ...] = (
    "client challenge",
    "enable javascript to proceed",
    "a required part of this site couldn",
    "captcha",
    "cf-challenge",
    "attention required",
)

_CONSERVATIVE_200_PLATFORMS: set[str] = {"twitter", "medium", "pypi"}


def _platform_key(platform_name: str | None, url: str) -> str:
    if platform_name:
        normalized = platform_name.strip().lower().replace("/x", "").replace("/", "")
        normalized = normalized.replace(" ", "")
        if normalized == "twitterx":
            return "twitter"
        return normalized

    lower_url = url.lower()
    if "gitlab.com" in lower_url:
        return "gitlab"
    if "npmjs.com" in lower_url:
        return "npm"
    if "pypi.org" in lower_url:
        return "pypi"
    if "x.com" in lower_url or "twitter.com" in lower_url:
        return "twitter"
    if "medium.com" in lower_url:
        return "medium"
    if "news.ycombinator.com" in lower_url:
        return "hackernews"
    if "linkedin.com" in lower_url:
        return "linkedin"
    if "github.com" in lower_url:
        return "github"
    if "keybase.io" in lower_url:
        return "keybase"
    if "hub.docker.com" in lower_url:
        return "dockerhub"
    return ""


def _looks_like_not_found_page(platform_name: str | None, url: str, response_text: str | None) -> bool:
    if not response_text:
        return False

    content = response_text.lower()
    key = _platform_key(platform_name, url)
    platform_markers = _PLATFORM_NOT_FOUND_MARKERS.get(key, ())

    if any(marker in content for marker in platform_markers):
        return True
    return any(marker in content for marker in _GLOBAL_NOT_FOUND_MARKERS)


def _looks_like_challenge_or_block_page(response_text: str | None) -> bool:
    if not response_text:
        return False
    content = response_text.lower()
    return any(marker in content for marker in _CHALLENGE_OR_BLOCK_MARKERS)


def _variants_from_identifier(identifier: str) -> list[str]:
    value = identifier.strip().lower()
    if not value:
        return []

    normalized = re.sub(r"[^a-z0-9]", "", value)
    dotted = value.replace("_", ".").replace("-", ".")
    tokens = [token for token in dotted.split(".") if token]

    variants = [
        value,
        normalized,
        value.replace(".", "-"),
        value.replace(".", "_"),
        value.replace("-", "_"),
        value.replace("_", "-"),
        value.replace("_", ""),
        value.replace("-", ""),
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
    return ordered


def _username_variants(email: str | None, username_hint: str | None = None) -> list[str]:
    """Generate username variants from username hint and/or email local part."""

    ordered: list[str] = []

    if username_hint:
        cleaned_hint = re.sub(r"[^a-zA-Z0-9._-]", "", username_hint)
        for candidate in _variants_from_identifier(cleaned_hint):
            if candidate not in ordered:
                ordered.append(candidate)

    if email:
        local_part = email.split("@", maxsplit=1)[0].strip().lower()
        for candidate in _variants_from_identifier(local_part):
            if candidate not in ordered:
                ordered.append(candidate)

    return ordered[:10]


def _variant_preference_score(variant: str | None, username_hint: str | None) -> int:
    if not variant:
        return 0
    if not username_hint:
        return 0

    raw_hint = re.sub(r"[^a-zA-Z0-9._-]", "", username_hint).lower()
    compact_hint = re.sub(r"[^a-z0-9]", "", raw_hint)
    compact_variant = re.sub(r"[^a-z0-9]", "", variant.lower())

    if variant.lower() == raw_hint:
        return 100
    if compact_variant == compact_hint:
        return 80
    if raw_hint in variant.lower() or variant.lower() in raw_hint:
        return 60
    return 10


def _status_from_http(
    status_code: int,
    url: str,
    *,
    platform_name: str | None = None,
    response_text: str | None = None,
) -> PlatformStatus:
    """Map HTTP status code to social profile status (hybrid policy)."""

    platform_key = _platform_key(platform_name, url)

    if status_code == 200 and _looks_like_challenge_or_block_page(response_text):
        return PlatformStatus.UNKNOWN
    if status_code == 200 and _looks_like_not_found_page(platform_name, url, response_text):
        return PlatformStatus.NOT_FOUND
    if status_code == 200:
        if platform_key in _CONSERVATIVE_200_PLATFORMS:
            return PlatformStatus.UNKNOWN
        return PlatformStatus.EXPOSED
    if status_code == 404:
        return PlatformStatus.NOT_FOUND
    if status_code == 999:
        LOGGER.info("LinkedIn returned HTTP 999 for %s; marking UNKNOWN.", url)
        return PlatformStatus.UNKNOWN
    if status_code in {401, 403, 429}:
        return PlatformStatus.UNKNOWN
    if status_code >= 500:
        return PlatformStatus.UNKNOWN
    return PlatformStatus.UNKNOWN


def _reason_from_http(
    status_code: int,
    url: str,
    *,
    platform_name: str | None = None,
    response_text: str | None = None,
) -> str | None:
    platform_key = _platform_key(platform_name, url)

    if status_code == 200 and _looks_like_challenge_or_block_page(response_text):
        return "Challenge or anti-bot page detected on HTTP 200 response."
    if status_code == 200 and _looks_like_not_found_page(platform_name, url, response_text):
        return "Profile-not-found markers detected in page content."
    if status_code == 200 and platform_key in _CONSERVATIVE_200_PLATFORMS:
        return f"{platform_name} returns ambiguous HTTP 200 pages; treated conservatively as UNKNOWN."
    if status_code == 200:
        return "Public profile page responded with HTTP 200."
    if status_code == 404:
        return "HTTP 404 Not Found."
    if status_code == 999 and platform_key == "linkedin":
        return (
            "LinkedIn anti-bot response (HTTP 999) blocked passive verification; "
            "manual browser verification is required."
        )
    if status_code in {401, 403}:
        return f"Access restricted (HTTP {status_code})."
    if status_code == 429:
        return "Rate limited by target platform (HTTP 429)."
    if status_code >= 500:
        return f"Server-side error from platform (HTTP {status_code})."
    return f"Ambiguous platform response (HTTP {status_code})."


async def _check_url(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    limiter: AsyncRateLimiter,
    url: str,
    platform_name: str,
) -> tuple[PlatformStatus, str | None, str]:
    """Check profile URL existence via HTTP HEAD with GET fallback."""

    headers = {"User-Agent": USER_AGENT}
    async with semaphore:
        await limiter.acquire()
        try:
            async with session.head(url, timeout=5, headers=headers, allow_redirects=True) as response:
                if response.status == 404:
                    status = _status_from_http(response.status, url, platform_name=platform_name)
                    reason = _reason_from_http(response.status, url, platform_name=platform_name)
                    final_url = str(getattr(response, "url", "") or url)
                    return status, reason, final_url
        except (aiohttp.ClientError, TimeoutError):
            pass

        try:
            async with session.get(url, timeout=5, headers=headers, allow_redirects=True) as response:
                response_text = None
                if response.status == 200:
                    response_text = await response.text(errors="ignore")
                status = _status_from_http(
                    response.status,
                    url,
                    platform_name=platform_name,
                    response_text=response_text,
                )
                reason = _reason_from_http(
                    response.status,
                    url,
                    platform_name=platform_name,
                    response_text=response_text,
                )
                final_url = str(getattr(response, "url", "") or url)
                return status, reason, final_url
        except (aiohttp.ClientError, TimeoutError):
            return PlatformStatus.UNKNOWN, "Network timeout/client error while probing profile URL.", url


async def run(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    config: AppConfig,
    email: str | None,
    username_hint: str | None = None,
) -> SocialFootprintResult:
    """Run social/web footprint checks from email-derived username variants."""

    if not email and not username_hint:
        return SocialFootprintResult(
            skipped=True,
            skip_reason="No email or username provided — username derivation requires at least one identifier.",
            score_impact=0,
        )

    limiter = AsyncRateLimiter(config.rate_limits.social_check_delay)
    variants = _username_variants(email, username_hint)

    profiles: list[SocialProfileEntry] = []
    max_platforms = config.scan_limits.max_social_platforms

    for platform_name, template in list(SOCIAL_PLATFORMS.items())[:max_platforms]:
        selected_variant = variants[0] if variants else None
        url = template.format(username=selected_variant)
        status, status_reason, final_url = await _check_url(session, semaphore, limiter, url, platform_name)
        status_rank = {
            PlatformStatus.EXPOSED: 3,
            PlatformStatus.UNKNOWN: 2,
            PlatformStatus.NOT_FOUND: 1,
        }

        best_variant = selected_variant
        best_url = final_url
        best_status = status
        best_status_reason = status_reason

        for variant in variants[1:]:
            if best_status == PlatformStatus.EXPOSED:
                break
            candidate_url = template.format(username=variant)
            candidate_status, candidate_reason, candidate_final_url = await _check_url(
                session,
                semaphore,
                limiter,
                candidate_url,
                platform_name,
            )
            if status_rank[candidate_status] > status_rank[best_status]:
                best_variant = variant
                best_url = candidate_final_url
                best_status = candidate_status
                best_status_reason = candidate_reason
            elif status_rank[candidate_status] == status_rank[best_status]:
                if _variant_preference_score(variant, username_hint) > _variant_preference_score(best_variant, username_hint):
                    best_variant = variant
                    best_url = candidate_final_url
                    best_status = candidate_status
                    best_status_reason = candidate_reason

        selected_variant = best_variant
        url = best_url
        status = best_status
        status_reason = best_status_reason

        positive = platform_name in POSITIVE_SIGNAL_PLATFORMS and status == PlatformStatus.EXPOSED

        profiles.append(
            SocialProfileEntry(
                platform=platform_name,
                url=url,
                status=status,
                status_reason=status_reason,
                username_tried=selected_variant,
                is_positive_signal=positive,
            )
        )

    if email:
        gravatar_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()  # noqa: S324
        gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
        gravatar_status, gravatar_reason, gravatar_final_url = await _check_url(
            session,
            semaphore,
            limiter,
            gravatar_url,
            "Gravatar",
        )
        profiles.append(
            SocialProfileEntry(
                platform="Gravatar",
                url=gravatar_final_url,
                status=gravatar_status,
                status_reason=gravatar_reason,
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
