"""Public document metadata extraction module."""

from __future__ import annotations

import io
import logging
import re
from urllib.parse import urljoin

import aiohttp
from docx import Document
from pypdf import PdfReader

from core.config_loader import AppConfig
from core.constants import USER_AGENT
from core.models import MetadataFinding, MetadataResult, RiskSeverity

LOGGER = logging.getLogger("osint_exposure_toolkit")


def _extract_doc_urls(base_url: str, text: str) -> list[str]:
    """Extract PDF and DOCX URLs from text payload."""

    matches = re.findall(r"https?://[^\s'\"<>]+\.(?:pdf|docx)", text, flags=re.IGNORECASE)
    urls: list[str] = []
    for item in matches:
        if item not in urls:
            urls.append(item)

    if not urls:
        for item in re.findall(r"/[^\s'\"<>]+\.(?:pdf|docx)", text, flags=re.IGNORECASE):
            absolute = urljoin(base_url, item)
            if absolute not in urls:
                urls.append(absolute)

    return urls


def _extract_pdf_metadata(data: bytes) -> dict[str, str]:
    """Extract selected metadata fields from PDF bytes."""

    reader = PdfReader(io.BytesIO(data))
    metadata = reader.metadata or {}
    mapped: dict[str, str] = {}

    keys = {
        "Author": "/Author",
        "Creator": "/Creator",
        "Producer": "/Producer",
        "Subject": "/Subject",
        "Keywords": "/Keywords",
        "CreationDate": "/CreationDate",
    }

    for label, key in keys.items():
        value = metadata.get(key)
        if value:
            mapped[label] = str(value)
    return mapped


def _extract_docx_metadata(data: bytes) -> dict[str, str]:
    """Extract selected metadata fields from DOCX bytes."""

    doc = Document(io.BytesIO(data))
    props = doc.core_properties

    mapped: dict[str, str] = {}
    if props.author:
        mapped["Author"] = props.author
    if props.last_modified_by:
        mapped["last_modified_by"] = props.last_modified_by
    if props.subject:
        mapped["Subject"] = props.subject
    if props.keywords:
        mapped["Keywords"] = props.keywords
    return mapped


def _is_likely_name(value: str) -> bool:
    """Simple heuristic to flag likely personal names."""

    parts = [part for part in value.split() if part]
    return len(parts) >= 2 and all(part[:1].isalpha() for part in parts)


async def _fetch_text(
    session: aiohttp.ClientSession,
    semaphore,
    url: str,
    request_timeout: int,
) -> str:
    """Fetch URL text, returning empty string on failure."""

    async with semaphore:
        try:
            async with session.get(
                url,
                timeout=request_timeout,
                headers={"User-Agent": USER_AGENT},
            ) as response:
                if response.status != 200:
                    return ""
                return await response.text()
        except (aiohttp.ClientError, TimeoutError):
            return ""


async def _fetch_bytes(
    session: aiohttp.ClientSession,
    semaphore,
    url: str,
    request_timeout: int,
) -> bytes | None:
    """Fetch URL bytes, returning None on failure."""

    async with semaphore:
        try:
            async with session.get(
                url,
                timeout=request_timeout,
                headers={"User-Agent": USER_AGENT},
            ) as response:
                if response.status != 200:
                    return None
                return await response.read()
        except (aiohttp.ClientError, TimeoutError):
            return None


async def run(
    session: aiohttp.ClientSession,
    semaphore,
    config: AppConfig,
    domain: str | None,
) -> MetadataResult:
    """Run document metadata extraction for target domain."""

    if not domain:
        return MetadataResult(
            skipped=True,
            skip_reason="No domain provided — metadata extraction requires a domain.",
            score_impact=0,
        )

    base_url = f"https://{domain}"
    request_timeout = config.general.request_timeout

    sitemap_text = await _fetch_text(session, semaphore, f"{base_url}/sitemap.xml", request_timeout)
    robots_text = await _fetch_text(session, semaphore, f"{base_url}/robots.txt", request_timeout)

    discovered_urls = _extract_doc_urls(base_url, sitemap_text + "\n" + robots_text)
    discovered_urls = discovered_urls[: config.scan_limits.max_docs_to_fetch]

    findings: list[MetadataFinding] = []
    unique_authors: list[str] = []
    internal_software: list[str] = []
    scanned = 0

    for url in discovered_urls:
        content = await _fetch_bytes(session, semaphore, url, request_timeout)
        if content is None:
            continue

        metadata: dict[str, str] = {}
        lowered = url.lower()
        if lowered.endswith(".pdf"):
            try:
                metadata = _extract_pdf_metadata(content)
            except Exception:
                metadata = {}
        elif lowered.endswith(".docx"):
            try:
                metadata = _extract_docx_metadata(content)
            except Exception:
                metadata = {}

        scanned += 1
        for field_name, value in metadata.items():
            severity = RiskSeverity.LOW
            if field_name in {"Author", "last_modified_by"} and _is_likely_name(value):
                severity = RiskSeverity.MEDIUM
                if value not in unique_authors:
                    unique_authors.append(value)
            if field_name in {"Creator", "Producer"} and value not in internal_software:
                internal_software.append(value)

            findings.append(
                MetadataFinding(
                    document_url=url,
                    field_name=field_name,
                    value=value,
                    severity=severity,
                )
            )

    if not discovered_urls:
        return MetadataResult(
            skipped=False,
            domain=domain,
            documents_found=0,
            documents_scanned=0,
            findings=[],
            unique_authors=[],
            internal_software=[],
            score_impact=0,
        )

    base = min(len(unique_authors) * 3, 6)
    if internal_software:
        base += 2
    if any(item.severity == RiskSeverity.MEDIUM for item in findings):
        base += 2

    return MetadataResult(
        skipped=False,
        domain=domain,
        documents_found=len(discovered_urls),
        documents_scanned=scanned,
        findings=findings,
        unique_authors=unique_authors,
        internal_software=internal_software,
        score_impact=min(base, 10),
    )
