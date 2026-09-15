"""Internal and researcher-visible external duplicate detection for Windeep."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.database import Database, finding_fingerprint


class DuplicateLookupError(RuntimeError):
    """Raised when an authenticated external duplicate lookup fails."""


@dataclass(frozen=True, slots=True)
class DuplicateCandidate:
    """Normalized duplicate candidate with a transparent similarity score."""

    source: str
    identifier: str
    title: str
    endpoint: str
    vuln_type: str
    score: float
    exact: bool
    url: str | None = None
    state: str | None = None


@dataclass(frozen=True, slots=True)
class DisclosureContext:
    """disclose.io routing/policy context; it is not a private duplicate-report result."""

    asset: str
    duplicate_visibility_supported: bool
    route_class: str | None
    delivery_agent: str | None
    contacts: tuple[str, ...]
    raw: dict[str, Any]


_WORD_RE = re.compile(r"[^a-z0-9]+")


def _normalize_text(value: str | None) -> str:
    return " ".join(part for part in _WORD_RE.split((value or "").casefold()) if part)


def _canonical_endpoint(value: str | None) -> str:
    if not value:
        return ""
    raw = value.strip()
    if "://" not in raw:
        return raw.casefold().rstrip("/")
    parsed = urlsplit(raw)
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    port = parsed.port
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if port is None or default else f"{host}:{port}"
    path = re.sub(r"/\d+(?=/|$)", "/{id}", parsed.path or "/")
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "/{uuid}", path, flags=re.I)
    return urlunsplit((scheme, netloc, path.rstrip("/") or "/", "", ""))


def _ratio(left: str | None, right: str | None) -> float:
    return SequenceMatcher(None, _normalize_text(left), _normalize_text(right), autojunk=False).ratio()


class DuplicateDetector:
    """Score exact/fuzzy duplicates without treating similarity as proof."""

    def __init__(self, database: Database, *, fuzzy_threshold: float = 0.72) -> None:
        if not 0.0 <= fuzzy_threshold <= 1.0:
            raise ValueError("fuzzy_threshold must be between 0 and 1")
        self.database = database
        self.fuzzy_threshold = fuzzy_threshold

    @staticmethod
    def similarity(candidate: Mapping[str, Any], existing: Mapping[str, Any]) -> float:
        """Return a weighted 0..1 duplicate similarity score."""
        title = _ratio(str(candidate.get("title") or ""), str(existing.get("title") or ""))
        vuln = _ratio(str(candidate.get("vuln_type") or ""), str(existing.get("vuln_type") or ""))
        endpoint_left = _canonical_endpoint(str(candidate.get("endpoint") or ""))
        endpoint_right = _canonical_endpoint(str(existing.get("endpoint") or ""))
        endpoint = 1.0 if endpoint_left and endpoint_left == endpoint_right else _ratio(endpoint_left, endpoint_right)
        description = _ratio(str(candidate.get("description") or ""), str(existing.get("description") or ""))
        return round((0.55 * title) + (0.20 * vuln) + (0.20 * endpoint) + (0.05 * description), 4)

    def internal(self, finding: Mapping[str, Any], *, target_id: int, limit: int = 25) -> list[DuplicateCandidate]:
        """Compare a proposed finding with local findings for the same target."""
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        title = str(finding.get("title") or "").strip()
        vuln_type = str(finding.get("vuln_type") or "informational").strip()
        endpoint = str(finding.get("endpoint") or "")
        if not title:
            raise ValueError("finding title is required")
        exact_fp = finding_fingerprint(target_id=target_id, title=title, vuln_type=vuln_type, endpoint=endpoint or None)
        existing = self.database.list_findings(target_id=target_id, limit=5000)
        matches: list[DuplicateCandidate] = []
        for item in existing:
            item_fp = str(item.get("fingerprint") or "")
            exact = item_fp == exact_fp
            score = 1.0 if exact else self.similarity(finding, item)
            if exact or score >= self.fuzzy_threshold:
                matches.append(
                    DuplicateCandidate(
                        source="internal",
                        identifier=str(item.get("id")),
                        title=str(item.get("title") or ""),
                        endpoint=str(item.get("endpoint") or ""),
                        vuln_type=str(item.get("vuln_type") or ""),
                        score=score,
                        exact=exact,
                    )
                )
        matches.sort(key=lambda item: (item.exact, item.score), reverse=True)
        return matches[:limit]

    @staticmethod
    def score_external(finding: Mapping[str, Any], reports: Sequence[Mapping[str, Any]], *, source: str, threshold: float = 0.72) -> list[DuplicateCandidate]:
        """Score normalized external reports already visible to the authenticated researcher."""
        matches: list[DuplicateCandidate] = []
        for report in reports:
            score = DuplicateDetector.similarity(finding, report)
            if score < threshold:
                continue
            matches.append(
                DuplicateCandidate(
                    source=source,
                    identifier=str(report.get("id") or report.get("identifier") or ""),
                    title=str(report.get("title") or ""),
                    endpoint=str(report.get("endpoint") or ""),
                    vuln_type=str(report.get("vuln_type") or ""),
                    score=score,
                    exact=False,
                    url=str(report.get("url")) if report.get("url") else None,
                    state=str(report.get("state")) if report.get("state") else None,
                )
            )
        return sorted(matches, key=lambda item: item.score, reverse=True)


class HackerOneDuplicateClient:
    """Compare against reports visible through the authenticated Hacker API account."""

    BASE_URL = "https://api.hackerone.com/v1/"

    def __init__(self, api_username: str, api_token: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 30.0) -> None:
        if not api_username or not api_token:
            raise ValueError("HackerOne API credentials are required")
        self.api_username = api_username
        self.api_token = api_token
        self.transport = transport
        self.timeout = timeout

    async def list_visible_reports(self, *, max_pages: int = 50) -> list[dict[str, Any]]:
        """Fetch researcher-visible reports; no inaccessible/private reports are inferred."""
        reports: list[dict[str, Any]] = []
        next_url: str | None = "hackers/me/reports"
        pages = 0
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL, auth=(self.api_username, self.api_token), headers={"Accept": "application/json"}, timeout=self.timeout, transport=self.transport) as client:
                while next_url:
                    pages += 1
                    if pages > max_pages:
                        raise DuplicateLookupError(f"HackerOne report pagination exceeded {max_pages} pages")
                    response = await client.get(next_url, params={"page[size]": 100} if pages == 1 else None)
                    response.raise_for_status()
                    payload = response.json()
                    for item in payload.get("data", []) if isinstance(payload, Mapping) else []:
                        if not isinstance(item, Mapping):
                            continue
                        attributes = item.get("attributes") or {}
                        if not isinstance(attributes, Mapping):
                            continue
                        reports.append({
                            "id": str(item.get("id") or ""),
                            "title": str(attributes.get("title") or ""),
                            "description": str(attributes.get("vulnerability_information") or ""),
                            "endpoint": str(attributes.get("weakness") or ""),
                            "vuln_type": str(attributes.get("weakness") or ""),
                            "state": str(attributes.get("state") or ""),
                            "url": f"https://hackerone.com/reports/{item.get('id')}" if item.get("id") else None,
                        })
                    links = payload.get("links") if isinstance(payload, Mapping) else None
                    next_value = links.get("next") if isinstance(links, Mapping) else None
                    next_url = str(next_value) if next_value else None
            return reports
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            raise DuplicateLookupError(f"HackerOne duplicate history lookup failed: {exc}") from exc


class BugcrowdDuplicateClient:
    """Compare against submissions visible to the authenticated Bugcrowd API token."""

    BASE_URL = "https://api.bugcrowd.com/"

    def __init__(self, token_username: str, token_password: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 30.0) -> None:
        if not token_username or not token_password:
            raise ValueError("Bugcrowd token credentials are required")
        self.headers = {
            "Accept": "application/vnd.bugcrowd+json",
            "Authorization": f"Token {token_username}:{token_password}",
        }
        self.transport = transport
        self.timeout = timeout

    async def list_visible_submissions(self, *, max_pages: int = 50) -> list[dict[str, Any]]:
        """Fetch API-visible submissions and normalize only fields present in responses."""
        reports: list[dict[str, Any]] = []
        next_url: str | None = "submissions"
        pages = 0
        try:
            async with httpx.AsyncClient(base_url=self.BASE_URL, headers=self.headers, timeout=self.timeout, transport=self.transport) as client:
                while next_url:
                    pages += 1
                    if pages > max_pages:
                        raise DuplicateLookupError(f"Bugcrowd submission pagination exceeded {max_pages} pages")
                    response = await client.get(next_url)
                    response.raise_for_status()
                    payload = response.json()
                    for item in payload.get("data", []) if isinstance(payload, Mapping) else []:
                        if not isinstance(item, Mapping):
                            continue
                        attributes = item.get("attributes") or {}
                        if not isinstance(attributes, Mapping):
                            continue
                        reports.append({
                            "id": str(item.get("id") or ""),
                            "title": str(attributes.get("title") or attributes.get("name") or ""),
                            "description": str(attributes.get("description") or attributes.get("vulnerability_details") or ""),
                            "endpoint": str(attributes.get("target") or ""),
                            "vuln_type": str(attributes.get("vrt_id") or attributes.get("vulnerability_type") or ""),
                            "state": str(attributes.get("state") or attributes.get("status") or ""),
                            "url": str((item.get("links") or {}).get("self") or "") if isinstance(item.get("links"), Mapping) else None,
                        })
                    links = payload.get("links") if isinstance(payload, Mapping) else None
                    next_value = links.get("next") if isinstance(links, Mapping) else None
                    next_url = str(next_value) if next_value else None
            return reports
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            raise DuplicateLookupError(f"Bugcrowd duplicate history lookup failed: {exc}") from exc


class DiscloseLookupClient:
    """Fetch disclose.io policy/routing context without claiming private duplicate visibility."""

    ENDPOINT = "https://lookup.disclose.io/api/lookup"

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 20.0) -> None:
        self.transport = transport
        self.timeout = timeout

    async def lookup(self, asset: str) -> DisclosureContext:
        """Resolve disclosure routing metadata for an asset via disclose.io lookup."""
        if not asset.strip():
            raise ValueError("asset is required")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                response = await client.post(self.ENDPOINT, json={"input": asset.strip()})
                response.raise_for_status()
                payload = response.json()
            if not isinstance(payload, Mapping):
                raise DuplicateLookupError("disclose.io returned a non-object response")
            contacts_value = payload.get("contacts") or []
            contacts: list[str] = []
            if isinstance(contacts_value, list):
                for item in contacts_value:
                    if isinstance(item, str):
                        contacts.append(item)
                    elif isinstance(item, Mapping):
                        value = item.get("value") or item.get("contact") or item.get("url") or item.get("email")
                        if value:
                            contacts.append(str(value))
            return DisclosureContext(
                asset=asset.strip(),
                duplicate_visibility_supported=False,
                route_class=str(payload.get("routeClass")) if payload.get("routeClass") else None,
                delivery_agent=str(payload.get("deliveryAgent")) if payload.get("deliveryAgent") else None,
                contacts=tuple(contacts),
                raw=dict(payload),
            )
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise DuplicateLookupError(f"disclose.io lookup failed: {exc}") from exc
