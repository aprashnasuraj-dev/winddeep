"""Tests for Windeep duplicate detection and external history adapters."""

from __future__ import annotations

import httpx
import pytest

from app.database import Database
from app.duplicates import BugcrowdDuplicateClient, DiscloseLookupClient, DuplicateDetector, HackerOneDuplicateClient


def test_internal_exact_fingerprint_is_top_match(tmp_path) -> None:
    db = Database(tmp_path / "windeep.db")
    target_id = db.create_target("Demo", "web", "example.com")
    finding_id, created = db.create_finding(target_id, "IDOR on invoice endpoint", "high", vuln_type="idor", endpoint="https://example.com/api/invoices/123")
    assert created
    detector = DuplicateDetector(db)
    matches = detector.internal({"title": "IDOR on invoice endpoint", "vuln_type": "idor", "endpoint": "https://example.com/api/invoices/123"}, target_id=target_id)
    assert matches[0].identifier == str(finding_id)
    assert matches[0].exact is True
    assert matches[0].score == 1.0


def test_fuzzy_duplicate_normalizes_numeric_object_ids(tmp_path) -> None:
    db = Database(tmp_path / "windeep.db")
    target_id = db.create_target("Demo", "web", "example.com")
    db.create_finding(target_id, "Horizontal access control issue in invoices", "high", vuln_type="idor", endpoint="https://example.com/api/invoices/123", description="User can read another invoice")
    detector = DuplicateDetector(db, fuzzy_threshold=0.6)
    matches = detector.internal({"title": "Horizontal access control issue in invoice", "vuln_type": "idor", "endpoint": "https://example.com/api/invoices/456", "description": "Another account invoice is readable"}, target_id=target_id)
    assert matches
    assert matches[0].exact is False
    assert matches[0].score >= 0.6


@pytest.mark.asyncio
async def test_hackerone_adapter_only_normalizes_visible_reports() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/hackers/me/reports")
        return httpx.Response(200, json={"data": [{"id": "42", "attributes": {"title": "Stored XSS in profile", "vulnerability_information": "profile bio reflection", "state": "triaged", "weakness": "CWE-79"}}], "links": {"next": None}})

    client = HackerOneDuplicateClient("user", "token", transport=httpx.MockTransport(handler))
    reports = await client.list_visible_reports()
    assert reports == [{"id": "42", "title": "Stored XSS in profile", "description": "profile bio reflection", "endpoint": "CWE-79", "vuln_type": "CWE-79", "state": "triaged", "url": "https://hackerone.com/reports/42"}]


@pytest.mark.asyncio
async def test_bugcrowd_adapter_normalizes_jsonapi_submission() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Token name:pass"
        return httpx.Response(200, json={"data": [{"id": "7", "attributes": {"title": "IDOR", "description": "object access", "target": "api.example.com", "vrt_id": "P2", "state": "unresolved"}, "links": {"self": "https://api.bugcrowd.com/submissions/7"}}], "links": {"next": None}})

    client = BugcrowdDuplicateClient("name", "pass", transport=httpx.MockTransport(handler))
    reports = await client.list_visible_submissions()
    assert reports[0]["id"] == "7"
    assert reports[0]["title"] == "IDOR"
    assert reports[0]["url"].endswith("/submissions/7")


@pytest.mark.asyncio
async def test_disclose_lookup_never_claims_duplicate_visibility() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "lookup.disclose.io"
        return httpx.Response(200, json={"routeClass": "first-party", "deliveryAgent": "example-platform", "contacts": [{"email": "security@example.com"}]})

    client = DiscloseLookupClient(transport=httpx.MockTransport(handler))
    result = await client.lookup("example.com")
    assert result.duplicate_visibility_supported is False
    assert result.route_class == "first-party"
    assert result.contacts == ("security@example.com",)


def test_external_scoring_orders_most_similar_first() -> None:
    finding = {"title": "IDOR in invoice API", "vuln_type": "idor", "endpoint": "https://example.com/api/invoices/99"}
    reports = [
        {"id": "1", "title": "Clickjacking", "vuln_type": "ui", "endpoint": "https://example.com/"},
        {"id": "2", "title": "IDOR in invoices API", "vuln_type": "idor", "endpoint": "https://example.com/api/invoices/55"},
    ]
    matches = DuplicateDetector.score_external(finding, reports, source="history", threshold=0.4)
    assert matches[0].identifier == "2"
    assert matches[0].score > matches[-1].score if len(matches) > 1 else True
