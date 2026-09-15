"""Tests for Windeep signed authorization consent."""

from __future__ import annotations

import json
import time

import pytest

from app.security.consent import ConsentAuthority, ConsentError
from app.security.crypto import FileProtector
from app.security.scope import ScopeEnforcer


def _authority(tmp_path) -> ConsentAuthority:
    return ConsentAuthority(tmp_path / "consent", protector=FileProtector(tmp_path / "master.key"))


def test_issue_and_verify_live_consent(tmp_path) -> None:
    authority = _authority(tmp_path)
    scope = ScopeEnforcer("example.com", allow=["example.com", "*.example.com"])
    record = authority.issue(scope, authorized_by="owner", purpose="authorized testing", ttl_seconds=600)
    verified = authority.verify(record.id, scope)
    assert verified.id == record.id
    assert verified.active


def test_consent_is_bound_to_exact_scope(tmp_path) -> None:
    authority = _authority(tmp_path)
    original = ScopeEnforcer("example.com", allow=["example.com"])
    changed = ScopeEnforcer("example.com", allow=["example.com", "*.example.com"])
    record = authority.issue(original, authorized_by="owner", purpose="authorized testing", ttl_seconds=600)
    with pytest.raises(ConsentError):
        authority.verify(record.id, changed)


def test_explicit_scope_consent_can_authorize_an_allowed_candidate(tmp_path) -> None:
    authority = _authority(tmp_path)
    program_scope = ScopeEnforcer(
        "example.com",
        allow=["example.com", "*.example.com"],
        deny=["admin.example.com"],
    )
    candidate_scope = ScopeEnforcer(
        "https://api.example.com/path",
        allow=["example.com", "*.example.com"],
        deny=["admin.example.com"],
    )
    record = authority.issue(program_scope, authorized_by="owner", purpose="authorized testing", ttl_seconds=600)
    verified = authority.verify(record.id, candidate_scope)
    assert verified.id == record.id
    candidate_scope.assert_allowed("https://api.example.com/path")


def test_target_only_consent_remains_bound_to_exact_target(tmp_path) -> None:
    authority = _authority(tmp_path)
    original = ScopeEnforcer("example.com")
    changed = ScopeEnforcer("api.example.com")
    record = authority.issue(original, authorized_by="owner", purpose="authorized testing", ttl_seconds=600)
    with pytest.raises(ConsentError):
        authority.verify(record.id, changed)


def test_modified_record_fails_signature(tmp_path) -> None:
    authority = _authority(tmp_path)
    scope = ScopeEnforcer("example.com")
    record = authority.issue(scope, authorized_by="owner", purpose="authorized testing", ttl_seconds=600)
    path = authority.directory / f"{record.id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["purpose"] = "modified"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConsentError):
        authority.verify(record.id, scope)


def test_expired_record_is_rejected(tmp_path, monkeypatch) -> None:
    authority = _authority(tmp_path)
    scope = ScopeEnforcer("example.com")
    record = authority.issue(scope, authorized_by="owner", purpose="authorized testing", ttl_seconds=60)
    monkeypatch.setattr(time, "time", lambda: record.expires_at + 1)
    with pytest.raises(ConsentError):
        authority.verify(record.id, scope)


def test_ttl_bounds_are_enforced(tmp_path) -> None:
    authority = _authority(tmp_path)
    with pytest.raises(ValueError):
        authority.issue(ScopeEnforcer("example.com"), authorized_by="owner", purpose="test", ttl_seconds=1)
