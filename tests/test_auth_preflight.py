"""Tests for local auth and mandatory Windeep pre-flight authorization."""

from __future__ import annotations

import json

import pytest

from app.security.audit import AuditLog
from app.security.auth import AuthenticationError, LocalAuthManager
from app.security.consent import ConsentAuthority
from app.security.crypto import CryptoManager, FileProtector
from app.security.preflight import PreFlightError, PreFlightGuard
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer, ScopeViolation


def _parts(tmp_path):
    protector = FileProtector(tmp_path / "master.key")
    crypto = CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=protector)
    auth = LocalAuthManager(protector=protector, ttl_seconds=600)
    consent = ConsentAuthority(tmp_path / "consent", protector=protector)
    audit = AuditLog(tmp_path / "audit.jsonl")
    scope = ScopeEnforcer("example.com", allow=["example.com", "*.example.com"], deny=["admin.example.com"])
    governor = RateGovernor(global_policy=RatePolicy(100, 10), default_key_policy=RatePolicy(100, 10))
    guard = PreFlightGuard(scope=scope, rate_governor=governor, consent=consent, crypto=crypto, audit=audit)
    return auth, consent, audit, scope, guard


def test_session_and_csrf_round_trip(tmp_path) -> None:
    auth, *_ = _parts(tmp_path)
    token, csrf, claims = auth.issue()
    verified = auth.validate(token)
    auth.validate_csrf(verified, csrf)
    assert verified.sid == claims.sid


def test_bad_csrf_is_rejected(tmp_path) -> None:
    auth, *_ = _parts(tmp_path)
    token, _, _ = auth.issue()
    claims = auth.validate(token)
    with pytest.raises(AuthenticationError):
        auth.validate_csrf(claims, "wrong")


def test_preflight_authorizes_live_signed_consent(tmp_path) -> None:
    _, consent, audit, scope, guard = _parts(tmp_path)
    record = consent.issue(scope, authorized_by="owner", purpose="authorized bug bounty", ttl_seconds=600)
    verified = guard.authorize_scan(target="https://api.example.com/path", consent_id=record.id)
    assert verified.id == record.id
    assert audit.verify_chain()[1] == 1


def test_preflight_rejects_out_of_scope_even_with_consent_and_audits_denial(tmp_path) -> None:
    _, consent, audit, scope, guard = _parts(tmp_path)
    record = consent.issue(scope, authorized_by="owner", purpose="authorized bug bounty", ttl_seconds=600)
    with pytest.raises(ScopeViolation):
        guard.authorize_scan(target="https://outside.test", consent_id=record.id)
    valid, count = audit.verify_chain()
    assert valid is True
    assert count == 1
    event = json.loads(audit.path.read_text(encoding="utf-8").strip())
    assert event["event"] == "scan.denied"
    assert event["data"]["reason"] == "ScopeViolation"


def test_unhealthy_audit_blocks_preflight(tmp_path) -> None:
    _, consent, audit, scope, guard = _parts(tmp_path)
    record = consent.issue(scope, authorized_by="owner", purpose="authorized bug bounty", ttl_seconds=600)
    audit.path.write_text("corrupt\n", encoding="utf-8")
    with pytest.raises(PreFlightError):
        guard.authorize_scan(target="example.com", consent_id=record.id)
