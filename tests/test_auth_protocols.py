"""Tests for Windeep JWT, OAuth/OIDC, and SAML analyzers."""

from __future__ import annotations

import base64
import json

import pytest

from app.auth.protocols import ProtocolAnalysisError, analyze_jwt, analyze_oauth, analyze_saml


def _segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(header: dict, claims: dict) -> str:
    return f"{_segment(header)}.{_segment(claims)}.signature"


def test_jwt_none_algorithm_and_missing_claims_are_reported() -> None:
    result = analyze_jwt(_jwt({"alg": "none"}, {"sub": "1"}), now=1000)
    codes = {issue.code for issue in result.issues}
    assert "jwt.alg.none" in codes
    assert "jwt.exp.missing" in codes
    assert "jwt.aud.missing" in codes
    assert "jwt.iss.missing" in codes


def test_jwt_expected_issuer_and_audience_are_bound() -> None:
    result = analyze_jwt(_jwt({"alg": "RS256"}, {"iss": "wrong", "aud": "other", "iat": 900, "exp": 1100}), now=1000, expected_issuer="issuer", expected_audience="api")
    codes = {issue.code for issue in result.issues}
    assert "jwt.iss.mismatch" in codes
    assert "jwt.aud.mismatch" in codes
    assert result.lifetime_seconds == 200


def test_jwt_rejects_malformed_compact_form() -> None:
    with pytest.raises(ProtocolAnalysisError):
        analyze_jwt("not.a.jwt.with.too.many.parts")


def test_oauth_code_flow_detects_state_nonce_and_pkce_gaps() -> None:
    result = analyze_oauth({"response_type": "code", "scope": "openid profile", "redirect_uri": "http://example.com/cb"})
    codes = {issue.code for issue in result.issues}
    assert {"oauth.state.missing", "oidc.nonce.missing", "oauth.pkce.missing", "oauth.redirect.http"}.issubset(codes)


def test_oauth_s256_pkce_avoids_pkce_findings() -> None:
    result = analyze_oauth("response_type=code&state=s&code_challenge=abc&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fexample.com%2Fcb")
    codes = {issue.code for issue in result.issues}
    assert "oauth.pkce.missing" not in codes
    assert "oauth.pkce.weak_method" not in codes


def test_saml_unsigned_response_is_critical() -> None:
    xml = """<Response InResponseTo="req"><Issuer>https://idp.example</Issuer><Assertion><AudienceRestriction><Audience>sp</Audience></AudienceRestriction><Subject><SubjectConfirmation><SubjectConfirmationData Recipient="https://sp.example/acs"/></SubjectConfirmation></Subject></Assertion></Response>"""
    result = analyze_saml(xml, expected_audience="sp", expected_recipient="https://sp.example/acs")
    codes = {issue.code for issue in result.issues}
    assert "saml.signature.missing" in codes
    assert "saml.audience.mismatch" not in codes
    assert result.recipient == "https://sp.example/acs"


def test_saml_rejects_dtd_entity_input() -> None:
    with pytest.raises(ProtocolAnalysisError, match="DTD/entity"):
        analyze_saml("<!DOCTYPE foo [<!ENTITY x 'y'>]><Response>&x;</Response>")
