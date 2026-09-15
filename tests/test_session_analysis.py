"""Tests for Windeep session/token lifecycle analysis."""

from __future__ import annotations

import pytest

from app.auth.session_analysis import SessionToken, analyze_sessions


def test_cross_account_reuse_is_critical() -> None:
    result = analyze_sessions([SessionToken("a", "same"), SessionToken("b", "same")], now=1000)
    issues = {issue.code: issue for issue in result.issues}
    assert issues["session.cross_account_reuse"].severity == "critical"
    assert result.unique_fingerprints == 1


def test_repeated_login_with_same_token_flags_rotation() -> None:
    result = analyze_sessions([
        SessionToken("a", "same", authenticated_at=100),
        SessionToken("a", "same", authenticated_at=200),
    ], now=300)
    assert "session.rotation.possible_failure" in {issue.code for issue in result.issues}


def test_explicit_no_change_rotation_is_high() -> None:
    result = analyze_sessions([SessionToken("a", "token", rotated_from="token")], now=100)
    issues = {issue.code: issue for issue in result.issues}
    assert issues["session.rotation.no_change"].severity == "high"


def test_cookie_hardening_findings_are_reported() -> None:
    result = analyze_sessions([SessionToken("a", "token", cookie_flags={"secure": False, "httponly": False, "samesite": "none"})], now=100)
    codes = {issue.code for issue in result.issues}
    assert "cookie.secure.missing" in codes
    assert "cookie.httponly.missing" in codes
    assert "cookie.samesite_none_insecure" in codes


def test_long_lifetime_and_expired_token_are_reported() -> None:
    result = analyze_sessions([SessionToken("a", "token", issued_at=0, expires_at=31 * 24 * 60 * 60)], now=40 * 24 * 60 * 60)
    codes = {issue.code for issue in result.issues}
    assert "session.lifetime.long" in codes
    assert "session.expired.present" in codes


def test_empty_account_or_token_is_rejected() -> None:
    with pytest.raises(ValueError):
        analyze_sessions([SessionToken("", "token")])
    with pytest.raises(ValueError):
        analyze_sessions([SessionToken("a", "")])
