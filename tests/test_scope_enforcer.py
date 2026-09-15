"""Tests for Windeep scope enforcement."""

from __future__ import annotations

import pytest

from app.security.scope import ScopeEnforcer, ScopeViolation


def test_exact_target_is_default_scope() -> None:
    scope = ScopeEnforcer("example.com")
    assert scope.is_allowed("https://example.com/path")
    assert not scope.is_allowed("https://api.example.com/")


def test_wildcard_includes_subdomains_not_apex() -> None:
    scope = ScopeEnforcer("example.com", allow=["*.example.com"])
    assert scope.is_allowed("https://api.example.com/")
    assert scope.is_allowed("deep.api.example.com")
    assert not scope.is_allowed("example.com")


def test_cidr_allows_member_and_rejects_outside() -> None:
    scope = ScopeEnforcer("10.10.10.1", allow=["10.10.10.0/24"])
    assert scope.is_allowed("10.10.10.200")
    assert not scope.is_allowed("10.10.11.1")


def test_deny_rule_overrides_allow() -> None:
    scope = ScopeEnforcer("example.com", allow=["*.example.com"], deny=["admin.example.com"])
    assert scope.is_allowed("api.example.com")
    assert not scope.is_allowed("admin.example.com")


def test_assert_allowed_raises_for_out_of_scope() -> None:
    scope = ScopeEnforcer("example.com")
    with pytest.raises(ScopeViolation):
        scope.assert_allowed("not-example.test")
