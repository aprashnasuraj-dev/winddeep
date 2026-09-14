"""Tests for scan context scope semantics."""

from __future__ import annotations

import pytest

from app.engine.scan_context import ScanContext


def test_empty_scope_defaults_to_exact_target_host() -> None:
    ctx = ScanContext(target="https://example.com")
    assert ctx.is_in_scope("https://example.com/path")
    assert not ctx.is_in_scope("https://api.example.com")


def test_wildcard_scope_allows_subdomains_but_not_apex() -> None:
    ctx = ScanContext(target="example.com", scope=["*.example.com"])
    assert ctx.is_in_scope("https://api.example.com/v1")
    assert not ctx.is_in_scope("https://example.com")


def test_out_of_scope_rule_takes_precedence() -> None:
    ctx = ScanContext(
        target="example.com",
        scope=["*.example.com", "example.com"],
        out_of_scope=["admin.example.com"],
    )
    assert not ctx.is_in_scope("https://admin.example.com")
    assert ctx.is_in_scope("https://api.example.com")


def test_url_path_scope_is_prefix_bounded() -> None:
    ctx = ScanContext(target="example.com", scope=["https://example.com/api"])
    assert ctx.is_in_scope("https://example.com/api/users")
    assert not ctx.is_in_scope("https://example.com/apix")


def test_require_in_scope_raises_permission_error() -> None:
    ctx = ScanContext(target="example.com")
    with pytest.raises(PermissionError):
        ctx.require_in_scope("evil.example.net")


def test_redacted_snapshot_excludes_auth_values_and_proxy_password() -> None:
    ctx = ScanContext(
        target="example.com",
        auth_tokens={"session": "secret-value"},
        proxy_config={"url": "http://127.0.0.1:8080", "password": "hidden"},
    )
    snapshot = ctx.redacted_snapshot()
    assert snapshot["auth_token_names"] == ["session"]
    assert "secret-value" not in repr(snapshot)
    assert "password" not in snapshot["proxy_config"]
