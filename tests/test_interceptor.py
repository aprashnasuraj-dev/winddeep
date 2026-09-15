"""Tests for Windeep capture interception rules."""

from __future__ import annotations

import pytest

from app.capture.interceptor import Interceptor, InterceptorRule


def sample_flow() -> dict[str, object]:
    return {
        "method": "POST",
        "url": "https://api.example.com/v1/items?id=7",
        "host": "api.example.com",
        "path": "/v1/items",
        "request_headers": {"Accept": "application/json"},
        "request_body": b'{"marker":"one"}',
        "tags": ["captured"],
    }


def test_modify_rule_updates_headers_query_body_and_tags() -> None:
    rule = InterceptorRule(
        name="bounded-modifier",
        action="modify",
        host="*.example.com",
        path="/v1/*",
        method="POST",
        set_headers={"X-Windeep": "1"},
        set_params={"id": "8"},
        body='{"marker":"two"}',
        tags=("modified",),
    )
    decision = Interceptor([rule], scope_validator=lambda _: True).evaluate(sample_flow())
    assert decision.action == "modify"
    assert decision.headers["X-Windeep"] == "1"
    assert "id=8" in decision.url
    assert decision.body == b'{"marker":"two"}'
    assert decision.tags == ["captured", "modified"]


def test_regex_and_method_must_both_match() -> None:
    matching = InterceptorRule(
        name="regex",
        action="tag",
        host="api.example.com",
        method="POST",
        regex=r'"marker":"one"',
        tags=("matched",),
    )
    wrong_method = InterceptorRule(
        name="wrong-method",
        action="drop",
        host="api.example.com",
        method="GET",
    )
    decision = Interceptor([matching, wrong_method], scope_validator=lambda _: True).evaluate(sample_flow())
    assert decision.tags[-1] == "matched"
    assert decision.dropped is False
    assert decision.matched_rules == ["regex"]


def test_drop_stops_later_rules() -> None:
    rules = [
        InterceptorRule(name="drop-now", action="drop", host="api.example.com"),
        InterceptorRule(name="never-reached", action="tag", tags=("late",)),
    ]
    decision = Interceptor(rules, scope_validator=lambda _: True).evaluate(sample_flow())
    assert decision.dropped is True
    assert decision.action == "drop"
    assert decision.matched_rules == ["drop-now"]
    assert "late" not in decision.tags


def test_replay_action_sets_directive_without_network_side_effect() -> None:
    rule = InterceptorRule(name="queue-replay", action="replay", host="api.example.com")
    decision = Interceptor([rule], scope_validator=lambda _: True).evaluate(sample_flow())
    assert decision.replay_requested is True
    assert decision.action == "replay"


def test_out_of_scope_flow_is_never_mutated() -> None:
    rule = InterceptorRule(
        name="would-modify",
        action="modify",
        set_headers={"X-Windeep": "1"},
        set_params={"id": "99"},
    )
    decision = Interceptor([rule], scope_validator=lambda _: False).evaluate(sample_flow())
    assert decision.out_of_scope is True
    assert decision.action == "forward"
    assert decision.matched_rules == []
    assert "X-Windeep" not in decision.headers
    assert "id=7" in decision.url


def test_missing_scope_validator_defaults_to_non_interception() -> None:
    rule = InterceptorRule(name="drop", action="drop")
    decision = Interceptor([rule], scope_validator=None).evaluate(sample_flow())
    assert decision.out_of_scope is True
    assert decision.dropped is False


def test_add_and_remove_rule_are_ordered() -> None:
    interceptor = Interceptor(scope_validator=lambda _: True)
    interceptor.add_rule(InterceptorRule(name="first", action="tag", tags=("one",)))
    interceptor.add_rule(InterceptorRule(name="second", action="tag", tags=("two",)))
    assert interceptor.remove_rule("first") is True
    assert interceptor.remove_rule("missing") is False
    decision = interceptor.evaluate(sample_flow())
    assert decision.matched_rules == ["second"]
    assert decision.tags[-1] == "two"


def test_invalid_rule_definition_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported interceptor action"):
        InterceptorRule(name="bad", action="explode")  # type: ignore[arg-type]
    with pytest.raises(Exception):
        InterceptorRule(name="bad-regex", action="tag", regex="[")
