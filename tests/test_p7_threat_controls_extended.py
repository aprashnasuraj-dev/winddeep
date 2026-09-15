"""Additional P7 trust-boundary tests."""
from __future__ import annotations

import pytest

from app.security.v3_guardrails import V3ThreatControls


def test_external_target_rejects_non_http_link_local_and_unspecified() -> None:
    guard = V3ThreatControls()
    for value in ("file:///etc/passwd", "http://0.0.0.0/", "http://169.254.169.254/latest", "http://[fe80::1]/"):
        with pytest.raises(PermissionError):
            guard.assert_external_target(value)


def test_tool_output_is_data_only_bounded_and_never_evaluated() -> None:
    guard = V3ThreatControls()
    value = {"payload": "__import__('os').system('whoami')", "nested": [1, {"shell": "not executable"}]}
    assert guard.validate_tool_output(value) == value
    with pytest.raises(ValueError):
        guard.validate_tool_output({"x": "a" * 20}, max_text_chars=10)
    with pytest.raises(ValueError):
        guard.validate_tool_output([1, 2, 3], max_items=2)


def test_model_plan_deduplicates_only_preapproved_task_ids() -> None:
    guard = V3ThreatControls()
    assert guard.validate_model_plan(
        {"task_ids": ["stage:rank", "stage:rank", "stage:report"]},
        allowed_task_ids={"stage:rank", "stage:report"},
    ) == ["stage:rank", "stage:report"]
