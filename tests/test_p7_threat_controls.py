"""P7 acceptance: controls required by the Windeep v3 platform threat model."""
from __future__ import annotations

import pytest

from app.security.v3_guardrails import V3ThreatControls


def test_target_ssrf_guard_blocks_loopback_and_local_control_plane() -> None:
    guard = V3ThreatControls()
    for url in (
        "http://127.0.0.1:7331/api/health",
        "http://localhost:7331/api/v2/scans",
        "http://[::1]:7331/",
    ):
        with pytest.raises(PermissionError):
            guard.assert_external_target(url)
    guard.assert_external_target("https://example.test/api")


def test_artifact_label_rejects_path_traversal_and_absolute_paths() -> None:
    guard = V3ThreatControls()
    assert guard.validate_artifact_label("response-body.json") == "response-body.json"
    for value in ("../secret.txt", "..\\secret.txt", "/tmp/x", "C:\\Windows\\x"):
        with pytest.raises(ValueError):
            guard.validate_artifact_label(value)


def test_redaction_terms_are_literal_bounded_and_cannot_be_regex_dos() -> None:
    guard = V3ThreatControls(max_redaction_terms=4, max_redaction_term_chars=32)
    values = guard.validate_redaction_terms(["(a+)+$", "token.*", "literal-secret"])
    assert values == ["(a+)+$", "token.*", "literal-secret"]
    assert all(not hasattr(item, "search") for item in values)
    with pytest.raises(ValueError):
        guard.validate_redaction_terms(["x" * 33])
    with pytest.raises(ValueError):
        guard.validate_redaction_terms(["a", "b", "c", "d", "e"])


def test_model_plan_is_data_only_and_cannot_directly_invoke_unapproved_tools() -> None:
    guard = V3ThreatControls()
    assert guard.validate_model_plan({"task_ids": ["stage:dedup", "stage:rank"]}, allowed_task_ids={"stage:dedup", "stage:rank"}) == ["stage:dedup", "stage:rank"]
    with pytest.raises(PermissionError):
        guard.validate_model_plan({"task_ids": ["tool:nuclei"]}, allowed_task_ids={"stage:dedup"})
    with pytest.raises(ValueError):
        guard.validate_model_plan({"shell": "curl http://127.0.0.1"}, allowed_task_ids=set())
