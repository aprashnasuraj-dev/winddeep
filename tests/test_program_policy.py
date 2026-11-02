"""Program-policy regression tests using a real-world Bugcrowd rules fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.programs.policy import ProgramPolicyViolation, ProgramTestingPolicy

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "programs" / "stonikbyte_bugcrowd.json"


def _raw_policy() -> dict:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return dict(payload["testing_requirements"])


def _policy() -> ProgramTestingPolicy:
    return ProgramTestingPolicy.from_mapping(_raw_policy()).bind({"bugcrowd_name": "researcher"})


def _metadata() -> dict[str, object]:
    return {
        "instance_owned": True,
        "program_app_context": "Great Gadgets for Jira Cloud",
        "latest_product_version": True,
    }


def test_fixture_compiles_operator_owned_instance_exactly() -> None:
    policy = _policy()
    assert policy.allowed_hosts == ("bugbounty-test-researcher.atlassian.net",)
    assert policy.allowed_host_templates == ()
    policy.assert_execution(
        "manual_interaction",
        target="https://bugbounty-test-researcher.atlassian.net",
        metadata=_metadata(),
    )


def test_marketplace_listing_is_not_a_test_target() -> None:
    policy = _policy()
    with pytest.raises(ProgramPolicyViolation, match="reporting/listing host"):
        policy.assert_execution(
            "manual_interaction",
            target="https://marketplace.atlassian.com/apps/1216564/great-gadgets-for-jira-cloud",
            metadata=_metadata(),
        )


def test_other_researcher_or_customer_instance_is_not_in_scope() -> None:
    policy = _policy()
    with pytest.raises(ProgramPolicyViolation, match="operator-bound"):
        policy.assert_execution(
            "manual_interaction",
            target="https://bugbounty-test-someone-else.atlassian.net",
            metadata=_metadata(),
        )


def test_program_blocks_automated_execution_but_keeps_local_workspace_capabilities() -> None:
    policy = _policy()
    with pytest.raises(ProgramPolicyViolation, match="automated tools/scanners"):
        policy.assert_execution(
            "automated_tool",
            target="https://bugbounty-test-researcher.atlassian.net",
            metadata=_metadata(),
        )

    for kind in ("local_analysis", "manual_guidance", "evidence", "reporting"):
        policy.assert_execution(kind)


def test_program_requires_owned_app_context_and_latest_version_for_target_interaction() -> None:
    policy = _policy()
    target = "https://bugbounty-test-researcher.atlassian.net"

    with pytest.raises(ProgramPolicyViolation, match="operator-owned"):
        policy.assert_execution("manual_interaction", target=target, metadata={})

    with pytest.raises(ProgramPolicyViolation, match="in-scope app"):
        policy.assert_execution(
            "manual_interaction",
            target=target,
            metadata={"instance_owned": True, "latest_product_version": True},
        )

    with pytest.raises(ProgramPolicyViolation, match="latest eligible product version"):
        policy.assert_execution(
            "manual_interaction",
            target=target,
            metadata={"instance_owned": True, "program_app_context": "app"},
        )


def test_unbound_operator_template_fails_closed() -> None:
    policy = ProgramTestingPolicy.from_mapping(_raw_policy())
    with pytest.raises(ProgramPolicyViolation, match="must be bound"):
        policy.assert_execution(
            "manual_interaction",
            target="https://bugbounty-test-researcher.atlassian.net",
            metadata=_metadata(),
        )


def test_no_pivoting_removes_chain_hints_and_blocks_pivot_execution() -> None:
    policy = _policy()
    assert policy.sanitize_chain_hints(["session", "object-ownership"]) == []
    with pytest.raises(ProgramPolicyViolation, match="pivoting/post-exploitation"):
        policy.assert_execution(
            "pivot",
            target="https://bugbounty-test-researcher.atlassian.net",
            metadata=_metadata(),
        )
