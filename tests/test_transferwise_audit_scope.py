"""Regression tests for the TransferWise GitHub program audit guardrails."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit" / "transferwise_org_audit.py"
CONFIG = ROOT / "config" / "programs" / "transferwise_github.json"

spec = importlib.util.spec_from_file_location("transferwise_org_audit", SCRIPT)
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_transferwise_repo_is_in_scope() -> None:
    assert audit.assert_repo_in_scope("https://github.com/transferwise/idempotence4j", config()) == "transferwise/idempotence4j"


def test_pipelinewise_is_explicitly_excluded() -> None:
    with pytest.raises(ValueError, match="explicitly excluded"):
        audit.assert_repo_in_scope("transferwise/pipelinewise", config())


def test_repo_outside_transferwise_is_rejected() -> None:
    with pytest.raises(ValueError, match="out of scope"):
        audit.assert_repo_in_scope("other-org/project", config())


def test_placeholder_and_sample_secret_are_suppressed(tmp_path: Path) -> None:
    sample = Path("tests/fixtures/config.yml")
    assert audit.placeholder_secret("changeit", sample, 'password: "changeit"')
    assert audit.placeholder_secret("sample-value", sample, 'api_key: "sample-value"')


def test_non_placeholder_secret_is_only_a_candidate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('client_secret = "A1-real-looking-value-998877"\n', encoding="utf-8")
    candidates = audit.scan_repo("transferwise/example", repo, "abc123", config())
    assert len(candidates) == 1
    assert candidates[0].detector == "hardcoded-secret-candidate"
    assert candidates[0].reportable is False


def test_scanner_candidate_cannot_pass_without_specific_proof() -> None:
    candidate = {
        "repo": "transferwise/example",
        "detector": "workflow-write-all",
        "wise_specific_review_required": False,
    }
    ok, reasons = audit.validate_candidate(candidate, {}, config())
    assert not ok
    assert any("specific_poc" in reason for reason in reasons)
    assert any("duplicate_reviewed" in reason for reason in reasons)


def test_third_party_candidate_requires_wise_specific_proof() -> None:
    candidate = {
        "repo": "transferwise/example",
        "detector": "unsafe-yaml-load-review",
        "wise_specific_review_required": True,
    }
    proof = {
        "reproduced": True,
        "impact_demonstrated": True,
        "specific_poc": True,
        "duplicate_reviewed": True,
        "poc_steps": "minimal safe reproduction",
        "impact": "specific Wise impact",
    }
    ok, reasons = audit.validate_candidate(candidate, proof, config())
    assert not ok
    assert "wise_specific=true is required for third-party/fork-derived code" in reasons


def test_credential_candidate_requires_manual_program_evidence() -> None:
    candidate = {
        "repo": "transferwise/example",
        "detector": "hardcoded-secret-candidate",
        "wise_specific_review_required": False,
    }
    proof = {
        "reproduced": True,
        "impact_demonstrated": True,
        "specific_poc": True,
        "duplicate_reviewed": True,
        "wise_owned_credential_or_key": True,
        "poc_steps": "manual program-compliant check",
        "impact": "internal access demonstrated manually",
    }
    ok, reasons = audit.validate_candidate(candidate, proof, config())
    assert not ok
    assert any("manual program-compliant evidence" in reason for reason in reasons)
