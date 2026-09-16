from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from app.engine.tool_wrapper import ToolExecutionError, ToolWrapperFactory, _failure_outcome
from app.tools import builtin_integrations
from app.tools.backends import BackendUnavailableError


def test_backend_failure_outcomes_distinguish_missing_and_rejected() -> None:
    assert _failure_outcome(BackendUnavailableError("not installed")) == "MISSING"
    assert _failure_outcome(FileNotFoundError("missing")) == "MISSING"
    assert _failure_outcome(ToolExecutionError("compiler rejected input")) == "REJECTED"


def test_remix_alias_falls_back_when_hardhat_rejects_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    classes = ToolWrapperFactory(root / "tools_config.json").load()
    wrapper = classes["remix"](
        tools_dir=tmp_path,
        scope_validator=lambda value: value == "contract.sol",
    )
    wrapper.retries = 0

    hardhat = tmp_path / "npx"
    hardhat.write_text("hardhat-present", encoding="utf-8")
    monkeypatch.setattr(wrapper, "resolve_local_binary", lambda: hardhat)

    async def rejected_hardhat(argv: list[str], stdin_data=None):
        del stdin_data
        assert str(hardhat) == argv[0]
        assert "hardhat" in argv
        return "", "Error HHE4: Config file contract.sol not found", 1

    async def fallback_run(name: str, target: str, *, environment=None):
        del environment
        assert name == "remix"
        assert target == "contract.sol"
        return [
            {
                "title": "fallback-ok",
                "severity": "info",
                "vuln_type": "integration_result",
                "tool": "remix",
                "endpoint": target,
                "description": "builtin alias fallback",
                "evidence": {"fallback": "remix"},
                "confidence": 1.0,
            }
        ]

    monkeypatch.setattr(wrapper, "_run_process", rejected_hardhat)
    monkeypatch.setattr(builtin_integrations, "run", fallback_run)

    findings = asyncio.run(wrapper.run("contract.sol"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "remix"
    assert finding.title == "fallback-ok"
    assert finding.evidence["backend"] == "builtin_fallback"
    assert finding.evidence["backend_outcome"] == "OK"
    assert finding.evidence["served_by"] == "hardhat"
    assert finding.evidence["backend_fallbacks"][0]["backend"] == "local_binary"
    assert finding.evidence["backend_fallbacks"][0]["outcome"] == "REJECTED"
    assert "HHE4" in finding.evidence["backend_fallbacks"][0]["error"]
