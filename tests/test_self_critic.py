"""Tests for the Windeep Brain self-critic quality gate."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.brain.self_critic import SelfCritic
from app.engine.scan_context import ScanContext


class FakeLLM:
    """LLM stub that records whether model review was reached."""

    def __init__(self, response: Any = None) -> None:
        self.response = response
        self.calls = 0
        self.prompts: list[str] = []

    async def complete_json(self, prompt: str, *, system: str = "", heuristic=None) -> Any:
        self.calls += 1
        self.prompts.append(prompt)
        return self.response if self.response is not None else heuristic()


class RecordingBus:
    """Records critic events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((topic, payload))


def valid_finding() -> dict[str, Any]:
    return {
        "id": 11,
        "title": "Verified access-control inconsistency",
        "endpoint": "https://example.com/api/object/11",
        "tool": "manual",
        "evidence": {"comparison": "authorized account behavior differs"},
        "verified": True,
        "impact": "An equivalent authorized account could read a record assigned to the first test account.",
        "status": "new",
    }


@pytest.mark.asyncio
async def test_rejects_out_of_scope_before_model_call() -> None:
    llm = FakeLLM()
    critic = SelfCritic(llm)
    finding = valid_finding()
    finding["endpoint"] = "https://outside.example.net/api/object/11"
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await critic.evaluate(finding, ctx)

    assert result.decision == "FAIL"
    assert any("outside configured scope" in reason for reason in result.reasons)
    assert llm.calls == 0


@pytest.mark.asyncio
async def test_rejects_scanner_only_unverified_result() -> None:
    llm = FakeLLM()
    critic = SelfCritic(llm)
    finding = valid_finding()
    finding.update({"tool": "scanner-x", "verified": False})
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await critic.evaluate(finding, ctx)

    assert result.decision == "FAIL"
    assert any("not independently verified" in reason for reason in result.reasons)


@pytest.mark.asyncio
async def test_rejects_missing_evidence_and_impact() -> None:
    critic = SelfCritic(FakeLLM())
    finding = valid_finding()
    finding["evidence"] = {}
    finding["impact"] = ""
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await critic.evaluate(finding, ctx)

    assert result.decision == "FAIL"
    assert any("No concrete" in reason for reason in result.reasons)
    assert any("Impact is missing" in reason for reason in result.reasons)
    assert len(result.missing_evidence) >= 2


@pytest.mark.asyncio
async def test_rejects_speculative_impact_when_unverified() -> None:
    critic = SelfCritic(FakeLLM())
    finding = valid_finding()
    finding.update(
        {
            "tool": "manual",
            "verified": False,
            "impact": "This could lead to account takeover.",
        }
    )
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await critic.evaluate(finding, ctx)

    assert result.decision == "FAIL"
    assert any("speculative" in reason for reason in result.reasons)


@pytest.mark.asyncio
async def test_verified_finding_reaches_model_and_can_pass() -> None:
    llm = FakeLLM(
        {
            "decision": "PASS",
            "reasons": ["Evidence and impact are appropriately bounded."],
            "missing_evidence": [],
            "confidence": 0.93,
        }
    )
    bus = RecordingBus()
    critic = SelfCritic(llm, event_bus=bus)  # type: ignore[arg-type]
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await critic.evaluate(valid_finding(), ctx, scan_id=3)

    assert result.decision == "PASS"
    assert llm.calls == 1
    assert bus.events[-1][0] == "brain.critic"
    assert bus.events[-1][1]["scan_id"] == 3


@pytest.mark.asyncio
async def test_prompt_schema_braces_are_preserved() -> None:
    llm = FakeLLM(
        {"decision": "PASS", "reasons": [], "missing_evidence": [], "confidence": 0.8}
    )
    critic = SelfCritic(llm)
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    await critic.evaluate(valid_finding(), ctx)

    assert '"decision": "PASS|FAIL"' in llm.prompts[0]
    assert "{context_json}" not in llm.prompts[0]


@pytest.mark.asyncio
async def test_invalid_model_response_falls_back_to_deterministic_pass() -> None:
    llm = FakeLLM({"decision": "MAYBE", "confidence": 2})
    critic = SelfCritic(llm)
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await critic.evaluate(valid_finding(), ctx)

    assert result.decision == "PASS"
    assert result.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_cancellation_propagates() -> None:
    class CancelLLM(FakeLLM):
        async def complete_json(self, prompt: str, *, system: str = "", heuristic=None) -> Any:
            raise asyncio.CancelledError

    critic = SelfCritic(CancelLLM())
    ctx = ScanContext(target="https://example.com", scope=["example.com"])
    with pytest.raises(asyncio.CancelledError):
        await critic.evaluate(valid_finding(), ctx)
