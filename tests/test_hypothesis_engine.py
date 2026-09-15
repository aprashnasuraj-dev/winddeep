"""Tests for Windeep Brain hypothesis generation."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.brain.hypothesis_engine import HypothesisEngine
from app.database import Database
from app.engine.scan_context import ScanContext


class FakeLLM:
    """Minimal LLM stub used to drive deterministic test responses."""

    def __init__(self, response: Any = None, *, use_heuristic: bool = False) -> None:
        self.response = response
        self.use_heuristic = use_heuristic
        self.prompts: list[str] = []

    async def complete_json(self, prompt: str, *, system: str = "", heuristic=None) -> Any:
        self.prompts.append(prompt)
        if self.use_heuristic:
            return heuristic()
        return self.response


class RecordingBus:
    """Event bus test double that records publications."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((topic, payload))


@pytest.mark.asyncio
async def test_generates_and_normalizes_relative_endpoint() -> None:
    llm = FakeLLM(
        {
            "hypotheses": [
                {
                    "id": "h1",
                    "test_class": "authorization",
                    "endpoint": "/api/items/7",
                    "parameters": {"id": "object identifier"},
                    "rationale": "Object reference appears in an authenticated API route.",
                    "confidence": 0.8,
                    "severity_hint": "high",
                    "chain_hints": ["session"],
                }
            ]
        }
    )
    bus = RecordingBus()
    engine = HypothesisEngine(llm, bus)  # type: ignore[arg-type]
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    result = await engine.generate([], ctx, scan_id=7)

    assert len(result) == 1
    assert result[0].endpoint == "https://example.com/api/items/7"
    assert ctx.hypotheses == result
    assert bus.events[-1][0] == "brain.hypotheses_generated"


@pytest.mark.asyncio
async def test_out_of_scope_hypothesis_is_dropped() -> None:
    llm = FakeLLM(
        {
            "hypotheses": [
                {
                    "id": "h1",
                    "test_class": "configuration",
                    "endpoint": "https://outside.example.net/status",
                    "parameters": {},
                    "rationale": "Model proposed an unrelated host.",
                    "confidence": 0.9,
                    "severity_hint": "medium",
                    "chain_hints": [],
                }
            ]
        }
    )
    ctx = ScanContext(target="https://example.com", scope=["example.com"])
    engine = HypothesisEngine(llm, RecordingBus())  # type: ignore[arg-type]

    assert await engine.generate([], ctx) == []


@pytest.mark.asyncio
async def test_rule_fallback_generates_authorization_hypothesis() -> None:
    llm = FakeLLM(use_heuristic=True)
    engine = HypothesisEngine(llm, RecordingBus())  # type: ignore[arg-type]
    ctx = ScanContext(target="https://example.com", scope=["example.com"])
    findings = [
        {
            "id": 1,
            "title": "Possible IDOR",
            "vuln_type": "idor",
            "endpoint": "https://example.com/api/orders/1",
        }
    ]

    result = await engine.generate(findings, ctx)

    assert len(result) == 1
    assert result[0].test_class == "authorization"
    assert result[0].source == "rule-based"
    assert result[0].confidence == pytest.approx(0.78)


@pytest.mark.asyncio
async def test_invalid_model_items_are_ignored() -> None:
    llm = FakeLLM(
        {
            "hypotheses": [
                {"id": "missing-required-fields"},
                {
                    "id": "bad-severity",
                    "test_class": "other",
                    "endpoint": "https://example.com",
                    "parameters": {},
                    "rationale": "x",
                    "confidence": 0.4,
                    "severity_hint": "catastrophic",
                    "chain_hints": [],
                },
            ]
        }
    )
    engine = HypothesisEngine(llm, RecordingBus())  # type: ignore[arg-type]
    ctx = ScanContext(target="example.com")

    assert await engine.generate([], ctx) == []


@pytest.mark.asyncio
async def test_hypothesis_is_persisted(tmp_path: Path) -> None:
    db = Database(tmp_path / "brain.db")
    target_id = db.create_target("Example", "web", "https://example.com")
    llm = FakeLLM(
        {
            "hypotheses": [
                {
                    "id": "persist-me",
                    "test_class": "configuration",
                    "endpoint": "https://example.com/health",
                    "parameters": {},
                    "rationale": "A configuration signal needs bounded verification.",
                    "confidence": 0.64,
                    "severity_hint": "low",
                    "chain_hints": [],
                }
            ]
        }
    )
    engine = HypothesisEngine(llm, RecordingBus(), database=db)  # type: ignore[arg-type]
    ctx = ScanContext(target="https://example.com", scope=["example.com"])

    await engine.generate([], ctx, target_id=target_id)

    rows = db.list_hypotheses(target_id=target_id)
    assert len(rows) == 1
    assert rows[0]["id"] == "persist-me"
    assert rows[0]["confidence"] == pytest.approx(0.64)


@pytest.mark.asyncio
async def test_prompt_preserves_json_schema_braces() -> None:
    llm = FakeLLM({"hypotheses": []})
    engine = HypothesisEngine(llm, RecordingBus())  # type: ignore[arg-type]
    ctx = ScanContext(target="example.com")

    await engine.generate([], ctx)

    assert '"hypotheses": [' in llm.prompts[0]
    assert "{context_json}" not in llm.prompts[0]


@pytest.mark.asyncio
async def test_cancellation_propagates() -> None:
    class CancelLLM(FakeLLM):
        async def complete_json(self, prompt: str, *, system: str = "", heuristic=None) -> Any:
            raise asyncio.CancelledError

    engine = HypothesisEngine(CancelLLM(), RecordingBus())  # type: ignore[arg-type]
    with pytest.raises(asyncio.CancelledError):
        await engine.generate([], ScanContext(target="example.com"))
