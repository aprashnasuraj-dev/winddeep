"""Tests for Windeep Brain finding-chain construction."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.brain.chain_builder import ChainBuilder, ChainEdge
from app.database import Database


class FakeLLM:
    """LLM stub for chain-builder tests."""

    def __init__(self, response: Any = None, *, use_heuristic: bool = False) -> None:
        self.response = response
        self.use_heuristic = use_heuristic
        self.prompts: list[str] = []

    async def complete_json(self, prompt: str, *, system: str = "", heuristic=None) -> Any:
        self.prompts.append(prompt)
        return heuristic() if self.use_heuristic else self.response


class RecordingBus:
    """Records event publications for assertions."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((topic, payload))


@pytest.mark.asyncio
async def test_build_accepts_known_finding_ids_only() -> None:
    llm = FakeLLM(
        {
            "edges": [
                {
                    "source_finding_id": 1,
                    "target_finding_id": 2,
                    "edge_type": "enables",
                    "weight": 0.8,
                    "rationale": "supported",
                },
                {
                    "source_finding_id": 1,
                    "target_finding_id": 999,
                    "edge_type": "enables",
                    "weight": 0.9,
                    "rationale": "unknown node",
                },
            ]
        }
    )
    bus = RecordingBus()
    builder = ChainBuilder(llm, bus)  # type: ignore[arg-type]
    findings = [{"id": 1, "title": "A"}, {"id": 2, "title": "B"}]

    edges = await builder.build(findings, scan_id=10)

    assert [(edge.source_finding_id, edge.target_finding_id) for edge in edges] == [(1, 2)]
    assert bus.events[-1][0] == "brain.chains_built"


@pytest.mark.asyncio
async def test_self_edges_and_duplicates_are_removed() -> None:
    duplicate = {
        "source_finding_id": 1,
        "target_finding_id": 2,
        "edge_type": "corroborates",
        "weight": 0.5,
        "rationale": "same logical edge",
    }
    llm = FakeLLM(
        {
            "edges": [
                {
                    "source_finding_id": 1,
                    "target_finding_id": 1,
                    "edge_type": "enables",
                    "weight": 0.9,
                    "rationale": "self",
                },
                duplicate,
                duplicate,
            ]
        }
    )
    builder = ChainBuilder(llm, RecordingBus())  # type: ignore[arg-type]

    edges = await builder.build([{"id": 1}, {"id": 2}])

    assert len(edges) == 1
    assert edges[0].edge_type == "corroborates"


@pytest.mark.asyncio
async def test_rule_fallback_links_info_disclosure_to_idor() -> None:
    builder = ChainBuilder(FakeLLM(use_heuristic=True), RecordingBus())  # type: ignore[arg-type]
    findings = [
        {"id": 1, "title": "Information disclosure", "vuln_type": "information disclosure"},
        {"id": 2, "title": "Object authorization", "vuln_type": "idor"},
    ]

    edges = await builder.build(findings)

    assert len(edges) == 1
    assert edges[0].source_finding_id == 1
    assert edges[0].target_finding_id == 2
    assert edges[0].source == "rule-based"


def test_find_paths_is_acyclic_and_multiplies_weights() -> None:
    builder = ChainBuilder(FakeLLM(), RecordingBus())  # type: ignore[arg-type]
    edges = [
        ChainEdge(source_finding_id=1, target_finding_id=2, edge_type="enables", weight=0.8),
        ChainEdge(source_finding_id=2, target_finding_id=3, edge_type="amplifies", weight=0.5),
        ChainEdge(source_finding_id=3, target_finding_id=1, edge_type="corroborates", weight=0.9),
    ]

    paths = builder.find_paths(edges, max_depth=4)

    assert any(path.finding_ids == (1, 2, 3) and path.score == 0.4 for path in paths)
    assert all(len(set(path.finding_ids)) == len(path.finding_ids) for path in paths)


def test_find_paths_filters_weak_edges() -> None:
    builder = ChainBuilder(FakeLLM(), RecordingBus())  # type: ignore[arg-type]
    edges = [
        ChainEdge(source_finding_id=1, target_finding_id=2, edge_type="enables", weight=0.2),
        ChainEdge(source_finding_id=2, target_finding_id=3, edge_type="enables", weight=0.9),
    ]
    assert builder.find_paths(edges, min_edge_weight=0.25) == []


@pytest.mark.asyncio
async def test_edges_are_cached_in_database(tmp_path: Path) -> None:
    db = Database(tmp_path / "chain.db")
    target_id = db.create_target("Example", "web", "https://example.com")
    left, _ = db.create_finding(target_id, "Info", "low", vuln_type="information disclosure", endpoint="/info")
    right, _ = db.create_finding(target_id, "IDOR", "high", vuln_type="idor", endpoint="/objects/1")
    llm = FakeLLM(
        {
            "edges": [
                {
                    "source_finding_id": left,
                    "target_finding_id": right,
                    "edge_type": "enables",
                    "weight": 0.75,
                    "rationale": "related evidence",
                }
            ]
        }
    )
    builder = ChainBuilder(llm, RecordingBus(), database=db)  # type: ignore[arg-type]

    await builder.build(
        [{"id": left, "title": "Info"}, {"id": right, "title": "IDOR"}],
        target_id=target_id,
    )

    with db._connect() as conn:
        row = conn.execute("SELECT edge_type, weight FROM chains").fetchone()
    assert row is not None
    assert tuple(row) == ("enables", 0.75)


@pytest.mark.asyncio
async def test_prompt_schema_braces_are_preserved() -> None:
    llm = FakeLLM({"edges": []})
    builder = ChainBuilder(llm, RecordingBus())  # type: ignore[arg-type]
    await builder.build([{"id": 1, "title": "A"}])
    assert '"edges": [' in llm.prompts[0]
    assert "{context_json}" not in llm.prompts[0]


@pytest.mark.asyncio
async def test_cancellation_propagates() -> None:
    class CancelLLM(FakeLLM):
        async def complete_json(self, prompt: str, *, system: str = "", heuristic=None) -> Any:
            raise asyncio.CancelledError

    builder = ChainBuilder(CancelLLM(), RecordingBus())  # type: ignore[arg-type]
    with pytest.raises(asyncio.CancelledError):
        await builder.build([{"id": 1}])
