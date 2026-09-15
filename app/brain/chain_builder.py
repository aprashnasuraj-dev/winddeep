"""Weighted finding relationship graph for the Windeep Brain."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.brain.llm_client import LLMClient
from app.brain.prompts import CHAIN_BUILDER_PROMPT
from app.database import Database
from app.engine.event_bus import EventBus

_ALLOWED_EDGE_TYPES = {"enables", "amplifies", "prerequisite", "corroborates"}


class ChainEdge(BaseModel):
    """Directed weighted relationship between two findings."""

    model_config = ConfigDict(extra="ignore")

    source_finding_id: int
    target_finding_id: int
    edge_type: str
    weight: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    source: str = "brain"

    @field_validator("edge_type")
    @classmethod
    def validate_edge_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in _ALLOWED_EDGE_TYPES:
            raise ValueError(f"unsupported edge type: {value}")
        return normalized


@dataclass(frozen=True, slots=True)
class ChainPath:
    """Acyclic path through the finding graph."""

    finding_ids: tuple[int, ...]
    edge_types: tuple[str, ...]
    score: float


class ChainBuilder:
    """Suggest, validate, persist, and traverse finding relationships."""

    def __init__(
        self,
        llm_client: LLMClient,
        event_bus: EventBus,
        *,
        database: Database | None = None,
        max_edges: int = 100,
    ) -> None:
        if max_edges < 1:
            raise ValueError("max_edges must be positive")
        self.llm_client = llm_client
        self.event_bus = event_bus
        self.database = database
        self.max_edges = max_edges

    async def build(
        self,
        findings: Sequence[Mapping[str, Any]],
        *,
        target_id: int | None = None,
        scan_id: int | None = None,
    ) -> list[ChainEdge]:
        """Build a validated finding graph and cache edges in SQLite."""
        try:
            compact = [self._compact(item) for item in findings if item.get("id") is not None]
            prompt = CHAIN_BUILDER_PROMPT.replace(
                "{context_json}",
                json.dumps({"findings": compact}, ensure_ascii=False, separators=(",", ":")),
            )
            raw = await self.llm_client.complete_json(
                prompt,
                heuristic=lambda: self._rule_based_edges(findings),
            )
            edges = self._normalize(raw, findings)
            for edge in edges:
                if self.database is not None:
                    self.database.upsert_chain_edge(
                        source_finding_id=edge.source_finding_id,
                        target_finding_id=edge.target_finding_id,
                        edge_type=edge.edge_type,
                        weight=edge.weight,
                        rationale=edge.rationale,
                        target_id=target_id,
                        scan_id=scan_id,
                    )
                await self.event_bus.publish(
                    "brain.chain_edge",
                    {
                        "scan_id": scan_id,
                        "target_id": target_id,
                        "edge": edge.model_dump(),
                    },
                )
            await self.event_bus.publish(
                "brain.chains_built",
                {"scan_id": scan_id, "target_id": target_id, "edge_count": len(edges)},
            )
            return edges
        except asyncio.CancelledError:
            raise

    def find_paths(
        self,
        edges: Sequence[ChainEdge],
        *,
        max_depth: int = 4,
        min_edge_weight: float = 0.25,
    ) -> list[ChainPath]:
        """Return acyclic multi-edge paths ranked by multiplicative edge weight."""
        if max_depth < 2:
            raise ValueError("max_depth must be >= 2")
        graph: dict[int, list[ChainEdge]] = defaultdict(list)
        for edge in edges:
            if edge.weight >= min_edge_weight:
                graph[edge.source_finding_id].append(edge)
        paths: list[ChainPath] = []

        def walk(node: int, ids: tuple[int, ...], types: tuple[str, ...], score: float) -> None:
            if len(ids) >= max_depth:
                return
            for edge in graph.get(node, []):
                if edge.target_finding_id in ids:
                    continue
                next_ids = (*ids, edge.target_finding_id)
                next_types = (*types, edge.edge_type)
                next_score = score * edge.weight
                if len(next_types) >= 2:
                    paths.append(ChainPath(next_ids, next_types, round(next_score, 4)))
                walk(edge.target_finding_id, next_ids, next_types, next_score)

        for source in sorted(graph):
            walk(source, (source,), (), 1.0)
        return sorted(paths, key=lambda item: (-item.score, item.finding_ids))

    def _normalize(
        self,
        raw: Any,
        findings: Sequence[Mapping[str, Any]],
    ) -> list[ChainEdge]:
        known_ids = {int(item["id"]) for item in findings if item.get("id") is not None}
        items = raw.get("edges", []) if isinstance(raw, Mapping) else raw if isinstance(raw, list) else []
        if not isinstance(items, list):
            return []
        result: list[ChainEdge] = []
        seen: set[tuple[int, int, str]] = set()
        for item in items[: self.max_edges * 2]:
            if not isinstance(item, Mapping):
                continue
            candidate = dict(item)
            candidate.setdefault("source", "brain")
            try:
                edge = ChainEdge.model_validate(candidate)
            except ValidationError:
                continue
            if edge.source_finding_id == edge.target_finding_id:
                continue
            if edge.source_finding_id not in known_ids or edge.target_finding_id not in known_ids:
                continue
            key = (edge.source_finding_id, edge.target_finding_id, edge.edge_type)
            if key in seen:
                continue
            seen.add(key)
            result.append(edge)
            if len(result) >= self.max_edges:
                break
        return result

    @staticmethod
    def _compact(item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: item.get(key)
            for key in ("id", "title", "severity", "vuln_type", "endpoint", "description", "verified", "confidence")
            if key in item
        }

    def _rule_based_edges(self, findings: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        edges: list[dict[str, Any]] = []
        normalized: list[tuple[int, str]] = []
        for item in findings:
            if item.get("id") is None:
                continue
            text = " ".join(
                [
                    str(item.get("vuln_type") or ""),
                    str(item.get("title") or ""),
                    str(item.get("description") or ""),
                ]
            ).casefold()
            normalized.append((int(item["id"]), text))

        def ids_matching(*tokens: str) -> list[int]:
            return [finding_id for finding_id, text in normalized if any(token in text for token in tokens)]

        info = ids_matching("information disclosure", "info disclosure", "sensitive information")
        object_auth = ids_matching("idor", "bola", "object authorization", "access control")
        self_xss = ids_matching("self-xss", "self xss")
        csrf = ids_matching("csrf", "cross-site request forgery")
        token_leak = ids_matching("token leak", "reset token", "session token disclosure")
        reset = ids_matching("password reset", "account recovery")

        for left in info:
            for right in object_auth:
                if left != right:
                    edges.append(self._edge(left, right, "enables", 0.72, "Disclosed identifiers or metadata may make an existing object-authorization weakness easier to validate."))
        for left in csrf:
            for right in self_xss:
                if left != right:
                    edges.append(self._edge(left, right, "amplifies", 0.62, "Cross-site request behavior may increase the reach of an otherwise self-only client-side issue; impact still requires separate verification."))
        for left in token_leak:
            for right in reset:
                if left != right:
                    edges.append(self._edge(left, right, "enables", 0.80, "Token exposure can materially affect a recovery-flow weakness when both findings refer to the same authorized workflow."))
        return {"edges": edges[: self.max_edges]}

    @staticmethod
    def _edge(source: int, target: int, edge_type: str, weight: float, rationale: str) -> dict[str, Any]:
        return {
            "source_finding_id": source,
            "target_finding_id": target,
            "edge_type": edge_type,
            "weight": weight,
            "rationale": rationale,
            "source": "rule-based",
        }
