"""Deterministic P0 post-execution stages for v3 scans."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.brain.chain_builder import ChainBuilder
from app.brain.finding_ranker import FindingRanker
from app.brain.hypothesis_engine import HypothesisEngine
from app.brain.llm_client import LLMClient
from app.database import finding_fingerprint
from app.duplicates import DuplicateDetector
from app.engine.event_bus import EventBus
from app.engine.scan_context import ScanContext


class DeterministicPostPipeline:
    """Deduplicate, correlate, rank, and hypothesize without wall-clock output."""

    def __init__(self, database: Any, event_bus: EventBus) -> None:
        self.database = database
        self.event_bus = event_bus
        heuristic_llm = LLMClient([])
        self.duplicates = DuplicateDetector(database)
        self.chains = ChainBuilder(heuristic_llm, event_bus, database=database)
        self.ranker = FindingRanker()
        self.hypotheses = HypothesisEngine(heuristic_llm, event_bus, database=database)

    async def run(
        self,
        findings: Sequence[Mapping[str, Any]],
        context: ScanContext,
        *,
        target_id: int,
        scan_id: int,
    ) -> dict[str, Any]:
        """Return stable JSON-compatible stage output for identical input."""
        deduplicated = self._deduplicate(findings, target_id=target_id)
        duplicate_context = self._duplicate_context(deduplicated, target_id=target_id)
        edges = await self.chains.build(deduplicated, target_id=target_id, scan_id=scan_id)
        paths = self.chains.find_paths(edges)
        ranked = self.ranker.rank(deduplicated)
        hypotheses = await self.hypotheses.generate(
            deduplicated,
            context,
            target_id=target_id,
            scan_id=scan_id,
        )
        return {
            "deduplicated": [dict(item) for item in deduplicated],
            "duplicate_context": duplicate_context,
            "chains": [edge.model_dump() for edge in edges],
            "chain_paths": [
                {
                    "finding_ids": list(path.finding_ids),
                    "edge_types": list(path.edge_types),
                    "score": path.score,
                }
                for path in paths
            ],
            "ranked": [
                {
                    "finding_id": int(item.finding.get("id") or 0),
                    "score": item.score,
                    "impact": item.impact,
                    "exploitability": item.exploitability,
                    "confidence": item.confidence,
                }
                for item in ranked
            ],
            "hypotheses": [item.model_dump() for item in hypotheses],
        }

    @staticmethod
    def _deduplicate(findings: Sequence[Mapping[str, Any]], *, target_id: int) -> list[dict[str, Any]]:
        by_fingerprint: dict[str, dict[str, Any]] = {}
        for item in findings:
            fingerprint = str(item.get("finding_fingerprint") or finding_fingerprint(
                target_id=target_id,
                title=str(item.get("title") or ""),
                vuln_type=str(item.get("vuln_type") or "informational"),
                endpoint=str(item.get("endpoint")) if item.get("endpoint") is not None else None,
            ))
            candidate = dict(item)
            candidate["finding_fingerprint"] = fingerprint
            current = by_fingerprint.get(fingerprint)
            if current is None or DeterministicPostPipeline._stable_candidate_key(candidate) < DeterministicPostPipeline._stable_candidate_key(current):
                by_fingerprint[fingerprint] = candidate
        return [by_fingerprint[key] for key in sorted(by_fingerprint)]

    def _duplicate_context(self, findings: Sequence[Mapping[str, Any]], *, target_id: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for finding in findings:
            matches = self.duplicates.internal(finding, target_id=target_id, limit=25)
            result.append(
                {
                    "finding_id": int(finding.get("id") or 0),
                    "matches": [
                        {
                            "source": match.source,
                            "identifier": match.identifier,
                            "score": match.score,
                            "exact": match.exact,
                        }
                        for match in matches
                        if str(match.identifier) != str(finding.get("id") or "")
                    ],
                }
            )
        return result

    @staticmethod
    def _stable_candidate_key(item: Mapping[str, Any]) -> tuple[str, str, str, int]:
        return (
            str(item.get("title") or "").casefold(),
            str(item.get("endpoint") or "").casefold(),
            str(item.get("tool") or "").casefold(),
            int(item.get("id") or 0),
        )
