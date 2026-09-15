"""Submission-quality gate for Windeep findings."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.brain.llm_client import LLMClient
from app.brain.prompts import SELF_CRITIC_PROMPT
from app.engine.event_bus import EventBus
from app.engine.scan_context import ScanContext


class CriticResult(BaseModel):
    """Normalized PASS/FAIL result from the submission gate."""

    model_config = ConfigDict(extra="ignore")

    decision: Literal["PASS", "FAIL"]
    reasons: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class SelfCritic:
    """Reject weak or unsafe submissions before they reach report output."""

    def __init__(self, llm_client: LLMClient, *, event_bus: EventBus | None = None) -> None:
        self.llm_client = llm_client
        self.event_bus = event_bus

    async def evaluate(
        self,
        finding: Mapping[str, Any],
        context: ScanContext,
        *,
        scan_id: int | None = None,
    ) -> CriticResult:
        """Run deterministic quality checks followed by optional model critique."""
        try:
            deterministic = self._deterministic_checks(finding, context)
            if deterministic.decision == "FAIL":
                await self._publish(deterministic, finding, scan_id)
                return deterministic

            context_json = json.dumps(
                {
                    "finding": self._safe_finding(finding),
                    "scope": context.scope or [context.target],
                    "out_of_scope": context.out_of_scope,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            prompt = SELF_CRITIC_PROMPT.replace("{context_json}", context_json)
            raw = await self.llm_client.complete_json(
                prompt,
                heuristic=lambda: deterministic.model_dump(),
            )
            try:
                result = CriticResult.model_validate(raw)
            except ValidationError:
                result = deterministic
            await self._publish(result, finding, scan_id)
            return result
        except asyncio.CancelledError:
            raise

    def _deterministic_checks(
        self,
        finding: Mapping[str, Any],
        context: ScanContext,
    ) -> CriticResult:
        reasons: list[str] = []
        missing: list[str] = []
        endpoint = str(finding.get("endpoint") or context.target)
        if not context.is_in_scope(endpoint):
            reasons.append("Finding endpoint is outside configured scope.")

        status = str(finding.get("status") or "").casefold()
        if status in {"duplicate", "rejected", "false_positive", "false-positive"}:
            reasons.append(f"Finding status is not submission-ready: {status}.")

        evidence = finding.get("evidence")
        has_evidence = bool(evidence) or bool(str(finding.get("request") or "").strip()) or bool(
            str(finding.get("response") or "").strip()
        )
        verified = finding.get("verified") is True
        source = str(finding.get("tool") or "").casefold()
        if not has_evidence:
            reasons.append("No concrete request, response, or evidence is attached.")
            missing.append("Attach reproducible evidence from an authorized validation step.")
        if source and source not in {"manual", "test_pack", "test-pack"} and not verified:
            reasons.append("Scanner/tool output is not independently verified.")
            missing.append("Confirm the behavior manually or through a bounded verification test.")

        impact = str(finding.get("impact") or "").strip()
        if not impact:
            reasons.append("Impact is missing.")
            missing.append("State only the impact demonstrated by the supplied evidence.")
        elif self._looks_speculative(impact) and not verified:
            reasons.append("Impact language is speculative relative to the verification state.")
            missing.append("Replace hypothetical impact with demonstrated consequences or explicit limitations.")

        if reasons:
            return CriticResult(
                decision="FAIL",
                reasons=reasons,
                missing_evidence=missing,
                confidence=0.98,
            )
        return CriticResult(
            decision="PASS",
            reasons=["Scope, evidence, verification, and impact checks passed."],
            missing_evidence=[],
            confidence=0.9,
        )

    async def _publish(
        self,
        result: CriticResult,
        finding: Mapping[str, Any],
        scan_id: int | None,
    ) -> None:
        try:
            if self.event_bus is None:
                return
            await self.event_bus.publish(
                "brain.critic",
                {
                    "scan_id": scan_id,
                    "finding_id": finding.get("id"),
                    "result": result.model_dump(),
                },
            )
        except asyncio.CancelledError:
            raise

    @staticmethod
    def _looks_speculative(impact: str) -> bool:
        text = impact.casefold()
        markers = (
            "could lead",
            "could allow",
            "may lead",
            "might allow",
            "potentially",
            "possible account takeover",
        )
        return any(marker in text for marker in markers)

    @staticmethod
    def _safe_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
        allowed = (
            "id",
            "title",
            "severity",
            "vuln_type",
            "tool",
            "endpoint",
            "description",
            "evidence",
            "steps",
            "impact",
            "remediation",
            "verified",
            "status",
            "confidence",
        )
        return {key: finding.get(key) for key in allowed if key in finding}
