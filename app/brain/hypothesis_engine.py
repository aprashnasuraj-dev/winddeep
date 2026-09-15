"""Evidence-grounded hypothesis generation for the Windeep Brain."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urljoin

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.brain.llm_client import LLMClient
from app.brain.prompts import HYPOTHESIS_GEN_PROMPT
from app.database import Database
from app.engine.event_bus import EventBus
from app.engine.scan_context import ScanContext

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class Hypothesis(BaseModel):
    """One testable, evidence-grounded security hypothesis."""

    model_config = ConfigDict(extra="ignore")

    id: str
    test_class: str
    endpoint: str | None = None
    parameters: dict[str, str] = Field(default_factory=dict)
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity_hint: str = "info"
    chain_hints: list[str] = Field(default_factory=list)
    source: str = "brain"

    @field_validator("severity_hint")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalized = value.lower().strip()
        if normalized not in _ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {value}")
        return normalized


class HypothesisEngine:
    """Generate hypotheses using an LLM with deterministic rule fallback."""

    def __init__(
        self,
        llm_client: LLMClient,
        event_bus: EventBus,
        *,
        database: Database | None = None,
        max_hypotheses: int = 40,
    ) -> None:
        if max_hypotheses < 1:
            raise ValueError("max_hypotheses must be positive")
        self.llm_client = llm_client
        self.event_bus = event_bus
        self.database = database
        self.max_hypotheses = max_hypotheses

    async def generate(
        self,
        findings: Sequence[Mapping[str, Any]],
        context: ScanContext,
        *,
        target_id: int | None = None,
        scan_id: int | None = None,
        memory_examples: Sequence[Mapping[str, Any]] = (),
    ) -> list[Hypothesis]:
        """Generate, validate, scope-filter, persist, and publish hypotheses."""
        try:
            payload = {
                "target": context.target,
                "scope": list(context.scope),
                "out_of_scope": list(context.out_of_scope),
                "tech_stack": sorted(context.tech_stack),
                "findings": [self._compact_finding(item) for item in findings],
                "memory_examples": list(memory_examples)[:8],
            }
            prompt = HYPOTHESIS_GEN_PROMPT.format(
                context_json=json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            )
            raw = await self.llm_client.complete_json(
                prompt,
                heuristic=lambda: self._rule_based(findings, context),
            )
            hypotheses = self._normalize(raw, context)
            context.hypotheses.extend(hypotheses)
            for hypothesis in hypotheses:
                if self.database is not None:
                    self.database.create_hypothesis(
                        hypothesis.model_dump(),
                        target_id=target_id,
                        scan_id=scan_id,
                    )
                await self.event_bus.publish(
                    "brain.hypothesis",
                    {
                        "scan_id": scan_id,
                        "target_id": target_id,
                        "hypothesis": hypothesis.model_dump(),
                    },
                )
            await self.event_bus.publish(
                "brain.hypotheses_generated",
                {
                    "scan_id": scan_id,
                    "target_id": target_id,
                    "count": len(hypotheses),
                },
            )
            return hypotheses
        except asyncio.CancelledError:
            raise

    def _normalize(self, raw: Any, context: ScanContext) -> list[Hypothesis]:
        if isinstance(raw, Mapping):
            items = raw.get("hypotheses", [])
        elif isinstance(raw, list):
            items = raw
        else:
            items = []
        if not isinstance(items, list):
            return []

        normalized: list[Hypothesis] = []
        seen: set[str] = set()
        for item in items[: self.max_hypotheses * 2]:
            if not isinstance(item, Mapping):
                continue
            candidate = dict(item)
            candidate.setdefault("source", "brain")
            if not str(candidate.get("id") or "").strip():
                candidate["id"] = self._stable_id(candidate)
            try:
                hypothesis = Hypothesis.model_validate(candidate)
            except ValidationError:
                continue
            if hypothesis.id in seen:
                continue
            endpoint = self._absolute_endpoint(hypothesis.endpoint, context.target)
            if endpoint is not None and not context.is_in_scope(endpoint):
                continue
            if endpoint is not None:
                hypothesis = hypothesis.model_copy(update={"endpoint": endpoint})
            seen.add(hypothesis.id)
            normalized.append(hypothesis)
            if len(normalized) >= self.max_hypotheses:
                break
        return normalized

    @staticmethod
    def _compact_finding(item: Mapping[str, Any]) -> dict[str, Any]:
        allowed = (
            "id",
            "title",
            "severity",
            "vuln_type",
            "tool",
            "endpoint",
            "description",
            "evidence",
            "confidence",
        )
        return {key: item.get(key) for key in allowed if key in item}

    @staticmethod
    def _absolute_endpoint(endpoint: str | None, target: str) -> str | None:
        if endpoint is None or not endpoint.strip():
            return None
        value = endpoint.strip()
        if "://" in value:
            return value
        base = target if "://" in target else f"https://{target}"
        return urljoin(base.rstrip("/") + "/", value.lstrip("/"))

    @staticmethod
    def _stable_id(item: Mapping[str, Any]) -> str:
        raw = json.dumps(dict(item), ensure_ascii=False, sort_keys=True, default=str)
        return "hyp-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def _rule_based(
        self,
        findings: Sequence[Mapping[str, Any]],
        context: ScanContext,
    ) -> dict[str, list[dict[str, Any]]]:
        hypotheses: list[dict[str, Any]] = []
        for finding in findings:
            vuln_type = str(finding.get("vuln_type") or "").casefold()
            title = str(finding.get("title") or "").casefold()
            endpoint = finding.get("endpoint")
            endpoint_text = str(endpoint) if endpoint else context.target
            if any(token in vuln_type or token in title for token in ("idor", "bola", "authorization", "access control")):
                hypotheses.append(
                    self._rule_hypothesis(
                        "authorization",
                        endpoint_text,
                        "Verify that object ownership is enforced consistently across equivalent authorized accounts using non-destructive reads.",
                        0.78,
                        "high",
                        ["session", "object_ownership"],
                    )
                )
            elif any(token in vuln_type or token in title for token in ("session", "jwt", "oauth", "authentication")):
                hypotheses.append(
                    self._rule_hypothesis(
                        "session",
                        endpoint_text,
                        "Check whether session state, expiry, and authorization decisions remain consistent after normal token lifecycle transitions.",
                        0.72,
                        "high",
                        ["authorization"],
                    )
                )
            elif any(token in vuln_type or token in title for token in ("cors", "header", "configuration", "tls")):
                hypotheses.append(
                    self._rule_hypothesis(
                        "configuration",
                        endpoint_text,
                        "Re-check the configuration signal with a minimal request and compare behavior across expected origins or protocol settings.",
                        0.62,
                        "medium",
                        [],
                    )
                )
            elif any(token in vuln_type or token in title for token in ("reflection", "xss", "injection", "ssti", "sqli")):
                hypotheses.append(
                    self._rule_hypothesis(
                        "input_validation",
                        endpoint_text,
                        "Use a benign unique marker to determine where input is reflected, transformed, or parsed before any deeper manual validation.",
                        0.58,
                        "medium",
                        ["encoding", "context"],
                    )
                )
        deduped: dict[str, dict[str, Any]] = {}
        for item in hypotheses:
            deduped[item["id"]] = item
        return {"hypotheses": list(deduped.values())[: self.max_hypotheses]}

    def _rule_hypothesis(
        self,
        test_class: str,
        endpoint: str,
        rationale: str,
        confidence: float,
        severity_hint: str,
        chain_hints: Sequence[str],
    ) -> dict[str, Any]:
        item = {
            "test_class": test_class,
            "endpoint": endpoint,
            "parameters": {},
            "rationale": rationale,
            "confidence": confidence,
            "severity_hint": severity_hint,
            "chain_hints": list(chain_hints),
            "source": "rule-based",
        }
        item["id"] = self._stable_id(item)
        return item
