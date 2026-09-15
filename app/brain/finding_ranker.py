"""Deterministic finding prioritization for the Windeep Brain."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_SEVERITY_IMPACT = {
    "critical": 1.0,
    "high": 0.85,
    "medium": 0.60,
    "low": 0.35,
    "info": 0.10,
}


@dataclass(frozen=True, slots=True)
class RankedFinding:
    """Finding plus normalized ranking factors and final priority score."""

    finding: Mapping[str, Any]
    impact: float
    exploitability: float
    confidence: float
    score: float


class FindingRanker:
    """Rank findings using impact × exploitability × confidence."""

    def rank(self, findings: Sequence[Mapping[str, Any]]) -> list[RankedFinding]:
        """Return findings sorted from highest to lowest priority."""
        ranked = [self.score(item) for item in findings]
        return sorted(ranked, key=lambda item: (-item.score, self._stable_key(item.finding)))

    def score(self, finding: Mapping[str, Any]) -> RankedFinding:
        """Score one finding on a 0-100 scale."""
        impact = self._impact(finding)
        exploitability = self._exploitability(finding)
        confidence = self._clamp(float(finding.get("confidence", 0.5)))
        score = round(100.0 * impact * exploitability * confidence, 2)
        return RankedFinding(
            finding=finding,
            impact=impact,
            exploitability=exploitability,
            confidence=confidence,
            score=score,
        )

    def _impact(self, finding: Mapping[str, Any]) -> float:
        cvss = finding.get("cvss_score")
        if cvss is not None:
            try:
                return self._clamp(float(cvss) / 10.0)
            except (TypeError, ValueError):
                pass
        return _SEVERITY_IMPACT.get(str(finding.get("severity", "info")).lower(), 0.10)

    def _exploitability(self, finding: Mapping[str, Any]) -> float:
        explicit = finding.get("exploitability")
        if explicit is not None:
            try:
                return self._clamp(float(explicit))
            except (TypeError, ValueError):
                pass

        value = 0.65
        if finding.get("requires_auth"):
            value -= 0.12
        if finding.get("requires_two_accounts"):
            value -= 0.08
        if finding.get("user_interaction"):
            value -= 0.10
        complexity = str(finding.get("attack_complexity") or "").lower()
        if complexity == "high":
            value -= 0.18
        elif complexity == "low":
            value += 0.08
        if finding.get("verified") is True:
            value += 0.10
        return self._clamp(value)

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    @staticmethod
    def _stable_key(finding: Mapping[str, Any]) -> str:
        return str(finding.get("id") or finding.get("title") or "")
