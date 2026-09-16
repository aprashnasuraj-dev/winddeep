"""V3-B tester-driven handling classification and ranking.

There is deliberately no reviewer-policy import dependency in v3.0.0. A tester
classifies/ranks findings first; optional reviewer alignment can be layered on in
a later release without suppressing historical findings.
"""
from __future__ import annotations

import ipaddress
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

ASSET_CLASSES = frozenset({"http", "https", "ipv4", "ipv6"})
DISPOSITIONS = frozenset({"actionable", "needs-review", "not-actionable", "informational"})
DUPLICATE_RISKS = frozenset({"low", "medium", "high"})

_SEVERITY_WEIGHT = {"critical": 100.0, "high": 85.0, "medium": 60.0, "low": 35.0, "info": 10.0}
_DISPOSITION_WEIGHT = {"actionable": 1.0, "needs-review": 0.85, "not-actionable": 0.35, "informational": 0.20}
_DUPLICATE_FACTOR = {"low": 1.0, "medium": 0.85, "high": 0.70}


class TriageError(ValueError):
    """Raised when tester triage input is invalid."""


def _infer_asset_class(endpoint: str | None) -> str | None:
    text = str(endpoint or "").strip()
    if not text:
        return None
    parts = urlsplit(text)
    if parts.scheme in {"http", "https"} and parts.hostname:
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            return parts.scheme
        return "ipv4" if address.version == 4 else "ipv6"
    candidate = text.strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return "ipv4" if address.version == 4 else "ipv6"


def _score(finding: Mapping[str, Any], *, disposition: str, tester_priority: float, duplicate_risk: str) -> float:
    severity = _SEVERITY_WEIGHT.get(str(finding.get("severity") or "info").casefold(), 10.0)
    blended = 0.60 * float(tester_priority) + 0.40 * severity
    return round(blended * _DISPOSITION_WEIGHT[disposition] * _DUPLICATE_FACTOR[duplicate_risk], 2)


class ManualTriage:
    """Persist one tester classification per finding without deleting findings."""

    def __init__(self, database: Any, audit: Any) -> None:
        self.database = database
        self.audit = audit

    def classify(
        self,
        finding_id: int,
        *,
        disposition: str,
        tester_priority: float,
        duplicate_risk: str,
        rationale: str,
        asset_class: str | None = None,
    ) -> dict[str, Any]:
        finding = self.database.get_finding(int(finding_id))
        if finding is None:
            raise TriageError(f"finding not found: {finding_id}")
        resolved_asset = str(asset_class or _infer_asset_class(finding.get("endpoint")) or "").casefold()
        if resolved_asset not in ASSET_CLASSES:
            raise TriageError("asset_class must be one of: http, https, ipv4, ipv6")
        resolved_disposition = str(disposition).casefold()
        if resolved_disposition not in DISPOSITIONS:
            raise TriageError(f"unsupported disposition: {disposition}")
        resolved_duplicate = str(duplicate_risk).casefold()
        if resolved_duplicate not in DUPLICATE_RISKS:
            raise TriageError(f"unsupported duplicate_risk: {duplicate_risk}")
        try:
            priority = float(tester_priority)
        except (TypeError, ValueError) as exc:
            raise TriageError("tester_priority must be numeric from 0 to 100") from exc
        if not 0.0 <= priority <= 100.0:
            raise TriageError("tester_priority must be between 0 and 100")
        reason = str(rationale).strip()
        if not reason:
            raise TriageError("rationale is required for tester classification")
        scan_id = finding.get("scan_id")
        if scan_id is None:
            raise TriageError("finding must belong to a scan before v3 triage")
        score = _score(
            finding,
            disposition=resolved_disposition,
            tester_priority=priority,
            duplicate_risk=resolved_duplicate,
        )
        now = time.time()
        with self.database._connect() as conn:
            conn.execute(
                """
                INSERT INTO handling_classification(
                    finding_id, scan_id, asset_class, disposition, tester_priority,
                    duplicate_risk, rationale, score, classified_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    scan_id=excluded.scan_id,
                    asset_class=excluded.asset_class,
                    disposition=excluded.disposition,
                    tester_priority=excluded.tester_priority,
                    duplicate_risk=excluded.duplicate_risk,
                    rationale=excluded.rationale,
                    score=excluded.score,
                    updated_at=excluded.updated_at
                """,
                (
                    int(finding_id),
                    int(scan_id),
                    resolved_asset,
                    resolved_disposition,
                    priority,
                    resolved_duplicate,
                    reason,
                    score,
                    now,
                    now,
                ),
            )
        self.audit.append(
            "v3.triage.classified",
            {
                "finding_id": int(finding_id),
                "scan_id": int(scan_id),
                "asset_class": resolved_asset,
                "disposition": resolved_disposition,
                "tester_priority": priority,
                "duplicate_risk": resolved_duplicate,
                "score": score,
            },
        )
        return self.get(int(finding_id))

    def get(self, finding_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM handling_classification WHERE finding_id = ?",
                (int(finding_id),),
            ).fetchone()
        if row is None:
            raise KeyError(f"triage classification not found: {finding_id}")
        item = dict(row)
        item["finding_id"] = int(item["finding_id"])
        item["scan_id"] = int(item["scan_id"])
        item["tester_priority"] = float(item["tester_priority"])
        item["score"] = float(item["score"])
        item["classified"] = True
        return item

    def rank_scan(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute("SELECT id FROM findings WHERE scan_id = ? ORDER BY id ASC", (int(scan_id),)).fetchall()
        ranked: list[dict[str, Any]] = []
        for row in rows:
            finding_id = int(row["id"])
            finding = self.database.get_finding(finding_id)
            if finding is None:
                continue
            try:
                classification = self.get(finding_id)
            except KeyError:
                severity_priority = _SEVERITY_WEIGHT.get(str(finding.get("severity") or "info").casefold(), 10.0)
                classification = {
                    "finding_id": finding_id,
                    "scan_id": int(scan_id),
                    "asset_class": _infer_asset_class(finding.get("endpoint")) or "unclassified",
                    "disposition": "needs-review",
                    "tester_priority": severity_priority,
                    "duplicate_risk": "low",
                    "rationale": "Tester has not classified this finding yet.",
                    "score": _score(
                        finding,
                        disposition="needs-review",
                        tester_priority=severity_priority,
                        duplicate_risk="low",
                    ),
                    "classified": False,
                }
            ranked.append({**classification, "finding": finding})
        return sorted(ranked, key=lambda item: (-float(item["score"]), int(item["finding_id"])))


__all__ = [
    "ASSET_CLASSES",
    "DISPOSITIONS",
    "DUPLICATE_RISKS",
    "ManualTriage",
    "TriageError",
]
