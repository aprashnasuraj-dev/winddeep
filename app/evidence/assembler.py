"""Automatic evidence assembly from scheduler-owned scan observations.

The assembler performs no network activity and does not infer missing proof.
It binds a scan observation only to:
- the exact raw stdout artifact recorded for that tool run,
- an exact parser line number when the parser supplied one,
- HTTP flows explicitly linked to the same tool_run_id,
- deterministic Windeep parser provenance.

Anything missing remains an incomplete bundle rather than being guessed.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from app.evidence.bundles import BundleIncompleteError, EvidenceBundleStore
from app.finding_observations import FindingObservationStore


class EvidenceAssembler:
    """Build P2 bundles from existing immutable P1/runtime evidence only."""

    def __init__(self, database: Any, crypto: Any, audit: Any) -> None:
        self.database = database
        self.crypto = crypto
        self.audit = audit
        self.observations = FindingObservationStore(database)
        self.bundles = EvidenceBundleStore(database, crypto, audit=audit)

    def _flow_ids(self, *, scan_id: int, tool_run_id: int) -> list[int]:
        try:
            with self.database._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT flow_id
                    FROM flow_evidence
                    WHERE scan_id = ? AND tool_run_id = ?
                    ORDER BY flow_id ASC
                    """,
                    (int(scan_id), int(tool_run_id)),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).casefold():
                return []
            raise
        return [int(row["flow_id"]) for row in rows]

    @staticmethod
    def _execution(payload: Mapping[str, Any]) -> dict[str, Any]:
        evidence = payload.get("evidence")
        if not isinstance(evidence, Mapping):
            return {}
        execution = evidence.get("_windeep_execution")
        return dict(execution) if isinstance(execution, Mapping) else {}

    @staticmethod
    def _line_number(payload: Mapping[str, Any]) -> int | None:
        raw = payload.get("source_line")
        evidence = payload.get("evidence")
        if raw is None and isinstance(evidence, Mapping):
            raw = evidence.get("line_number")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        return value if value >= 1 else None

    @staticmethod
    def _provenance(payload: Mapping[str, Any], execution: Mapping[str, Any]) -> dict[str, Any]:
        tool = str(payload.get("tool") or "unknown-tool")
        parser = str(execution.get("parser") or "unknown-parser")
        tool_run_id = execution.get("tool_run_id")
        backend = str(execution.get("backend") or "")
        node: dict[str, Any] = {
            "id": f"parser:{tool}:{parser}",
            "kind": "parser",
            "name": f"Windeep {tool} normalizer",
            "version": "windeep.tool-execution-evidence.v2",
            "detector_id": f"{tool}:{parser}",
            "source": "runtime-parser",
        }
        if tool_run_id is not None:
            node["reference"] = f"tool-run:{int(tool_run_id)}"
        if backend:
            node["backend"] = backend
        stdout_sha = str(execution.get("stdout_sha256") or "")
        if stdout_sha:
            node["observation_artifact_sha256"] = stdout_sha
        return {"nodes": [node], "edges": []}

    def assemble_observation(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        scan_id = int(observation["scan_id"])
        finding_id = int(observation["finding_id"])
        payload = dict(observation.get("payload") or {})
        finding = self.database.get_finding(finding_id)
        if finding is None:
            return {
                "finding_id": finding_id,
                "scan_id": scan_id,
                "state": "blocked",
                "reason": "canonical finding is missing",
            }

        execution = self._execution(payload)
        tool_run_id = int(execution.get("tool_run_id") or observation["tool_run_id"])
        stdout_sha = str(execution.get("stdout_sha256") or "")
        line_number = self._line_number(payload)
        flow_ids = self._flow_ids(scan_id=scan_id, tool_run_id=tool_run_id)
        provenance = self._provenance(payload, execution)

        kwargs = {
            "finding": finding,
            "scan_id": scan_id,
            "tool_run_id": tool_run_id,
            "flow_ids": flow_ids,
            "artifact_sha256": stdout_sha if stdout_sha and line_number is not None else None,
            "line_start": line_number,
            "line_end": line_number,
            "provenance": provenance,
            "exploitability": "observed",
        }
        try:
            bundle = self.bundles.build(**kwargs, close=True)
        except BundleIncompleteError:
            bundle = self.bundles.build(**kwargs, close=False)
        except Exception as exc:
            self.audit.append(
                "evidence.assembly_blocked",
                {
                    "scan_id": scan_id,
                    "finding_id": finding_id,
                    "tool_run_id": tool_run_id,
                    "reason": str(exc),
                },
            )
            return {
                "finding_id": finding_id,
                "scan_id": scan_id,
                "tool_run_id": tool_run_id,
                "state": "blocked",
                "reason": str(exc),
            }

        state = "closed" if bool(bundle.get("completeness", {}).get("closed")) else "incomplete"
        result = {
            "finding_id": finding_id,
            "scan_id": scan_id,
            "tool_run_id": tool_run_id,
            "state": state,
            "profile": str(bundle.get("evidence_profile") or ""),
            "bundle_sha256": str(bundle["bundle_sha256"]),
            "missing": list(bundle.get("completeness", {}).get("missing") or []),
            "flow_ids": flow_ids,
            "stdout_sha256": stdout_sha,
            "line_number": line_number,
        }
        self.audit.append("evidence.assembled", result)
        return result

    def assemble_scan(self, scan_id: int) -> list[dict[str, Any]]:
        """Assemble each scheduler observation deterministically by tool run."""
        observations = self.observations.list_scan(int(scan_id))
        observations.sort(
            key=lambda item: (
                int(item["finding_id"]),
                int(item["tool_run_id"]),
                str(item["fingerprint"]),
            )
        )
        return [self.assemble_observation(observation) for observation in observations]


__all__ = ["EvidenceAssembler"]
