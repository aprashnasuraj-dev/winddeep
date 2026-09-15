"""Windeep v3 forensic convergence layer.

This module is the production bridge from P1 raw custody to P2 evidence bundles.
All public evidence operations require a live PreFlightGuard; the low-level P1
store remains a cryptographic primitive and is not exposed as the v3 API.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from typing import Any

from app.capture.forensic import ForensicFlowStore
from app.evidence.bundles import BundleIncompleteError, EvidenceIntegrityError
from app.evidence.raw_store import RawArtifactStore
from app.evidence.redaction import EvidenceRedactor

BUNDLE_SCHEMA_V2 = "windeep.evidence-bundle.v2"
_EXPLOITABILITY = {"observed", "needs-human-review"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class GuardedEvidenceVault:
    """Mandatory-preflight facade over P1 artifacts, flows, redaction and sealing."""

    def __init__(self, database: Any, crypto: Any, audit: Any, guard: Any, *, target: str, consent_id: str) -> None:
        self.database = database
        self.crypto = crypto
        self.audit = audit
        self.guard = guard
        self.target = target
        self.consent_id = consent_id
        self.raw = RawArtifactStore(database, crypto, audit)
        self.flows = ForensicFlowStore(database, self.raw, audit)
        self.redactor = EvidenceRedactor(self.raw)

    def authorize(self, action: str) -> None:
        try:
            self.guard.authorize_scan(target=self.target, consent_id=self.consent_id)
            self.audit.append("v3.evidence.authorized", {"action": action, "target": self.target})
        except Exception as exc:
            try:
                self.audit.append("v3.evidence.denied", {"action": action, "target": self.target, "reason": type(exc).__name__})
            except Exception:
                pass
            raise

    def record_tool_run(self, **kwargs: Any) -> dict[str, Any]:
        self.authorize("tool-run.write")
        return self.raw.record_tool_run(**kwargs)

    def read_tool_run(self, tool_run_id: int) -> dict[str, Any]:
        self.authorize("tool-run.read")
        return self.raw.read_tool_run(tool_run_id)

    def read_artifact(self, sha256: str, *, scan_id: int, reason: str) -> bytes:
        self.authorize("artifact.read")
        return self.raw.read(sha256, scan_id=scan_id, reason=reason)

    def export_har(self, *, scan_id: int, operator_terms: Sequence[str] = (), flow_ids: Sequence[int] | None = None) -> bytes:
        self.authorize("har.export")
        return self.flows.export_har(scan_id=scan_id, redactor=self.redactor, operator_terms=operator_terms, flow_ids=flow_ids)

    def capture_flow(self, **kwargs: Any) -> int:
        self.authorize("flow.capture")
        return self.flows.capture(**kwargs)

    def reconstruct_request(self, flow_id: int) -> bytes:
        self.authorize("flow.replay-read")
        return self.flows.reconstruct_request(flow_id)

    def reconstruct_response(self, flow_id: int) -> bytes:
        self.authorize("flow.replay-read")
        return self.flows.reconstruct_response(flow_id)

    def seal_scan(self, scan_id: int, *, reason: str = "scan close") -> dict[str, Any]:
        self.authorize("scan.seal")
        return self.raw.seal_scan(scan_id, reason=reason)

    def verify_scan(self, scan_id: int) -> bool:
        self.authorize("scan.verify")
        return self.raw.verify_scan_root(scan_id)


class ForensicEvidenceBundleStore:
    """P2 v2 bundles that reference P1 content-addressed artifacts directly."""

    def __init__(self, database: Any, vault: GuardedEvidenceVault) -> None:
        self.database = database
        self.vault = vault

    def _flow_refs(self, scan_id: int, tool_run_id: int | None) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            if tool_run_id is None:
                rows = conn.execute("SELECT flow_id FROM flow_evidence WHERE scan_id = ? ORDER BY flow_id", (scan_id,)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT flow_id FROM flow_evidence WHERE scan_id = ? AND tool_run_id = ? ORDER BY flow_id",
                    (scan_id, tool_run_id),
                ).fetchall()
        refs: list[dict[str, Any]] = []
        for row in rows:
            flow = self.vault.flows.get(int(row["flow_id"]))
            refs.append(
                {
                    "id": int(flow["id"]),
                    "flow_sha256": str(flow["flow_sha256"]),
                    "raw_request_sha256": str(flow["raw_request_sha256"]),
                    "raw_response_sha256": str(flow["raw_response_sha256"]),
                    "method": str(flow.get("method") or ""),
                    "url": str(flow.get("url") or ""),
                    "status": flow.get("status"),
                    "http_version": str(flow.get("http_version") or "HTTP/1.1"),
                    "stream_id": flow.get("stream_id"),
                    "tls": dict(flow.get("tls") or {}),
                }
            )
        return refs

    @staticmethod
    def _line_ref(content: bytes, finding: Mapping[str, Any]) -> dict[str, Any] | None:
        lines = content.splitlines()
        if not lines:
            return None
        evidence = finding.get("evidence") or {}
        requested = evidence.get("line_number") if isinstance(evidence, Mapping) else None
        if isinstance(requested, int) and 1 <= requested <= len(lines):
            start = end = requested
        else:
            title = str(finding.get("title") or "").encode("utf-8", errors="ignore")
            index = next((idx for idx, line in enumerate(lines) if title and title in line), None)
            if index is None:
                start, end = 1, len(lines)
            else:
                start = end = index + 1
        selected = b"\n".join(lines[start - 1 : end])
        return {"line_start": start, "line_end": end, "slice_sha256": _sha256(selected)}

    def build_from_run(
        self,
        *,
        finding: Mapping[str, Any],
        scan_id: int,
        tool_run_id: int,
        close: bool = True,
    ) -> dict[str, Any]:
        self.vault.authorize("bundle.build")
        run = self.vault.read_tool_run(tool_run_id)
        stdout = bytes(run.get("stdout") or b"")
        stderr = bytes(run.get("stderr") or b"")
        chosen = stdout if stdout else stderr
        chosen_sha = str(run["stdout_sha256"] if stdout else run["stderr_sha256"])
        line_ref = self._line_ref(chosen, finding)
        flows = self._flow_refs(scan_id, tool_run_id)
        exploitability = str(finding.get("exploitability") or ("observed" if flows else "needs-human-review"))
        if exploitability not in _EXPLOITABILITY:
            raise ValueError(f"unsupported exploitability: {exploitability}")
        provenance = {
            "nodes": [
                {
                    "id": f"detector:{finding.get('tool') or run.get('tool_name')}:{finding.get('vuln_type') or 'tool_output'}",
                    "kind": "detector",
                    "name": str(run.get("tool_name") or finding.get("tool") or "unknown"),
                    "version": str(run.get("tool_version") or "unknown"),
                    "detector_id": str((finding.get("evidence") or {}).get("detector_id") if isinstance(finding.get("evidence"), Mapping) else "") or str(finding.get("vuln_type") or "tool_output"),
                    "source": "tool-wrapper-catalog",
                    "source_digest": str(run.get("resolved_binary_sha256") or ""),
                }
            ],
            "edges": [],
        }
        human_plan = []
        if exploitability == "needs-human-review":
            human_plan = ["Review the stored detector observation and captured authorization context; do not execute an exploit or state-changing action."]
        reproduction = None
        if flows:
            primary = flows[0]
            reproduction = {
                "replay_handle": f"forensic-flow:{primary['id']}:{primary['raw_request_sha256']}",
                "steps": [
                    f"Load captured flow {primary['id']} from the encrypted evidence store.",
                    "Reconstruct the recorded request bytes under the same approved scope and authorization context.",
                    "Compare the replay observation with the recorded response and stop at the observation point.",
                ],
                "plan": human_plan,
            }
        required = {
            "flow": bool(flows),
            "tool_output": bool(line_ref and chosen_sha),
            "provenance": bool(provenance["nodes"]),
            "reproduction": bool(reproduction),
        }
        if exploitability == "needs-human-review":
            required["human_plan"] = bool(human_plan)
        missing = [name for name, present in required.items() if not present]
        score = sum(1 for value in required.values() if value) / len(required)
        if close and missing:
            raise BundleIncompleteError(f"cannot close forensic evidence bundle; missing: {', '.join(missing)}")
        payload = {
            "schema": BUNDLE_SCHEMA_V2,
            "finding": {
                "id": int(finding["id"]),
                "fingerprint": str(finding.get("fingerprint") or ""),
                "title": str(finding.get("title") or ""),
                "severity": str(finding.get("severity") or "info").lower(),
                "vuln_type": str(finding.get("vuln_type") or ""),
                "tool": str(finding.get("tool") or run.get("tool_name") or ""),
                "endpoint": finding.get("endpoint"),
            },
            "tool_run_id": int(tool_run_id),
            "tool_output": {
                "artifact_sha256": chosen_sha,
                **(line_ref or {}),
            } if chosen_sha else None,
            "flows": flows,
            "provenance": provenance,
            "reproduction": reproduction,
            "confidence": float(finding.get("confidence") or 0.0),
            "exploitability": exploitability,
            "completeness": {"score": round(score, 6), "missing": missing, "closed": bool(close and not missing)},
        }
        canonical = _canonical(payload)
        digest = _sha256(canonical)
        encrypted = self.database._enc(canonical.decode("utf-8"), field="forensic_bundle.payload")
        now = time.time()
        with self.database._connect() as conn:
            previous = conn.execute(
                "SELECT id FROM forensic_evidence_bundles WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (int(finding["id"]),),
            ).fetchone()
            existing = conn.execute(
                "SELECT id FROM forensic_evidence_bundles WHERE finding_id = ? AND bundle_sha256 = ?",
                (int(finding["id"]), digest),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO forensic_evidence_bundles(
                        finding_id, scan_id, tool_run_id, schema_version, bundle_sha256,
                        completeness_score, state, payload, supersedes_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(finding["id"]), scan_id, tool_run_id, BUNDLE_SCHEMA_V2, digest, round(score, 6),
                        "closed" if payload["completeness"]["closed"] else "incomplete", encrypted,
                        int(previous["id"]) if previous is not None else None, now,
                    ),
                )
        return {**payload, "bundle_sha256": digest, "canonical_json": canonical.decode("utf-8")}

    def resolve(self, finding_id: int) -> dict[str, Any]:
        self.vault.authorize("bundle.resolve")
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM forensic_evidence_bundles WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"forensic evidence bundle not found: {finding_id}")
        item = dict(row)
        text = self.database._dec(str(item["payload"]), field="forensic_bundle.payload")
        if _sha256(text.encode("utf-8")) != str(item["bundle_sha256"]):
            raise EvidenceIntegrityError("forensic evidence bundle hash mismatch")
        payload = json.loads(text)
        if payload.get("schema") != BUNDLE_SCHEMA_V2:
            raise EvidenceIntegrityError("unsupported forensic evidence bundle schema")
        output = payload.get("tool_output") or {}
        if output.get("artifact_sha256"):
            content = self.vault.read_artifact(str(output["artifact_sha256"]), scan_id=int(item["scan_id"]), reason="validate bundle tool output")
            lines = content.splitlines()
            start, end = int(output["line_start"]), int(output["line_end"])
            selected = b"\n".join(lines[start - 1 : end])
            if _sha256(selected) != output.get("slice_sha256"):
                raise EvidenceIntegrityError("forensic tool-output slice hash mismatch")
        for ref in payload.get("flows") or []:
            flow = self.vault.flows.get(int(ref["id"]))
            if str(flow["flow_sha256"]) != ref.get("flow_sha256"):
                raise EvidenceIntegrityError(f"forensic flow hash mismatch: {ref['id']}")
            if _sha256(self.vault.reconstruct_request(int(ref["id"]))) != ref.get("raw_request_sha256"):
                raise EvidenceIntegrityError(f"raw request hash mismatch: {ref['id']}")
            if _sha256(self.vault.reconstruct_response(int(ref["id"]))) != ref.get("raw_response_sha256"):
                raise EvidenceIntegrityError(f"raw response hash mismatch: {ref['id']}")
        return {**payload, "bundle_sha256": str(item["bundle_sha256"]), "bundle_id": int(item["id"]), "state": str(item["state"])}


__all__ = ["BUNDLE_SCHEMA_V2", "ForensicEvidenceBundleStore", "GuardedEvidenceVault"]
