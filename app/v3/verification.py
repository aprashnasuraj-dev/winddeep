"""R5 verification pass between bundle close and report generation."""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from typing import Any


class VerificationError(RuntimeError):
    """Raised when a finding cannot be converted into a defensible verification record."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _ref(kind: str, value: str) -> dict[str, str]:
    return {"kind": kind, "ref": value}


class VerificationPass:
    """Create immutable claim-level verification records backed by P1 artifacts."""

    CLAIM_ORDER = ("title", "affected_asset", "technical_detail", "impact", "reproduction")

    def __init__(self, database: Any, artifacts: Any) -> None:
        self.database = database
        self.artifacts = artifacts

    def _claim(
        self,
        claim: str,
        *,
        state: str,
        evidence_refs: Sequence[Mapping[str, str]],
        plan: Sequence[str] = (),
    ) -> dict[str, Any]:
        if state not in {"verified", "partially_verified", "needs-review"}:
            raise VerificationError(f"unsupported verification state: {state}")
        refs = [dict(item) for item in evidence_refs]
        steps = [str(item) for item in plan if str(item).strip()]
        if state == "needs-review" and not steps:
            raise VerificationError(f"needs-review claim {claim} requires a human-review plan")
        if state != "needs-review" and not refs:
            raise VerificationError(f"claim {claim} requires at least one evidence reference")
        return {"claim": claim, "state": state, "evidence_refs": refs, "plan": steps}

    def verify_finding(self, *, finding_id: int, scan_id: int, bundle: Mapping[str, Any]) -> dict[str, Any]:
        finding = self.database.get_finding(int(finding_id))
        if finding is None:
            raise VerificationError(f"finding not found: {finding_id}")
        completeness = bundle.get("completeness") if isinstance(bundle, Mapping) else None
        bundle_sha = str(bundle.get("bundle_sha256") or "") if isinstance(bundle, Mapping) else ""
        if not isinstance(completeness, Mapping) or completeness.get("closed") is not True or len(bundle_sha) != 64:
            raise VerificationError("verification requires a closed evidence bundle with a stable bundle hash")

        flows = list(bundle.get("flows") or [])
        provenance = bundle.get("provenance") if isinstance(bundle.get("provenance"), Mapping) else {"nodes": []}
        tool_output = bundle.get("tool_output") if isinstance(bundle.get("tool_output"), Mapping) else None
        reproduction = bundle.get("reproduction") if isinstance(bundle.get("reproduction"), Mapping) else {}
        exploitability = str(bundle.get("exploitability") or "observed")

        flow_refs = [
            _ref("flow", f"flow:{int(item['id'])}:{str(item['sha256'])}")
            for item in flows
            if isinstance(item, Mapping) and item.get("id") is not None and item.get("sha256")
        ]
        provenance_refs = [
            _ref("provenance", f"detector:{str(node.get('detector_id') or node.get('id') or 'unknown')}")
            for node in provenance.get("nodes") or []
            if isinstance(node, Mapping)
        ]
        artifact_refs: list[dict[str, str]] = []
        if tool_output:
            artifact_refs.append(
                _ref(
                    "artifact_slice",
                    f"artifact:{tool_output.get('artifact_sha256')}:{tool_output.get('line_start')}-{tool_output.get('line_end')}:{tool_output.get('slice_sha256')}",
                )
            )
        replay_handle = str(reproduction.get("replay_handle") or "")
        replay_refs = [_ref("replay", replay_handle)] if replay_handle else []
        plan = [str(item) for item in reproduction.get("plan") or [] if str(item).strip()]

        if exploitability == "needs-human-review" and not plan:
            raise VerificationError("needs-human-review bundle requires a human-review plan")

        title_refs = [*_ref_list(flow_refs), *_ref_list(provenance_refs)]
        asset_refs = list(flow_refs)
        technical_refs = [*_ref_list(flow_refs), *_ref_list(artifact_refs), *_ref_list(provenance_refs)]
        impact_state = "partially_verified" if flow_refs else "needs-review"
        impact_plan = plan or ["Review the recorded evidence and decide whether the stated impact follows from the observed behavior."]
        repro_state = "verified" if replay_refs and exploitability != "needs-human-review" else "needs-review"
        repro_plan = plan or ["Review the observation-only reproduction plan against the captured request before any manual action."]

        claims = [
            self._claim("title", state="verified", evidence_refs=title_refs),
            self._claim("affected_asset", state="verified", evidence_refs=asset_refs),
            self._claim("technical_detail", state="verified", evidence_refs=technical_refs),
            self._claim("impact", state=impact_state, evidence_refs=flow_refs, plan=impact_plan if impact_state == "needs-review" else ()),
            self._claim("reproduction", state=repro_state, evidence_refs=replay_refs, plan=repro_plan if repro_state == "needs-review" else ()),
        ]

        payload = {
            "schema": "windeep.verification.v1",
            "finding_id": int(finding_id),
            "scan_id": int(scan_id),
            "bundle_sha256": bundle_sha,
            "claims": claims,
        }
        raw = _canonical(payload)
        record_sha = hashlib.sha256(raw).hexdigest()
        ref = self.artifacts.put(
            scan_id=int(scan_id),
            tool_run_id=None,
            kind="verification.record",
            media_type="application/json",
            content=raw,
            reason=f"record v3 claim verification for finding {finding_id}",
            metadata={"finding_id": int(finding_id), "bundle_sha256": bundle_sha, "schema": payload["schema"]},
        )
        now = time.time()
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT OR IGNORE INTO verification_record(
                    finding_id, scan_id, bundle_sha256, artifact_sha256, schema_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (int(finding_id), int(scan_id), bundle_sha, ref.sha256, payload["schema"], now),
            )
            row = conn.execute(
                "SELECT id FROM verification_record WHERE finding_id = ? AND bundle_sha256 = ? AND artifact_sha256 = ?",
                (int(finding_id), bundle_sha, ref.sha256),
            ).fetchone()
            if row is None:
                raise VerificationError("verification record persistence failed")
            record_id = int(row["id"])
            for claim in claims:
                evidence_text = json.dumps(claim["evidence_refs"], sort_keys=True, separators=(",", ":"))
                plan_text = json.dumps(claim["plan"], sort_keys=True, separators=(",", ":"))
                enc = getattr(self.database, "_enc", None)
                if not callable(enc):
                    raise VerificationError("verification claims require encrypted database fields")
                conn.execute(
                    """
                    INSERT OR IGNORE INTO verification_claim(record_id, claim_key, state, evidence_refs, plan, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_id,
                        claim["claim"],
                        claim["state"],
                        enc(evidence_text, field="verification_claim.evidence_refs"),
                        enc(plan_text, field="verification_claim.plan"),
                        now,
                    ),
                )
        return {**payload, "record_id": record_id, "artifact_sha256": ref.sha256, "record_sha256": record_sha}

    def resolve(self, finding_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM verification_record WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (int(finding_id),),
            ).fetchone()
        if row is None:
            raise VerificationError(f"verification record not found for finding {finding_id}")
        item = dict(row)
        raw = self.artifacts.read(
            str(item["artifact_sha256"]),
            scan_id=int(item["scan_id"]),
            reason=f"resolve verification record for finding {finding_id}",
        )
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("schema") != "windeep.verification.v1":
            raise VerificationError("unsupported verification record schema")
        return {
            **payload,
            "record_id": int(item["id"]),
            "artifact_sha256": str(item["artifact_sha256"]),
            "record_sha256": hashlib.sha256(raw).hexdigest(),
        }


def _ref_list(value: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    return [dict(item) for item in value]
