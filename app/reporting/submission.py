"""Evidence-bound, reviewable submission drafts with no remote side effects."""
from __future__ import annotations

import hashlib
import re
import sqlite3
from typing import Any, Mapping

from app.reporting.generator import ReportArtifact, ReportGenerator


def _inline(value: Any) -> str:
    """Put untrusted content in an inline code span it cannot terminate."""
    text = " ".join(str(value or "").split())
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def _block(value: Any, *, language: str = "text", limit: int = 16384) -> str:
    """Render untrusted content without allowing it to close the code fence."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    truncated = len(text) > limit
    text = text[:limit]
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    suffix = "\n\n[Excerpt truncated; inspect the attached evidence for the full redacted view.]" if truncated else ""
    return f"{fence}{language}\n{text}\n{fence}{suffix}"


class SubmissionDraftGenerator:
    """Create a human-review draft from one closed, revalidated scan bundle."""

    _REQUIRED_VERIFIED_CLAIMS = (
        "title",
        "affected_asset",
        "technical_detail",
        "expected_observed",
        "control",
        "reproduction",
    )

    def __init__(self, generator: ReportGenerator) -> None:
        self.generator = generator

    def _verification_snapshot(self, finding_id: int, scan_id: int, bundle_sha256: str) -> dict[str, Any]:
        try:
            with self.generator.database._connect() as conn:
                record = conn.execute(
                    """
                    SELECT id, artifact_sha256 FROM verification_record
                    WHERE finding_id = ? AND scan_id = ? AND bundle_sha256 = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (int(finding_id), int(scan_id), str(bundle_sha256)),
                ).fetchone()
                if record is None:
                    return {"recorded": False, "claims": {}, "record_id": None, "artifact_sha256": None}
                rows = conn.execute(
                    "SELECT claim_key, state FROM verification_claim WHERE record_id = ? ORDER BY id ASC",
                    (int(record["id"]),),
                ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).casefold():
                return {"recorded": False, "claims": {}, "record_id": None, "artifact_sha256": None}
            raise
        return {
            "recorded": True,
            "record_id": int(record["id"]),
            "artifact_sha256": str(record["artifact_sha256"]),
            "claims": {str(row["claim_key"]): str(row["state"]) for row in rows},
        }

    def _triage_snapshot(self, finding_id: int) -> dict[str, Any]:
        try:
            with self.generator.database._connect() as conn:
                row = conn.execute(
                    """
                    SELECT disposition, tester_priority, duplicate_risk, rationale
                    FROM handling_classification WHERE finding_id = ?
                    """,
                    (int(finding_id),),
                ).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).casefold():
                return {"classified": False, "disposition": "needs-review"}
            raise
        if row is None:
            return {"classified": False, "disposition": "needs-review"}
        return {
            "classified": True,
            "disposition": str(row["disposition"]),
            "tester_priority": float(row["tester_priority"]),
            "duplicate_risk": str(row["duplicate_risk"]),
            "rationale": str(row["rationale"]),
        }

    def render_finding(self, finding_id: int, *, scan_id: int, scan_status: str) -> ReportArtifact:
        """Build a deterministic, redacted draft for a specific scan observation."""
        model = self.generator._finding_model(
            int(finding_id), scan_id=int(scan_id), allow_unscored=True, include_duplicates=False
        )
        issues: list[str] = []
        for key, message in (
            ("description", "Add a clear description of the observed behavior."),
            ("recorded_steps", "Add reproducible, authorized steps."),
            ("impact", "Describe only the impact supported by the evidence."),
            ("remediation", "Add or review remediation guidance."),
        ):
            if not model.get(key):
                issues.append(message)
        if not model.get("cvss_vector"):
            issues.append("Severity is recorded, but no CVSS vector is available; review the rating.")
        if model.get("exploitability") == "needs-human-review":
            issues.append("The evidence is marked as needing human validation.")
        if model.get("finding_status") in {"duplicate", "rejected", "false_positive", "false-positive"}:
            issues.append(f"The finding is marked {model['finding_status']}; resolve its disposition before submission.")
        if scan_status != "completed":
            issues.append(f"The source scan ended with status {scan_status}; review its errors or interruptions.")
        issues.extend([
            "Confirm the steps, expected behavior, actual behavior, and demonstrated impact.",
            "Review every attachment for sensitive data; automatic redaction may miss secrets.",
            "Check program scope, reporting rules, and possible duplicates before sending.",
        ])

        verification = self._verification_snapshot(
            int(finding_id),
            int(scan_id),
            str(model.get("bundle_sha256") or ""),
        )
        triage = self._triage_snapshot(int(finding_id))
        blocking_reasons: list[str] = []
        if scan_status != "completed":
            blocking_reasons.append("source_scan_not_cleanly_completed")
        if not verification["recorded"]:
            blocking_reasons.append("claim_verification_not_recorded")
        claims = dict(verification.get("claims") or {})
        for claim in self._REQUIRED_VERIFIED_CLAIMS:
            if claims.get(claim) != "verified":
                blocking_reasons.append(f"{claim}_not_verified")
        if claims.get("impact") not in {"verified", "partially_verified"}:
            blocking_reasons.append("impact_not_evidence_supported")
        if not triage.get("classified"):
            blocking_reasons.append("tester_triage_not_recorded")
        elif triage.get("disposition") != "actionable":
            blocking_reasons.append("tester_disposition_not_actionable")
        if not model.get("description"):
            blocking_reasons.append("description_missing")
        if not model.get("recorded_steps"):
            blocking_reasons.append("reproduction_steps_missing")
        if not model.get("impact"):
            blocking_reasons.append("impact_statement_missing")
        if not model.get("endpoint"):
            blocking_reasons.append("affected_asset_missing")
        proof_context = model.get("proof_context") if isinstance(model.get("proof_context"), Mapping) else {}
        if not str(proof_context.get("security_property") or "").strip():
            blocking_reasons.append("security_property_missing")
        if not str(proof_context.get("expected_behavior") or "").strip():
            blocking_reasons.append("expected_behavior_missing")
        if not str(proof_context.get("observed_behavior") or "").strip():
            blocking_reasons.append("observed_behavior_missing")
        if not proof_context.get("candidate_flows"):
            blocking_reasons.append("candidate_flow_missing")
        if not proof_context.get("control_flows"):
            blocking_reasons.append("matched_control_missing")
        source_role = str(model.get("source_result_role") or "").casefold()
        source_candidate = model.get("source_submission_candidate")
        source_vuln_type = str(model.get("vuln_type") or "").casefold()
        if source_role == "observation":
            blocking_reasons.append("source_is_reconnaissance_observation")
        if source_candidate is False:
            blocking_reasons.append("source_explicitly_not_submission_candidate")
        if source_vuln_type in {"asset_observation", "builtin_fallback"}:
            blocking_reasons.append(f"source_type_{source_vuln_type}_is_not_vulnerability_proof")
        profile = str(model.get("evidence_profile") or "")
        if profile in {"http", "browser"} and not model.get("flows"):
            blocking_reasons.append("captured_http_flow_missing")
        if profile == "artifact" and not model.get("tool_output"):
            blocking_reasons.append("artifact_proof_missing")
        if model.get("exploitability") == "needs-human-review":
            blocking_reasons.append("exploitability_needs_human_validation")
        if model.get("finding_status") in {"duplicate", "rejected", "false_positive", "false-positive"}:
            blocking_reasons.append(f"finding_status_{model['finding_status']}")

        blocking_reasons = list(dict.fromkeys(blocking_reasons))
        submission_candidate = not blocking_reasons
        readiness = {
            "state": "candidate_for_human_approval" if submission_candidate else "human_review_required",
            "submission_candidate": submission_candidate,
            "human_approval_required": True,
            "evidence_bundle_closed_and_revalidated": True,
            "scan_id": int(scan_id),
            "scan_status": scan_status,
            "verification": verification,
            "triage": triage,
            "blocking_reasons": blocking_reasons,
            "review_items": issues,
        }
        title = " ".join(str(model.get("title") or "Finding").split())[:300]
        severity = str(model.get("severity") or "info")
        vector = str(model.get("cvss_vector") or "")
        score = model.get("cvss_score")
        lines = [
            f"# {_inline(title)}",
            "",
            (
                "**Candidate for human approval.** Evidence, claim verification, and tester triage satisfy the automated V6 draft gate; nothing is submitted automatically."
                if submission_candidate
                else "**Draft for human review.** A closed evidence bundle confirms the recorded artifacts' integrity; it does not independently establish a vulnerability or its impact."
            ),
            "",
            f"- Affected asset: {_inline(model.get('endpoint'))}",
            f"- Recorded severity: {_inline(severity.upper())}",
            f"- CVSS v3.1: {_inline(f'{score:.1f} ({vector})' if score is not None else 'not recorded')}",
            f"- Source scan / finding: `{int(scan_id)}` / `{int(finding_id)}`",
            f"- Evidence profile: {_inline(model.get('evidence_profile'))}",
            f"- Evidence bundle SHA-256: {_inline(model.get('bundle_sha256'))}",
            "",
            "## Summary and observed behavior",
            "",
            _block(model.get("description") or "Not recorded; add the observed behavior before submission."),
            "",
            "## Steps to reproduce",
            "",
            "These are recorded instructions and require tester validation; they may have been generated by the tool.",
            "",
            _block(model.get("recorded_steps") or "Not recorded; add authorized reproduction steps."),
            "",
            "## Security property and expected vs observed",
            "",
            f"- Security property: {_inline(proof_context.get('security_property') or 'Not recorded')}",
            "",
            "### Expected behavior",
            "",
            _block(proof_context.get("expected_behavior") or "Not recorded; candidate status is blocked."),
            "",
            "### Observed behavior",
            "",
            _block(proof_context.get("observed_behavior") or "Not recorded; candidate status is blocked."),
            "",
            "### Matched controls",
            "",
            *(
                [
                    f"- Candidate flow `{item.get('id')}` SHA-256 {_inline(item.get('sha256'))}"
                    for item in proof_context.get("candidate_flows") or []
                ]
                or ["- Candidate flow: not recorded"]
            ),
            *(
                [
                    f"- Control flow `{item.get('id')}` SHA-256 {_inline(item.get('sha256'))}"
                    for item in proof_context.get("control_flows") or []
                ]
                or ["- Control flow: not recorded"]
            ),
            "",
            "## Technical evidence",
            "",
        ]
        for index, flow in enumerate(model.get("flows") or [], start=1):
            lines.extend([
                f"### Captured flow {index}",
                f"- SHA-256: {_inline(flow.get('sha256'))}",
                f"- Captured at: {_inline(flow.get('created_at'))}",
                "", "**Redacted request**", "", _block(flow.get("request"), language="http"),
                "", "**Redacted response**", "", _block(flow.get("response"), language="http"), "",
            ])
        output = model.get("tool_output")
        if isinstance(output, Mapping):
            lines.extend([
                "### Recorded tool output", "",
                f"- Artifact SHA-256: {_inline(output.get('artifact_sha256'))}",
                f"- Lines: `{output['line_start']}-{output['line_end']}`; slice SHA-256: {_inline(output.get('slice_sha256'))}",
                "", _block(output.get("text")), "",
            ])
        lines.extend([
            "## Recorded impact", "",
            _block(model.get("impact") or "Not recorded; do not infer impact from the detector output."),
            "", "## Recorded remediation", "",
            _block(model.get("remediation") or "Not recorded; add or review remediation guidance."),
            "", "## V6 proof gate", "",
            f"- Submission candidate: `{'yes' if submission_candidate else 'no'}`",
            f"- Tester disposition: `{triage.get('disposition') or 'not-recorded'}`",
            f"- Verification record: `{verification.get('record_id') or 'not-recorded'}`",
            *(
                [f"- Blocking reasons: `{', '.join(blocking_reasons)}`"]
                if blocking_reasons else
                ["- Blocking reasons: `none`"]
            ),
            "", "## Review before submission", "",
            *(f"- [ ] {item}" for item in issues), "",
        ])
        markdown = "\n".join(lines)
        draft_model = {**model, "submission_readiness": readiness}
        return ReportArtifact(
            title=title,
            markdown=markdown,
            html=self.generator._html(markdown, model.get("images") or []),
            sha256=hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
            severity=severity,
            cvss_vector=vector,
            cvss_score=float(score) if score is not None else None,
            finding_ids=(int(finding_id),),
            flow_ids=tuple(int(flow["id"]) for flow in model.get("flows") or []),
            model=draft_model,
        )
