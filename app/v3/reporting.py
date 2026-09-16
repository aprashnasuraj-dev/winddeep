"""Deterministic v3 scan report with tester triage and no policy gate.

Every finding for the scan is emitted. Tester classification affects ordering and
labels only. Existing P3 evidence reports are embedded when available; a missing
bundle never suppresses the normalized finding from the v3 scan report.
"""
from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass
from typing import Any

from app.reporting.generator import ReportGenerator
from app.reporting.redaction import redact_text, redact_url
from app.v3.triage import ManualTriage


@dataclass(frozen=True, slots=True)
class V3ReportArtifact:
    markdown: str
    html: str
    sha256: str
    finding_ids: tuple[int, ...]


class V3ReportGenerator:
    """Render every scan finding regardless of tester triage state."""

    def __init__(
        self,
        database: Any,
        crypto: Any,
        *,
        triage: ManualTriage | None = None,
        finding_renderer: Any | None = None,
    ) -> None:
        self.database = database
        self.crypto = crypto
        self.triage = triage or ManualTriage(database, _NullAudit())
        self.finding_renderer = finding_renderer or ReportGenerator(database, crypto)

    def _verification(self, finding_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            record = conn.execute(
                "SELECT id, artifact_sha256 FROM verification_record WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (int(finding_id),),
            ).fetchone()
            if record is None:
                return {"state": "not-recorded", "artifact_sha256": "", "claims": []}
            rows = conn.execute(
                "SELECT claim_key, state, evidence_refs, plan FROM verification_claim WHERE record_id = ? ORDER BY id ASC",
                (int(record["id"]),),
            ).fetchall()
        decoder = getattr(self.database, "_dec", None)
        claims: list[dict[str, Any]] = []
        for row in rows:
            evidence_refs: Any = []
            plan: Any = []
            if callable(decoder):
                evidence_refs = json.loads(decoder(str(row["evidence_refs"]), field="verification_claim.evidence_refs"))
                plan = json.loads(decoder(str(row["plan"]), field="verification_claim.plan"))
            claims.append(
                {
                    "claim": str(row["claim_key"]),
                    "state": str(row["state"]),
                    "evidence_refs": evidence_refs,
                    "plan": plan,
                }
            )
        order = {"verified": 0, "partially_verified": 1, "needs-review": 2}
        state = max((str(item["state"]) for item in claims), key=lambda value: order.get(value, 3), default="not-recorded")
        return {"state": state, "artifact_sha256": str(record["artifact_sha256"]), "claims": claims}

    @staticmethod
    def _fallback(finding: dict[str, Any], error: Exception) -> str:
        lines = [
            "### Normalized finding record",
            "",
            f"- Endpoint: `{redact_url(str(finding.get('endpoint') or ''))}`",
            f"- Tool: `{redact_text(str(finding.get('tool') or 'unknown'))}`",
            f"- Vulnerability type: `{redact_text(str(finding.get('vuln_type') or 'unknown'))}`",
            f"- Confidence: `{float(finding.get('confidence') or 0.0):.2f}`",
            "",
            "#### Technical detail",
            "",
            redact_text(str(finding.get("description") or "No normalized description was recorded.")),
            "",
            "#### Observation-only reproduction",
            "",
            redact_text(str(finding.get("steps") or "No normalized reproduction steps were recorded.")),
            "",
            "#### Impact",
            "",
            redact_text(str(finding.get("impact") or "No impact statement was recorded.")),
            "",
            "#### Remediation",
            "",
            redact_text(str(finding.get("remediation") or "No remediation guidance was recorded.")),
            "",
            "#### Evidence detail availability",
            "",
            f"The full P3 evidence-backed subsection could not be rendered: `{redact_text(str(error))}`. The finding remains in this report for tester review.",
        ]
        return "\n".join(lines)

    def render_scan(self, scan_id: int) -> V3ReportArtifact:
        ranked = self.triage.rank_scan(int(scan_id))
        lines = [
            "# Windeep v3 scan report",
            "",
            "Every normalized finding from this scan is included. Tester triage changes ordering and disposition only; it never suppresses a finding.",
            "",
            "## Ranked finding index",
            "",
            "| Rank | Finding | Severity | Disposition | Tester score | Asset class |",
            "|---:|---|---|---|---:|---|",
        ]
        for index, item in enumerate(ranked, start=1):
            finding = item["finding"]
            lines.append(
                f"| {index} | {redact_text(str(finding.get('title') or 'Finding'))} | {str(finding.get('severity') or 'info').upper()} | {item['disposition']} | {float(item['score']):.2f} | {item['asset_class']} |"
            )
        lines.extend(["", "## Findings", ""])
        finding_ids: list[int] = []
        for index, item in enumerate(ranked, start=1):
            finding = item["finding"]
            finding_id = int(item["finding_id"])
            finding_ids.append(finding_id)
            verification = self._verification(finding_id)
            lines.extend(
                [
                    f"## {index}. {redact_text(str(finding.get('title') or 'Finding'))}",
                    "",
                    f"**Verdict:** `{item['disposition']}` · tester rank `{float(item['score']):.2f}` · asset `{item['asset_class']}`",
                    "",
                    "### Acceptance / handling rationale",
                    "",
                    redact_text(str(item["rationale"])),
                    "",
                    "### Verification status",
                    "",
                    f"- Overall: `{verification['state']}`",
                ]
            )
            if verification["artifact_sha256"]:
                lines.append(f"- Verification artifact: `{verification['artifact_sha256']}`")
            for claim in verification["claims"]:
                lines.append(f"- `{claim['claim']}`: `{claim['state']}`")
            vector = str(finding.get("cvss_vector") or "")
            score = finding.get("cvss_score")
            lines.extend(
                [
                    "",
                    "### Severity",
                    "",
                    f"- Severity: `{str(finding.get('severity') or 'info').upper()}`",
                    f"- CVSS v3.1: `{score if score is not None else 'not recorded'}` `{vector or 'not recorded'}`",
                    "",
                    "### Evidence, reproduction, impact, remediation, and provenance",
                    "",
                ]
            )
            try:
                rendered = self.finding_renderer.render_finding(finding_id)
                detail = str(rendered.markdown).strip()
                model = getattr(rendered, "model", {}) or {}
                bundle_sha = str(model.get("bundle_sha256") or "") if isinstance(model, dict) else ""
                if bundle_sha:
                    lines.append(f"Evidence bundle: `{bundle_sha}`")
                    lines.append("")
                lines.append(detail)
            except Exception as exc:
                lines.append(self._fallback(finding, exc))
            lines.extend(["", "---", ""])
        markdown = "\n".join(lines).replace("\r\n", "\n").replace("\r", "\n")
        if not markdown.endswith("\n"):
            markdown += "\n"
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        html_view = (
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Windeep v3 report</title></head>"
            "<body><main><pre>" + html.escape(markdown) + "</pre></main></body></html>\n"
        )
        return V3ReportArtifact(markdown=markdown, html=html_view, sha256=digest, finding_ids=tuple(finding_ids))


class _NullAudit:
    def append(self, event: str, data: dict[str, Any]) -> None:
        return None


__all__ = ["V3ReportArtifact", "V3ReportGenerator"]
