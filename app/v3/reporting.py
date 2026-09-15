"""P3 renderer for P1-backed P2 v2 forensic bundles."""
from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass
from typing import Any, Mapping

from app.reporting.cvss import score_cvss31
from app.v3.evidence import ForensicEvidenceBundleStore, GuardedEvidenceVault


class ForensicReportingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ForensicReport:
    finding_id: int
    title: str
    severity: str
    cvss_vector: str
    cvss_score: float
    markdown: str
    html: str
    sha256: str


class ForensicReportGenerator:
    """Render only claims that can be traced to a closed v2 forensic bundle."""

    def __init__(self, database: Any, vault: GuardedEvidenceVault) -> None:
        self.database = database
        self.vault = vault
        self.bundles = ForensicEvidenceBundleStore(database, vault)

    @staticmethod
    def _html(markdown: str) -> str:
        return (
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:auto;padding:32px;line-height:1.5}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;padding:20px;border-radius:8px}</style>"
            "</head><body><pre>" + html.escape(markdown) + "</pre></body></html>\n"
        )

    def render_finding(self, finding_id: int) -> ForensicReport:
        self.vault.authorize("report.render")
        finding = self.database.get_finding(finding_id)
        if finding is None:
            raise ForensicReportingError(f"finding not found: {finding_id}")
        bundle = self.bundles.resolve(finding_id)
        if not (bundle.get("completeness") or {}).get("closed"):
            raise ForensicReportingError("forensic evidence bundle is incomplete")
        vector = str(finding.get("cvss_vector") or "").strip()
        if not vector:
            raise ForensicReportingError("explicit CVSS v3.1 vector is required")
        try:
            score, severity = score_cvss31(vector)
        except ValueError as exc:
            raise ForensicReportingError(str(exc)) from exc
        flow_sections: list[str] = []
        for index, ref in enumerate(bundle.get("flows") or [], start=1):
            self.vault.authorize("report.flow-redaction")
            request_view = self.vault.redactor.redact_artifact(
                str(ref["raw_request_sha256"]),
                scan_id=int(finding["scan_id"]),
                path=f"report.finding[{finding_id}].flow[{ref['id']}].request",
            ).content.decode("utf-8", errors="replace")
            response_view = self.vault.redactor.redact_artifact(
                str(ref["raw_response_sha256"]),
                scan_id=int(finding["scan_id"]),
                path=f"report.finding[{finding_id}].flow[{ref['id']}].response",
            ).content.decode("utf-8", errors="replace")
            flow_sections.extend(
                [
                    f"### Flow {index}",
                    "",
                    f"- Flow ID: `{ref['id']}`",
                    f"- Flow SHA-256: `{ref['flow_sha256']}`",
                    f"- Request SHA-256: `{ref['raw_request_sha256']}`",
                    f"- Response SHA-256: `{ref['raw_response_sha256']}`",
                    f"- Replay handle: `{bundle['reproduction']['replay_handle']}`",
                    "",
                    "#### Redacted request",
                    "```http",
                    request_view,
                    "```",
                    "",
                    "#### Redacted response",
                    "```http",
                    response_view,
                    "```",
                    "",
                ]
            )
        provenance_lines = []
        for node in (bundle.get("provenance") or {}).get("nodes") or []:
            provenance_lines.append(
                f"- detector=`{node.get('detector_id')}`; engine=`{node.get('name')}`; version=`{node.get('version')}`; source_digest=`{node.get('source_digest')}`"
            )
        reproduction = bundle.get("reproduction") or {}
        repro_lines = [f"{idx}. {step}" for idx, step in enumerate(reproduction.get("steps") or [], start=1)]
        title = str(finding.get("title") or "Finding")
        lines = [
            f"# {title}",
            "",
            f"- Severity: **{severity.upper()}**",
            f"- CVSS v3.1: `{score:.1f}` (`{vector}`)",
            f"- Endpoint: `{finding.get('endpoint') or ''}`",
            f"- Exploitability: `{bundle.get('exploitability')}`",
            f"- Evidence bundle: `{bundle.get('bundle_sha256')}`",
            "",
            "## Summary",
            "",
            str(finding.get("description") or "Recorded detector observation."),
            "",
            "## Technical evidence",
            "",
            *flow_sections,
            "## Observation-only reproduction",
            "",
            *repro_lines,
            "",
            "## Impact",
            "",
            str(finding.get("impact") or "No impact statement was recorded."),
            "",
            "## Remediation",
            "",
            str(finding.get("remediation") or "No remediation statement was recorded."),
            "",
            "## Detector provenance / references",
            "",
            *(provenance_lines or ["- No detector provenance was recorded."]),
            "",
            "## Evidence integrity",
            "",
            "- P1 raw request/response and tool-output hashes were revalidated from encrypted custody at render time.",
            "- No exploitation step was executed by the report generator.",
            "",
        ]
        markdown = "\n".join(lines).replace("\r\n", "\n").replace("\r", "\n")
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        return ForensicReport(
            finding_id=finding_id,
            title=title,
            severity=severity,
            cvss_vector=vector,
            cvss_score=score,
            markdown=markdown,
            html=self._html(markdown),
            sha256=digest,
        )


__all__ = ["ForensicReport", "ForensicReportGenerator", "ForensicReportingError"]
