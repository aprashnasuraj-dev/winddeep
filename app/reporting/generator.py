"""Evidence-grounded deterministic report generation for P3."""
from __future__ import annotations

import base64
import hashlib
import html
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from app.duplicates import DuplicateDetector
from app.evidence.bundles import EvidenceBundleStore, EvidenceIntegrityError
from app.reporting.cvss import score_cvss31
from app.reporting.redaction import (
    redact_body,
    redact_headers,
    redact_mapping,
    redact_text,
    redact_url,
    redacted_http_request,
    redacted_http_response,
)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ReportingError(RuntimeError):
    """Raised when a report cannot be proven from persisted evidence."""


@dataclass(frozen=True, slots=True)
class ReportArtifact:
    """Canonical P3 report plus its deterministic self-contained HTML view."""

    title: str
    markdown: str
    html: str
    sha256: str
    severity: str
    cvss_vector: str
    cvss_score: float
    finding_ids: tuple[int, ...]
    flow_ids: tuple[int, ...]
    model: dict[str, Any]


class ReportGenerator:
    """Render findings/chains strictly from normalized findings and P2 bundles."""

    def __init__(self, database: Any, crypto: Any) -> None:
        self.database = database
        self.crypto = crypto
        self.evidence = EvidenceBundleStore(database, crypto)

    @staticmethod
    def _iso_timestamp(value: Any) -> str:
        try:
            timestamp = float(value)
        except (TypeError, ValueError):
            return "unknown"
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _finding(self, finding_id: int) -> dict[str, Any]:
        finding = self.database.get_finding(int(finding_id))
        if finding is None:
            raise ReportingError(f"finding not found: {finding_id}")
        return finding

    def _bundle(self, finding_id: int) -> dict[str, Any]:
        try:
            bundle = self.evidence.resolve(int(finding_id))
        except KeyError as exc:
            raise ReportingError(f"evidence bundle required for finding {finding_id}") from exc
        except EvidenceIntegrityError as exc:
            raise ReportingError(f"evidence bundle integrity validation failed for finding {finding_id}: {exc}") from exc
        except Exception as exc:
            if isinstance(exc, ReportingError):
                raise
            raise ReportingError(f"evidence bundle validation failed for finding {finding_id}: {exc}") from exc
        completeness = bundle.get("completeness") or {}
        if not completeness.get("closed"):
            missing = ", ".join(str(item) for item in completeness.get("missing") or []) or "unknown evidence"
            raise ReportingError(f"evidence bundle is incomplete for finding {finding_id}: {missing}")
        return bundle

    def _flow(self, flow_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM flows WHERE id = ?", (int(flow_id),)).fetchone()
        if row is None:
            raise ReportingError(f"captured flow not found: {flow_id}")
        item = dict(row)
        decoder = getattr(self.database, "decode_flow_row", None)
        if callable(decoder):
            item = decoder(item)
        return item

    def _flow_views(self, bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
        views: list[dict[str, Any]] = []
        for ref in bundle.get("flows") or []:
            flow_id = int(ref["id"])
            flow = self._flow(flow_id)
            request_headers = redact_headers(flow.get("request_headers") or {})
            response_headers = redact_headers(flow.get("response_headers") or {})
            request_content_type = next(
                (value for key, value in request_headers.items() if key.casefold() == "content-type"), ""
            )
            response_content_type = next(
                (value for key, value in response_headers.items() if key.casefold() == "content-type"), ""
            )
            views.append(
                {
                    "id": flow_id,
                    "sha256": str(ref["sha256"]),
                    "method": str(flow.get("method") or ""),
                    "url": redact_url(str(flow.get("url") or "")),
                    "status": flow.get("status"),
                    "created_at": self._iso_timestamp(flow.get("created_at")),
                    "timing_ms": flow.get("timing_ms"),
                    "request_headers": request_headers,
                    "response_headers": response_headers,
                    "request_body": redact_body(flow.get("request_body") or b"", content_type=request_content_type),
                    "response_body": redact_body(flow.get("response_body") or b"", content_type=response_content_type),
                    "request": redacted_http_request(flow),
                    "response": redacted_http_response(flow),
                    "replay_handle": f"flow:{flow_id}:{ref['sha256']}",
                }
            )
        views.sort(key=lambda item: (item["created_at"], item["id"], item["sha256"]))
        return views

    def _tool_output(self, bundle: Mapping[str, Any]) -> dict[str, Any] | None:
        output = bundle.get("tool_output")
        if not isinstance(output, Mapping):
            return None
        try:
            artifact = self.evidence.read_artifact(str(output["artifact_sha256"]))
        except Exception as exc:
            raise ReportingError(f"tool-output integrity validation failed: {exc}") from exc
        start = int(output["line_start"])
        end = int(output["line_end"])
        lines = artifact["content"].splitlines()
        if start < 1 or end < start or end > len(lines):
            raise ReportingError("tool-output line range no longer matches the artifact")
        selected = b"\n".join(lines[start - 1 : end]).decode("utf-8", errors="replace")
        digest = hashlib.sha256(b"\n".join(lines[start - 1 : end])).hexdigest()
        if digest != str(output.get("slice_sha256") or ""):
            raise ReportingError("tool-output slice integrity validation failed")
        return {
            "artifact_sha256": str(output["artifact_sha256"]),
            "line_start": start,
            "line_end": end,
            "slice_sha256": digest,
            "text": redact_text(selected),
        }

    def _dedup_context(
        self,
        finding: Mapping[str, Any],
        *,
        external_duplicates: Sequence[Mapping[str, Any]] | None,
    ) -> dict[str, Any]:
        detector = DuplicateDetector(self.database)
        current_id = int(finding["id"])
        matches: list[dict[str, Any]] = []
        for candidate in detector.internal(finding, target_id=int(finding["target_id"]), limit=25):
            try:
                candidate_id = int(candidate.identifier)
            except (TypeError, ValueError):
                continue
            if candidate_id == current_id:
                continue
            prior = self.database.get_finding(candidate_id)
            if prior is None:
                continue
            matches.append(
                {
                    "source": candidate.source,
                    "finding_id": candidate_id,
                    "score": candidate.score,
                    "exact": candidate.exact,
                    "first_seen_scan_id": prior.get("scan_id"),
                    "first_seen_at": self._iso_timestamp(prior.get("created_at")),
                    "title": redact_text(str(prior.get("title") or "")),
                }
            )
        matches.sort(
            key=lambda item: (
                0 if item["exact"] else 1,
                -float(item["score"]),
                str(item["first_seen_at"]),
                int(item["finding_id"]),
            )
        )
        external: list[dict[str, Any]] = []
        if external_duplicates is not None:
            for item in external_duplicates:
                external.append(
                    {
                        "source": redact_text(str(item.get("source") or "external")),
                        "identifier": redact_text(str(item.get("identifier") or item.get("id") or "")),
                        "score": float(item.get("score") or 0.0),
                        "state": redact_text(str(item.get("state") or "")),
                        "url": redact_url(str(item.get("url") or "")),
                    }
                )
            external.sort(key=lambda item: (item["source"], item["identifier"], -item["score"]))
        return {
            "internal": matches,
            "external_status": "not provided" if external_duplicates is None else "provided",
            "external": external,
        }

    def _redacted_images(self, bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
        observation = bundle.get("browser_observation")
        if not isinstance(observation, Mapping):
            return []
        redacted_sha = str(observation.get("redacted_screenshot_sha256") or "")
        if not redacted_sha:
            return []
        try:
            artifact = self.evidence.read_artifact(redacted_sha)
        except Exception as exc:
            raise ReportingError(f"redacted screenshot integrity validation failed: {exc}") from exc
        return [
            {
                "sha256": redacted_sha,
                "media_type": str(artifact.get("media_type") or "application/octet-stream"),
                "content": bytes(artifact["content"]),
                "final_url": redact_url(str(observation.get("final_url") or "")),
                "status": observation.get("status"),
                "viewport": redact_mapping(observation.get("viewport") or {}),
            }
        ]

    def _finding_model(
        self,
        finding_id: int,
        *,
        external_duplicates: Sequence[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        finding = self._finding(finding_id)
        bundle = self._bundle(finding_id)
        vector = str(finding.get("cvss_vector") or "").strip()
        if not vector:
            raise ReportingError(f"finding {finding_id} has no explicit CVSS v3.1 vector")
        try:
            cvss_score, cvss_severity = score_cvss31(vector)
        except ValueError as exc:
            raise ReportingError(f"invalid CVSS v3.1 vector for finding {finding_id}: {exc}") from exc
        flows = self._flow_views(bundle)
        if not flows:
            raise ReportingError(f"finding {finding_id} bundle has no captured flow")
        provenance = redact_mapping(bundle.get("provenance") or {"nodes": [], "edges": []})
        detector_ids = sorted(
            {
                str(node.get("detector_id"))
                for node in provenance.get("nodes") or []
                if isinstance(node, Mapping) and node.get("detector_id")
            }
        )
        title = redact_text(str(finding.get("title") or "Finding"))
        endpoint = redact_url(str(finding.get("endpoint") or flows[0]["url"]))
        exploitability = str(bundle.get("exploitability") or "observed")
        summary = (
            f"Detector {', '.join(f'`{item}`' for item in detector_ids) if detector_ids else '`unknown`'} "
            f"recorded **{title}** at `{endpoint}`. "
            "[evidence: bundle.finding + bundle.provenance]"
        )
        if exploitability == "needs-human-review":
            summary += " This candidate may require human review before any stronger conclusion."
        return {
            "kind": "finding",
            "title": title,
            "finding_id": int(finding_id),
            "fingerprint": str(bundle.get("finding", {}).get("fingerprint") or finding.get("fingerprint") or ""),
            "severity": cvss_severity,
            "stored_severity": str(finding.get("severity") or "info").lower(),
            "cvss_vector": vector,
            "cvss_score": cvss_score,
            "endpoint": endpoint,
            "bundle_sha256": str(bundle["bundle_sha256"]),
            "exploitability": exploitability,
            "confidence": redact_mapping(bundle.get("confidence") or {}),
            "summary": summary,
            "flows": flows,
            "tool_output": self._tool_output(bundle),
            "reproduction": redact_mapping(bundle.get("reproduction") or {}),
            "impact": redact_text(str(finding.get("impact") or "").strip()),
            "remediation": redact_text(str(finding.get("remediation") or "").strip()),
            "provenance": provenance,
            "duplicates": self._dedup_context(finding, external_duplicates=external_duplicates),
            "images": self._redacted_images(bundle),
            "browser_observation_present": isinstance(bundle.get("browser_observation"), Mapping),
            "captured_at": flows[0]["created_at"],
        }

    @staticmethod
    def _finding_markdown(model: Mapping[str, Any]) -> str:
        confidence = model.get("confidence") or {}
        lines = [
            f"# {model['title']}",
            "",
            f"- Severity: **{str(model['severity']).upper()}**",
            f"- CVSS v3.1: `{model['cvss_score']:.1f}` (`{model['cvss_vector']}`)",
            f"- Affected endpoint: `{model['endpoint']}`",
            f"- Finding fingerprint: `{model['fingerprint']}`",
            f"- Evidence bundle: `{model['bundle_sha256']}`",
            f"- Exploitability: `{model['exploitability']}`",
            f"- Confidence: `{float(confidence.get('score') or 0.0):.2f}` (`{confidence.get('band') or 'unknown'}`)",
            f"- Evidence timestamp: `{model['captured_at']}`",
            "",
            "## Summary",
            "",
            str(model["summary"]),
            "",
            "## Technical evidence",
            "",
        ]
        for index, flow in enumerate(model.get("flows") or [], start=1):
            lines.extend(
                [
                    f"### Captured flow {index}",
                    "",
                    f"- Evidence reference: `bundle.flows[{index - 1}]`",
                    f"- Replay handle: `{flow['replay_handle']}`",
                    f"- Method / URL: `{flow['method']} {flow['url']}`",
                    f"- Captured status: `{flow['status']}`",
                    f"- Flow SHA-256: `{flow['sha256']}`",
                    f"- Captured at: `{flow['created_at']}`",
                    "",
                    "#### Redacted request",
                    "",
                    "```http",
                    str(flow["request"]),
                    "```",
                    "",
                    "#### Redacted response",
                    "",
                    "```http",
                    str(flow["response"]),
                    "```",
                    "",
                ]
            )
        tool_output = model.get("tool_output")
        if isinstance(tool_output, Mapping):
            lines.extend(
                [
                    "### Raw detector output slice (redacted view)",
                    "",
                    f"- Artifact SHA-256: `{tool_output['artifact_sha256']}`",
                    f"- Lines: `{tool_output['line_start']}-{tool_output['line_end']}`",
                    f"- Slice SHA-256: `{tool_output['slice_sha256']}`",
                    "",
                    "```text",
                    str(tool_output["text"]),
                    "```",
                    "",
                ]
            )
        lines.extend(["## Observation-only reproduction", ""])
        reproduction = model.get("reproduction") or {}
        for number, step in enumerate(reproduction.get("steps") or [], start=1):
            lines.append(f"{number}. {step}")
        if reproduction.get("plan"):
            lines.extend(["", "Human-review plan:"])
            for step in reproduction["plan"]:
                lines.append(f"- {step}")
        lines.extend(["", "## Impact", ""])
        lines.append(model.get("impact") or "No impact statement was captured with this normalized finding.")
        lines.extend(["", "## Remediation", ""])
        lines.append(model.get("remediation") or "No remediation guidance was captured with this normalized finding.")
        lines.extend(["", "## Detector provenance / references", ""])
        nodes = (model.get("provenance") or {}).get("nodes") or []
        if not nodes:
            lines.append("- No provenance node was present.")
        for node in nodes:
            bits = [
                f"detector=`{node.get('detector_id')}`",
                f"engine=`{node.get('name')}`",
                f"version=`{node.get('version')}`",
            ]
            if node.get("source"):
                bits.append(f"source=`{node.get('source')}`")
            if node.get("source_digest"):
                bits.append(f"source_digest=`{node.get('source_digest')}`")
            if node.get("reference"):
                bits.append(f"reference=`{node.get('reference')}`")
            lines.append("- " + "; ".join(bits))
        lines.extend(["", "## Duplicate context", ""])
        duplicates = model.get("duplicates") or {}
        internal = duplicates.get("internal") or []
        if internal:
            for item in internal:
                lines.append(
                    f"- Internal match: finding `{item['finding_id']}`, score `{item['score']:.4f}`, "
                    f"first-seen scan `{item['first_seen_scan_id']}`, first-seen at `{item['first_seen_at']}`."
                )
        else:
            lines.append("- Internal duplicate match: none recorded.")
        lines.append(f"- External duplicate check: {duplicates.get('external_status') or 'not provided'}.")
        for item in duplicates.get("external") or []:
            lines.append(
                f"  - `{item['source']}` `{item['identifier']}` score `{item['score']:.4f}` state `{item['state']}` URL `{item['url']}`"
            )
        if model.get("browser_observation_present"):
            lines.extend(["", "## Browser observation", ""])
            if model.get("images"):
                lines.append("- A redacted screenshot is embedded in the self-contained HTML and export bundle.")
            else:
                lines.append("- A raw browser screenshot exists in encrypted evidence; no redacted screenshot was supplied, so it is not embedded or exported.")
        lines.extend(
            [
                "",
                "## Evidence integrity",
                "",
                f"- Bundle SHA-256: `{model['bundle_sha256']}`",
                "- Every request/response and tool-output slice above was revalidated against its persisted P2 evidence reference at render time.",
                "",
            ]
        )
        return "\n".join(lines).replace("\r\n", "\n").replace("\r", "\n")

    @staticmethod
    def _html(markdown: str, images: Sequence[Mapping[str, Any]]) -> str:
        image_html: list[str] = []
        for index, image in enumerate(images, start=1):
            payload = base64.b64encode(bytes(image["content"])).decode("ascii")
            media_type = html.escape(str(image["media_type"]), quote=True)
            digest = html.escape(str(image["sha256"]), quote=True)
            image_html.append(
                f'<figure><img alt="Redacted evidence screenshot {index}" src="data:{media_type};base64,{payload}"><figcaption>SHA-256 {digest}</figcaption></figure>'
            )
        escaped = html.escape(markdown)
        return (
            "<!doctype html>\n"
            '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>Windeep evidence report</title>"
            "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:1100px;margin:0 auto;padding:32px;line-height:1.5}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;padding:20px;border-radius:8px}"
            "img{max-width:100%;height:auto;border:1px solid #ccc}figcaption{font-family:monospace;font-size:.85rem}</style>"
            "</head><body><main><pre>"
            + escaped
            + "</pre>"
            + "".join(image_html)
            + "</main></body></html>\n"
        )

    def render_finding(
        self,
        finding_id: int,
        *,
        external_duplicates: Sequence[Mapping[str, Any]] | None = None,
    ) -> ReportArtifact:
        """Render one evidence-backed finding with no model-authored claims."""
        model = self._finding_model(finding_id, external_duplicates=external_duplicates)
        markdown = self._finding_markdown(model)
        html_view = self._html(markdown, model.get("images") or [])
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        return ReportArtifact(
            title=str(model["title"]),
            markdown=markdown,
            html=html_view,
            sha256=digest,
            severity=str(model["severity"]),
            cvss_vector=str(model["cvss_vector"]),
            cvss_score=float(model["cvss_score"]),
            finding_ids=(int(finding_id),),
            flow_ids=tuple(int(flow["id"]) for flow in model["flows"]),
            model=model,
        )

    def render_chain(
        self,
        finding_ids: Sequence[int],
        *,
        external_duplicates: Mapping[int, Sequence[Mapping[str, Any]]] | None = None,
    ) -> ReportArtifact:
        """Render an ordered evidence chain; input order defines narrative hop order."""
        ordered_ids = tuple(int(value) for value in finding_ids)
        if len(ordered_ids) < 2 or len(set(ordered_ids)) != len(ordered_ids):
            raise ReportingError("a chain requires at least two unique finding ids")
        models = [
            self._finding_model(
                finding_id,
                external_duplicates=(external_duplicates or {}).get(finding_id),
            )
            for finding_id in ordered_ids
        ]
        placeholders = ",".join("?" for _ in ordered_ids)
        with self.database._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM chains
                WHERE source_finding_id IN ({placeholders}) AND target_finding_id IN ({placeholders})
                ORDER BY created_at ASC, id ASC
                """,
                (*ordered_ids, *ordered_ids),
            ).fetchall()
        edges = [dict(row) for row in rows]
        edge_map = {(int(row["source_finding_id"]), int(row["target_finding_id"])): row for row in edges}
        missing_pairs = [pair for pair in zip(ordered_ids, ordered_ids[1:]) if pair not in edge_map]
        if missing_pairs:
            raise ReportingError(f"chain relation missing for ordered hop(s): {missing_pairs}")
        highest = max(models, key=lambda item: (_SEVERITY_RANK.get(str(item["severity"]), -1), float(item["cvss_score"])))
        title = "Evidence chain: " + " → ".join(str(item["title"]) for item in models)
        lines = [
            f"# {title}",
            "",
            f"- Chain severity: **{str(highest['severity']).upper()}**",
            f"- Highest hop CVSS v3.1: `{highest['cvss_score']:.1f}` (`{highest['cvss_vector']}`)",
            "- Chain severity rule: maximum severity across all evidence-backed hops; an `amplifies` relation strengthens the narrative linkage but does not exceed the maximum hop severity.",
            "",
            "## Chain narrative",
            "",
        ]
        for index, model in enumerate(models, start=1):
            lines.extend(
                [
                    f"### Hop {index}: {model['title']}",
                    "",
                    f"- Severity / CVSS: `{str(model['severity']).upper()}` / `{model['cvss_score']:.1f}` (`{model['cvss_vector']}`)",
                    f"- Evidence bundle: `{model['bundle_sha256']}`",
                    f"- Endpoint: `{model['endpoint']}`",
                    f"- Exploitability: `{model['exploitability']}`",
                ]
            )
            for flow in model["flows"]:
                lines.append(f"- Evidence flow: `{flow['replay_handle']}` status `{flow['status']}`")
            if index < len(models):
                edge = edge_map[(ordered_ids[index - 1], ordered_ids[index])]
                lines.extend(
                    [
                        "",
                        f"Relation to next hop: **{edge['edge_type']}** (weight `{float(edge['weight']):.3f}`) — {redact_text(str(edge.get('rationale') or ''))}",
                    ]
                )
            lines.append("")
        lines.extend(["## Observation-only reproduction", ""])
        for index, model in enumerate(models, start=1):
            lines.append(f"### Hop {index}")
            for number, step in enumerate((model.get("reproduction") or {}).get("steps") or [], start=1):
                lines.append(f"{number}. {step}")
            lines.append("")
        lines.extend(["## Duplicate context", ""])
        for model in models:
            lines.append(f"### {model['title']}")
            duplicates = model.get("duplicates") or {}
            internal = duplicates.get("internal") or []
            if internal:
                for item in internal:
                    lines.append(
                        f"- Internal match: finding `{item['finding_id']}`, score `{item['score']:.4f}`, first-seen scan `{item['first_seen_scan_id']}`, first-seen at `{item['first_seen_at']}`."
                    )
            else:
                lines.append("- Internal duplicate match: none recorded.")
            lines.append(f"- External duplicate check: {duplicates.get('external_status') or 'not provided'}.")
            lines.append("")
        lines.extend(["## Detector provenance / references", ""])
        for model in models:
            for node in (model.get("provenance") or {}).get("nodes") or []:
                lines.append(
                    f"- Hop `{model['finding_id']}` detector `{node.get('detector_id')}` engine `{node.get('name')}` version `{node.get('version')}` source digest `{node.get('source_digest')}`."
                )
        markdown = "\n".join(lines).replace("\r\n", "\n").replace("\r", "\n")
        images = [image for model in models for image in model.get("images") or []]
        html_view = self._html(markdown, images)
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        chain_model = {
            "kind": "chain",
            "title": title,
            "severity": highest["severity"],
            "cvss_vector": highest["cvss_vector"],
            "cvss_score": highest["cvss_score"],
            "hops": models,
            "edges": edges,
            "images": images,
        }
        return ReportArtifact(
            title=title,
            markdown=markdown,
            html=html_view,
            sha256=digest,
            severity=str(highest["severity"]),
            cvss_vector=str(highest["cvss_vector"]),
            cvss_score=float(highest["cvss_score"]),
            finding_ids=ordered_ids,
            flow_ids=tuple(int(flow["id"]) for model in models for flow in model["flows"]),
            model=chain_model,
        )
