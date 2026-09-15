"""Deterministic, encrypted-at-rest evidence bundles for Windeep findings.

P2 deliberately binds findings to already-captured evidence.  It never performs
network activity, launches tools, or invents confirmation.  Bundle construction
is therefore safe to run after the scheduler has persisted a finding, flow, and
raw detector artifact.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from typing import Any


BUNDLE_SCHEMA = "windeep.evidence-bundle.v1"
_EXPLOITABILITY = {"observed", "needs-human-review"}
_FLOW_HASH_FIELDS = (
    "method",
    "url",
    "scheme",
    "host",
    "port",
    "path",
    "query",
    "request_headers",
    "request_body",
    "status",
    "response_headers",
    "response_body",
    "timing_ms",
    "tls_info",
    "client_ip",
    "tags",
    "created_at",
)


class EvidenceIntegrityError(RuntimeError):
    """Raised when persisted evidence no longer matches its recorded digest."""


class BundleIncompleteError(RuntimeError):
    """Raised when a bundle is asked to close without required evidence."""


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"encoding": "base64", "data": base64.b64encode(bytes(value)).decode("ascii")}
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        _json_safe(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class EvidenceBundleStore:
    """Construct, persist, and revalidate append-only finding evidence bundles."""

    def __init__(self, database: Any, crypto: Any) -> None:
        self.database = database
        self.crypto = crypto

    def put_artifact(
        self,
        *,
        scan_id: int,
        tool_run_id: int | None,
        kind: str,
        media_type: str,
        content: bytes,
    ) -> dict[str, Any]:
        """Persist immutable encrypted bytes under their content SHA-256."""
        raw = bytes(content)
        digest = _sha256(raw)
        encoded = base64.b64encode(raw).decode("ascii")
        encrypted = self.crypto.encrypt_text(
            encoded,
            aad=f"windeep:evidence-blob:{digest}".encode("utf-8"),
        )
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT sha256, size FROM evidence_blobs WHERE sha256 = ?",
                (digest,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO evidence_blobs(
                        sha256, origin_scan_id, origin_tool_run_id, kind,
                        media_type, size, payload, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (digest, scan_id, tool_run_id, kind, media_type, len(raw), encrypted, time.time()),
                )
            elif int(row["size"]) != len(raw):
                raise EvidenceIntegrityError("artifact digest collision or size mismatch")
        return {
            "sha256": digest,
            "size": len(raw),
            "kind": kind,
            "media_type": media_type,
        }

    def read_artifact(self, sha256: str) -> dict[str, Any]:
        """Read and hash-verify an encrypted content-addressed artifact."""
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence_blobs WHERE sha256 = ?",
                (sha256,),
            ).fetchone()
        if row is None:
            raise KeyError(f"evidence artifact not found: {sha256}")
        item = dict(row)
        encoded = self.crypto.decrypt_text(
            str(item["payload"]),
            aad=f"windeep:evidence-blob:{sha256}".encode("utf-8"),
        )
        try:
            content = base64.b64decode(encoded.encode("ascii"), validate=True)
        except Exception as exc:  # encrypted payload authenticated, base64 is schema-level validation
            raise EvidenceIntegrityError("artifact payload is not valid encoded evidence") from exc
        if _sha256(content) != sha256 or len(content) != int(item["size"]):
            raise EvidenceIntegrityError(f"artifact hash mismatch: {sha256}")
        return {
            "sha256": sha256,
            "size": int(item["size"]),
            "kind": str(item["kind"]),
            "media_type": str(item["media_type"]),
            "origin_scan_id": int(item["origin_scan_id"]),
            "origin_tool_run_id": item["origin_tool_run_id"],
            "content": content,
        }

    def _decoded_flow(self, flow_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if row is None:
            raise KeyError(f"flow not found: {flow_id}")
        item = dict(row)
        decoder = getattr(self.database, "decode_flow_row", None)
        if callable(decoder):
            item = decoder(item)
        return item

    @staticmethod
    def _flow_digest(flow: Mapping[str, Any]) -> str:
        content = {key: flow.get(key) for key in _FLOW_HASH_FIELDS}
        return _sha256(_canonical(content))

    def _flow_ref(self, flow_id: int) -> dict[str, Any]:
        flow = self._decoded_flow(flow_id)
        return {
            "id": int(flow_id),
            "sha256": self._flow_digest(flow),
            "method": str(flow.get("method") or ""),
            "url": str(flow.get("url") or ""),
            "status": int(flow["status"]) if flow.get("status") is not None else None,
        }

    @staticmethod
    def _validate_line_range(content: bytes, start: int | None, end: int | None) -> dict[str, Any] | None:
        if start is None and end is None:
            return None
        if start is None or end is None or start < 1 or end < start:
            raise ValueError("invalid artifact line range")
        lines = content.splitlines()
        if end > len(lines):
            raise ValueError("artifact line range exceeds captured output")
        selected = b"\n".join(lines[start - 1 : end])
        return {"line_start": start, "line_end": end, "slice_sha256": _sha256(selected)}

    @staticmethod
    def _normalize_provenance(provenance: Mapping[str, Any] | None) -> dict[str, Any]:
        source = dict(provenance or {})
        raw_nodes = source.get("nodes") or []
        raw_edges = source.get("edges") or []
        if not isinstance(raw_nodes, Sequence) or isinstance(raw_nodes, (str, bytes)):
            raise ValueError("provenance nodes must be a sequence")
        if not isinstance(raw_edges, Sequence) or isinstance(raw_edges, (str, bytes)):
            raise ValueError("provenance edges must be a sequence")
        nodes: list[dict[str, Any]] = []
        for raw in raw_nodes:
            if not isinstance(raw, Mapping):
                raise ValueError("provenance node must be an object")
            node = {str(key): _json_safe(value) for key, value in raw.items()}
            for key in ("id", "kind", "name", "version", "detector_id"):
                if not str(node.get(key) or "").strip():
                    raise ValueError(f"provenance node missing {key}")
            nodes.append(node)
        edges: list[dict[str, Any]] = []
        for raw in raw_edges:
            if not isinstance(raw, Mapping):
                raise ValueError("provenance edge must be an object")
            edge = {str(key): _json_safe(value) for key, value in raw.items()}
            edges.append(edge)
        nodes.sort(key=lambda item: (str(item.get("id")), _canonical(item)))
        edges.sort(key=lambda item: _canonical(item))
        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _confidence(value: Any) -> dict[str, Any]:
        score = max(0.0, min(1.0, float(value or 0.0)))
        if score >= 0.80:
            band = "high"
        elif score >= 0.50:
            band = "medium"
        else:
            band = "low"
        return {
            "score": score,
            "band": band,
            "definition": "high >= 0.80; medium >= 0.50 and < 0.80; low < 0.50",
        }

    @staticmethod
    def _is_reflection(finding: Mapping[str, Any]) -> bool:
        text = f"{finding.get('vuln_type', '')} {finding.get('title', '')}".casefold()
        return any(token in text for token in ("reflection", "reflected", "xss"))

    @staticmethod
    def _is_browser_observable(finding: Mapping[str, Any]) -> bool:
        evidence = finding.get("evidence")
        return bool(isinstance(evidence, Mapping) and evidence.get("browser_observed"))

    @staticmethod
    def _reproduction(flows: Sequence[Mapping[str, Any]], human_plan: Sequence[str]) -> dict[str, Any] | None:
        if not flows:
            return None
        primary = flows[0]
        handle = f"flow:{primary['id']}:{primary['sha256']}"
        status = "no captured status" if primary.get("status") is None else f"HTTP {primary['status']}"
        steps = [
            f"Send the captured {primary['method']} request to `{primary['url']}` using the recorded authorization context (`{handle}`).",
            f"Observe the recorded response ({status}) and compare it with flow SHA-256 `{primary['sha256']}`.",
            "Stop at the recorded observation point; do not perform exploitation or state-changing actions.",
        ]
        return {
            "replay_handle": handle,
            "steps": steps,
            "plan": [str(item) for item in human_plan],
        }

    @staticmethod
    def _completeness(
        *,
        flows: Sequence[Mapping[str, Any]],
        tool_output: Mapping[str, Any] | None,
        provenance: Mapping[str, Any],
        reproduction: Mapping[str, Any] | None,
        exploitability: str,
        human_plan: Sequence[str],
        reflection_required: bool,
        reflected_marker: Mapping[str, Any] | None,
        browser_required: bool,
        browser_observation: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        checks: list[tuple[str, bool]] = [
            ("flow", bool(flows)),
            ("tool_output", bool(tool_output)),
            ("provenance", bool(provenance.get("nodes"))),
            ("reproduction", bool(reproduction and reproduction.get("replay_handle"))),
        ]
        if exploitability == "needs-human-review":
            checks.append(("human_plan", bool(human_plan)))
        if reflection_required:
            checks.append(("reflected_marker", bool(reflected_marker)))
        if browser_required:
            checks.append(("browser_observation", bool(browser_observation)))
        missing = [name for name, present in checks if not present]
        score = sum(1 for _name, present in checks if present) / len(checks)
        return {"score": round(score, 6), "missing": missing, "closed": not missing}

    def build(
        self,
        *,
        finding: Mapping[str, Any],
        scan_id: int,
        tool_run_id: int | None,
        flow_ids: Sequence[int],
        artifact_sha256: str | None,
        line_start: int | None,
        line_end: int | None,
        provenance: Mapping[str, Any] | None,
        exploitability: str,
        human_plan: Sequence[str] = (),
        reflected_marker: Mapping[str, Any] | None = None,
        browser_observation: Mapping[str, Any] | None = None,
        close: bool = False,
    ) -> dict[str, Any]:
        """Build a deterministic bundle and optionally require it to be complete."""
        if exploitability not in _EXPLOITABILITY:
            raise ValueError(f"unsupported exploitability: {exploitability}")
        finding_id = int(finding["id"])
        flows = [self._flow_ref(int(flow_id)) for flow_id in sorted({int(value) for value in flow_ids})]
        tool_output: dict[str, Any] | None = None
        if artifact_sha256:
            artifact = self.read_artifact(artifact_sha256)
            line_ref = self._validate_line_range(artifact["content"], line_start, line_end)
            if line_ref is None:
                raise ValueError("artifact line range is required when tool output is referenced")
            tool_output = {
                "artifact_sha256": artifact_sha256,
                "media_type": artifact["media_type"],
                "size": artifact["size"],
                **line_ref,
            }
        normalized_provenance = self._normalize_provenance(provenance)
        plan = tuple(str(item) for item in human_plan if str(item).strip())
        reproduction = self._reproduction(flows, plan)

        screenshot: dict[str, Any] | None = None
        if browser_observation:
            screenshot = dict(browser_observation)
            screenshot_sha = str(screenshot.get("screenshot_sha256") or "")
            if screenshot_sha:
                self.read_artifact(screenshot_sha)
            else:
                screenshot = None

        reflection = dict(reflected_marker) if reflected_marker else None
        completeness = self._completeness(
            flows=flows,
            tool_output=tool_output,
            provenance=normalized_provenance,
            reproduction=reproduction,
            exploitability=exploitability,
            human_plan=plan,
            reflection_required=self._is_reflection(finding),
            reflected_marker=reflection,
            browser_required=self._is_browser_observable(finding),
            browser_observation=screenshot,
        )
        if close and completeness["missing"]:
            severity = str(finding.get("severity") or "info").lower()
            raise BundleIncompleteError(
                f"cannot close {severity} evidence bundle; missing: {', '.join(completeness['missing'])}"
            )

        finding_ref = {
            "fingerprint": str(finding.get("fingerprint") or ""),
            "severity": str(finding.get("severity") or "info").lower(),
            "title": str(finding.get("title") or ""),
            "vuln_type": str(finding.get("vuln_type") or ""),
            "tool": str(finding.get("tool") or ""),
            "endpoint": finding.get("endpoint"),
        }
        payload = {
            "schema": BUNDLE_SCHEMA,
            "finding": finding_ref,
            "flows": flows,
            "tool_output": tool_output,
            "provenance": normalized_provenance,
            "reproduction": reproduction,
            "reflected_marker": reflection,
            "browser_observation": screenshot,
            "confidence": self._confidence(finding.get("confidence")),
            "exploitability": exploitability,
            "completeness": {
                **completeness,
                "closed": bool(close and not completeness["missing"]),
            },
        }
        canonical = _canonical(payload)
        digest = _sha256(canonical)
        encrypted = self.crypto.encrypt_text(
            canonical.decode("utf-8"),
            aad=f"windeep:evidence-bundle:{finding_id}".encode("utf-8"),
        )
        now = time.time()
        state = "closed" if payload["completeness"]["closed"] else "incomplete"
        with self.database._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM evidence_bundles WHERE finding_id = ? AND bundle_sha256 = ?",
                (finding_id, digest),
            ).fetchone()
            if existing is None:
                previous = conn.execute(
                    "SELECT id FROM evidence_bundles WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                    (finding_id,),
                ).fetchone()
                conn.execute(
                    """
                    INSERT INTO evidence_bundles(
                        finding_id, scan_id, tool_run_id, schema_version,
                        bundle_sha256, completeness_score, state, payload,
                        supersedes_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        scan_id,
                        tool_run_id,
                        BUNDLE_SCHEMA,
                        digest,
                        float(payload["completeness"]["score"]),
                        state,
                        encrypted,
                        int(previous["id"]) if previous is not None else None,
                        now,
                    ),
                )
        return {**payload, "bundle_sha256": digest, "canonical_json": canonical.decode("utf-8")}

    def resolve(self, finding_id: int) -> dict[str, Any]:
        """Resolve the latest bundle and revalidate every referenced evidence hash."""
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence_bundles WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                (finding_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"evidence bundle not found for finding: {finding_id}")
        item = dict(row)
        canonical_text = self.crypto.decrypt_text(
            str(item["payload"]),
            aad=f"windeep:evidence-bundle:{finding_id}".encode("utf-8"),
        )
        canonical = canonical_text.encode("utf-8")
        if _sha256(canonical) != str(item["bundle_sha256"]):
            raise EvidenceIntegrityError("evidence bundle hash mismatch")
        payload = json.loads(canonical_text)
        if payload.get("schema") != BUNDLE_SCHEMA:
            raise EvidenceIntegrityError("unsupported evidence bundle schema")

        for flow_ref in payload.get("flows") or []:
            current = self._flow_ref(int(flow_ref["id"]))
            if current["sha256"] != flow_ref.get("sha256"):
                raise EvidenceIntegrityError(f"flow hash mismatch: {flow_ref['id']}")
        tool_output = payload.get("tool_output")
        if isinstance(tool_output, Mapping):
            artifact = self.read_artifact(str(tool_output["artifact_sha256"]))
            current_slice = self._validate_line_range(
                artifact["content"],
                int(tool_output["line_start"]),
                int(tool_output["line_end"]),
            )
            if current_slice is None or current_slice["slice_sha256"] != tool_output.get("slice_sha256"):
                raise EvidenceIntegrityError("tool output slice hash mismatch")
        browser = payload.get("browser_observation")
        if isinstance(browser, Mapping) and browser.get("screenshot_sha256"):
            self.read_artifact(str(browser["screenshot_sha256"]))

        return {
            **payload,
            "bundle_sha256": str(item["bundle_sha256"]),
            "canonical_json": canonical_text,
            "bundle_id": int(item["id"]),
            "state": str(item["state"]),
        }
