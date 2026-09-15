"""P1 forensic HTTP flow capture, exact reconstruction, and deterministic HAR export."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from app.evidence.raw_store import RawArtifactStore
from app.evidence.redaction import EvidenceRedactor


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _iso(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _pairs(value: Sequence[tuple[str, str]] | Mapping[str, Any]) -> list[tuple[str, str]]:
    if isinstance(value, Mapping):
        return [(str(key), str(item)) for key, item in value.items()]
    return [(str(key), str(item)) for key, item in value]


def _mapping(value: Sequence[tuple[str, str]] | Mapping[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, item in _pairs(value):
        if key in output:
            output[key] += "\n" + item
        else:
            output[key] = item
    return output


def _parse_http(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n") if head else []
    first = lines[0].decode("utf-8", errors="replace") if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, item = line.split(b":", 1)
        headers.append((name.decode("utf-8", errors="replace"), item.lstrip().decode("utf-8", errors="replace")))
    return first, headers, body


def _header(headers: Sequence[tuple[str, str]], name: str, default: str = "") -> str:
    folded = name.casefold()
    for key, value in headers:
        if key.casefold() == folded:
            return value
    return default


def _har_body(body: bytes) -> tuple[str, str | None]:
    if not body:
        return "", None
    try:
        text = body.decode("utf-8")
        if "\x00" not in text:
            return text, None
    except UnicodeDecodeError:
        pass
    return base64.b64encode(body).decode("ascii"), "base64"


class ForensicFlowStore:
    """Bind parsed flow rows to immutable raw request/response evidence."""

    def __init__(self, database: Any, artifacts: RawArtifactStore, audit: Any) -> None:
        self.database = database
        self.artifacts = artifacts
        self.audit = audit

    def _enc(self, value: str, *, field: str) -> str:
        encoder = getattr(self.database, "_enc", None)
        if not callable(encoder):
            raise RuntimeError("forensic flow metadata requires encrypted database fields")
        return encoder(value, field=field)

    def _dec(self, value: str, *, field: str) -> str:
        decoder = getattr(self.database, "_dec", None)
        if not callable(decoder):
            raise RuntimeError("forensic flow metadata requires encrypted database fields")
        return decoder(value, field=field)

    def capture(
        self,
        *,
        target_id: int,
        scan_id: int,
        tool_run_id: int | None,
        task_id: str | None,
        method: str,
        url: str,
        request_headers: Sequence[tuple[str, str]] | Mapping[str, Any],
        request_body: bytes,
        status: int | None,
        response_headers: Sequence[tuple[str, str]] | Mapping[str, Any],
        response_body: bytes,
        raw_request: bytes,
        raw_response: bytes,
        timings: Mapping[str, float],
        tls: Mapping[str, Any],
        server_ip: str | None,
        created_at: float,
        http_version: str = "HTTP/1.1",
        stream_id: int | None = None,
        pseudo_headers: Sequence[tuple[str, str]] = (),
    ) -> int:
        parts = urlsplit(url)
        flow_id = self.database.insert_flow(
            {
                "target_id": target_id,
                "scan_id": scan_id,
                "method": method.upper(),
                "url": url,
                "scheme": parts.scheme,
                "host": (parts.hostname or "").casefold(),
                "port": parts.port,
                "path": parts.path or "/",
                "query": parts.query,
                "request_headers": _mapping(request_headers),
                "request_body": bytes(request_body),
                "status": status,
                "response_headers": _mapping(response_headers),
                "response_body": bytes(response_body),
                "timing_ms": float(timings.get("total", 0.0)),
                "tls_info": dict(tls),
                "client_ip": "",
                "tags": ["forensic", "raw-bound"],
                "created_at": float(created_at),
            }
        )
        request_ref = self.artifacts.put(
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            kind="http.raw_request",
            media_type="application/http",
            content=bytes(raw_request),
            reason=f"capture raw request for flow {flow_id}",
            metadata={"flow_id": flow_id, "task_id": task_id},
        )
        response_ref = self.artifacts.put(
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            kind="http.raw_response",
            media_type="application/http",
            content=bytes(raw_response),
            reason=f"capture raw response for flow {flow_id}",
            metadata={"flow_id": flow_id, "task_id": task_id},
        )
        flow_digest = _sha256(
            _canonical(
                {
                    "schema": "windeep.flow-evidence.v1",
                    "flow_id": flow_id,
                    "scan_id": scan_id,
                    "tool_run_id": tool_run_id,
                    "task_id": task_id,
                    "raw_request_sha256": request_ref.sha256,
                    "raw_response_sha256": response_ref.sha256,
                    "http_version": http_version,
                    "stream_id": stream_id,
                    "pseudo_headers": list(_pairs(pseudo_headers)),
                    "timings": dict(timings),
                    "server_ip": server_ip,
                    "tls": dict(tls),
                }
            )
        )
        with self.database._connect() as conn:
            conn.execute(
                """
                INSERT INTO flow_evidence(
                    flow_id, scan_id, tool_run_id, task_id,
                    raw_request_sha256, raw_response_sha256, flow_sha256,
                    http_version, stream_id, pseudo_headers, timings, server_ip, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow_id,
                    scan_id,
                    tool_run_id,
                    task_id,
                    request_ref.sha256,
                    response_ref.sha256,
                    flow_digest,
                    http_version,
                    stream_id,
                    self._enc(_canonical(list(_pairs(pseudo_headers))).decode("utf-8"), field="flow_evidence.pseudo_headers"),
                    self._enc(_canonical(dict(timings)).decode("utf-8"), field="flow_evidence.timings"),
                    server_ip,
                    time.time(),
                ),
            )
        self.audit.append(
            "evidence.flow_captured",
            {
                "flow_id": flow_id,
                "scan_id": scan_id,
                "tool_run_id": tool_run_id,
                "flow_sha256": flow_digest,
                "raw_request_sha256": request_ref.sha256,
                "raw_response_sha256": response_ref.sha256,
                "wall": time.time(),
                "monotonic": time.monotonic(),
            },
        )
        return flow_id

    def get(self, flow_id: int) -> dict[str, Any]:
        with self.database._connect() as conn:
            flow_row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
            evidence_row = conn.execute("SELECT * FROM flow_evidence WHERE flow_id = ?", (flow_id,)).fetchone()
        if flow_row is None or evidence_row is None:
            raise KeyError(f"forensic flow not found: {flow_id}")
        flow = dict(flow_row)
        decoder = getattr(self.database, "decode_flow_row", None)
        if callable(decoder):
            flow = decoder(flow)
        evidence = dict(evidence_row)
        evidence["pseudo_headers"] = json.loads(self._dec(str(evidence["pseudo_headers"]), field="flow_evidence.pseudo_headers"))
        evidence["timings"] = json.loads(self._dec(str(evidence["timings"]), field="flow_evidence.timings"))
        flow.update(evidence)
        flow["tls"] = dict(flow.get("tls_info") or {})
        return flow

    def reconstruct_request(self, flow_id: int) -> bytes:
        flow = self.get(flow_id)
        return self.artifacts.read(
            str(flow["raw_request_sha256"]),
            scan_id=int(flow["scan_id"]),
            reason=f"reconstruct request for flow {flow_id}",
        )

    def reconstruct_response(self, flow_id: int) -> bytes:
        flow = self.get(flow_id)
        return self.artifacts.read(
            str(flow["raw_response_sha256"]),
            scan_id=int(flow["scan_id"]),
            reason=f"reconstruct response for flow {flow_id}",
        )

    def _scan_flows(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT flow_id FROM flow_evidence WHERE scan_id = ? ORDER BY flow_id ASC",
                (scan_id,),
            ).fetchall()
        values = [self.get(int(row["flow_id"])) for row in rows]
        values.sort(key=lambda item: (float(item.get("created_at") or 0.0), int(item["id"])))
        return values

    def export_har(
        self,
        *,
        scan_id: int,
        redactor: EvidenceRedactor,
        operator_terms: Sequence[str] = (),
        flow_ids: Sequence[int] | None = None,
    ) -> bytes:
        allowed = {int(value) for value in flow_ids} if flow_ids is not None else None
        flows = [item for item in self._scan_flows(scan_id) if allowed is None or int(item["id"]) in allowed]
        started = _iso(float(flows[0].get("created_at") or 0.0)) if flows else _iso(0.0)
        entries: list[dict[str, Any]] = []
        for flow in flows:
            flow_id = int(flow["id"])
            request_view = redactor.redact_artifact(
                str(flow["raw_request_sha256"]),
                scan_id=scan_id,
                path=f"flow[{flow_id}].request",
                operator_terms=operator_terms,
            ).content
            response_view = redactor.redact_artifact(
                str(flow["raw_response_sha256"]),
                scan_id=scan_id,
                path=f"flow[{flow_id}].response",
                operator_terms=operator_terms,
            ).content
            request_line, request_headers, request_body = _parse_http(request_view)
            response_line, response_headers, response_body = _parse_http(response_view)
            request_parts = request_line.split(" ", 2)
            request_target = request_parts[1] if len(request_parts) >= 2 else str(flow.get("path") or "/")
            host = _header(request_headers, "Host", str(flow.get("host") or ""))
            request_url = urlunsplit((str(flow.get("scheme") or "https"), host, urlsplit(request_target).path, urlsplit(request_target).query, ""))
            response_parts = response_line.split(" ", 2)
            try:
                status = int(response_parts[1]) if len(response_parts) >= 2 else int(flow.get("status") or 0)
            except ValueError:
                status = int(flow.get("status") or 0)
            request_text, request_encoding = _har_body(request_body)
            response_text, response_encoding = _har_body(response_body)
            request_obj: dict[str, Any] = {
                "method": str(flow.get("method") or "GET"),
                "url": request_url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": key, "value": value} for key, value in request_headers],
                "queryString": [{"name": key, "value": value} for key, value in parse_qsl(urlsplit(request_url).query, keep_blank_values=True)],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(request_body),
            }
            if request_body:
                post_data: dict[str, Any] = {
                    "mimeType": _header(request_headers, "Content-Type", "application/octet-stream").split(";", 1)[0],
                    "text": request_text,
                }
                if request_encoding:
                    post_data["encoding"] = request_encoding
                request_obj["postData"] = post_data
            response_content: dict[str, Any] = {
                "size": len(response_body),
                "mimeType": _header(response_headers, "Content-Type", "application/octet-stream").split(";", 1)[0],
                "text": response_text,
            }
            if response_encoding:
                response_content["encoding"] = response_encoding
            timings = dict(flow.get("timings") or {})
            total = float(timings.get("total", flow.get("timing_ms") or 0.0))
            entry = {
                "pageref": f"scan-{scan_id}",
                "startedDateTime": _iso(float(flow.get("created_at") or 0.0)),
                "time": total,
                "request": request_obj,
                "response": {
                    "status": status,
                    "statusText": response_parts[2] if len(response_parts) >= 3 else "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": key, "value": value} for key, value in response_headers],
                    "cookies": [],
                    "content": response_content,
                    "redirectURL": _header(response_headers, "Location", ""),
                    "headersSize": -1,
                    "bodySize": len(response_body),
                },
                "cache": {},
                "timings": {
                    "blocked": 0.0,
                    "dns": -1.0,
                    "connect": float(timings.get("connect", 0.0)),
                    "send": 0.0,
                    "wait": float(timings.get("ttfb", total)),
                    "receive": max(0.0, total - float(timings.get("ttfb", total))),
                    "ssl": float(timings.get("tls", 0.0)),
                },
                "serverIPAddress": str(flow.get("server_ip") or ""),
                "_windeep": {
                    "schema": "windeep.har-extension.v1",
                    "flow_id": flow_id,
                    "flow_sha256": str(flow["flow_sha256"]),
                    "tool_run_id": flow.get("tool_run_id"),
                    "scan_id": scan_id,
                    "task_id": flow.get("task_id"),
                    "captured_http_version": str(flow.get("http_version") or "HTTP/1.1"),
                    "stream_id": flow.get("stream_id"),
                    "pseudo_headers": flow.get("pseudo_headers") or [],
                    "http2_downgraded": str(flow.get("http_version") or "").upper().startswith("HTTP/2"),
                    "note": "HAR 1.2 represents HTTP/2 captures as HTTP/1.1 while preserving HTTP/2 metadata in _windeep."
                    if str(flow.get("http_version") or "").upper().startswith("HTTP/2")
                    else "",
                },
            }
            entries.append(entry)
        document = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Windeep", "version": "3"},
                "pages": [
                    {
                        "startedDateTime": started,
                        "id": f"scan-{scan_id}",
                        "title": f"Windeep scan {scan_id}",
                        "pageTimings": {},
                    }
                ],
                "entries": entries,
            }
        }
        encoded = (_canonical(document) + b"\n")
        har_ref = self.artifacts.put(
            scan_id=scan_id,
            tool_run_id=None,
            kind="export.har.redacted",
            media_type="application/json",
            content=encoded,
            reason="persist deterministic redacted HAR export",
            metadata={"flow_ids": [int(item["id"]) for item in flows]},
        )
        self.artifacts.export(har_ref.sha256, scan_id=scan_id, reason="HAR export")
        self.audit.append(
            "evidence.har_exported",
            {
                "scan_id": scan_id,
                "har_sha256": har_ref.sha256,
                "flow_ids": [int(item["id"]) for item in flows],
                "wall": time.time(),
                "monotonic": time.monotonic(),
            },
        )
        return encoded


__all__ = ["ForensicFlowStore"]
