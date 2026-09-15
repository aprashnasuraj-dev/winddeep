"""mitmproxy addon that normalizes HTTP/HTTPS/WebSocket traffic for Windeep.

The module deliberately avoids importing mitmproxy itself so the Windeep app remains
Python 3.11 compatible. It is loaded by a portable mitmdump runtime (currently
mitmproxy 12.x / Python 3.12+) and interacts with flow objects by their public
attributes. Events are either published to an injected in-process EventBus or sent
to a loopback callback endpoint when mitmdump runs as an isolated process.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit

from app.capture.flow_database import ExportFormat, FlowDatabase
from app.capture.interceptor import Interceptor
from app.database import Database

if TYPE_CHECKING:
    from app.engine.event_bus import EventBus

TargetResolver = Callable[[str], tuple[int | None, int | None]]


class CaptureAddon:
    """Capture, persist, optionally intercept, and publish mitmproxy flows."""

    def __init__(
        self,
        flows: FlowDatabase,
        *,
        event_bus: EventBus | None = None,
        event_endpoint: str | None = None,
        target_resolver: TargetResolver | None = None,
        interceptor: Interceptor | None = None,
    ) -> None:
        self.flows = flows
        self.event_bus = event_bus
        self.event_endpoint = event_endpoint
        self.target_resolver = target_resolver
        self.interceptor = interceptor

    @classmethod
    def from_environment(cls) -> "CaptureAddon":
        """Build an addon from environment values used by the portable runtime.

        The standalone addon intentionally has no resolver and therefore stores
        no traffic until the host application supplies an explicit in-scope
        target mapping. This is a fail-closed privacy/scope boundary.
        """
        db_path = Path(os.getenv("WINDEEP_DB", "app/data/windeep.db"))
        endpoint = os.getenv("WINDEEP_EVENT_ENDPOINT") or None
        return cls(FlowDatabase(Database(db_path)), event_endpoint=endpoint)

    async def request(self, flow: Any) -> None:
        """Apply configured interceptor rules before forwarding a request."""
        try:
            if self.interceptor is None:
                return
            request = self._request_record(flow)
            decision = self.interceptor.evaluate(request)
            if decision.out_of_scope:
                return
            if decision.dropped:
                if hasattr(flow, "kill"):
                    flow.kill()
                await self._publish(
                    "flow.intercepted",
                    {"action": "drop", "url": request["url"], "rules": decision.matched_rules},
                )
                return
            if decision.action == "modify":
                self._apply_request_decision(flow, decision.headers, decision.url, decision.body)
            if decision.tags:
                metadata = getattr(flow, "metadata", None)
                if isinstance(metadata, dict):
                    metadata["windeep_tags"] = list(decision.tags)
            if decision.replay_requested:
                await self._publish(
                    "flow.replay_requested",
                    {"url": request["url"], "rules": decision.matched_rules},
                )
            if decision.matched_rules:
                await self._publish(
                    "flow.intercepted",
                    {
                        "action": decision.action,
                        "url": decision.url,
                        "rules": decision.matched_rules,
                        "tags": decision.tags,
                    },
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._publish("log.capture_error", {"phase": "request", "error": str(exc)})

    async def response(self, flow: Any) -> None:
        """Persist a completed HTTP/HTTPS flow only for a resolved in-scope target."""
        try:
            record = self._completed_record(flow)
            if record.get("target_id") is None:
                await self._publish("log.capture_skipped", {"reason": "unresolved_target", "url": record["url"]})
                return
            flow_id = self.flows.insert_flow(record)
            await self._publish(
                "flow.captured",
                {
                    "flow_id": flow_id,
                    "target_id": record.get("target_id"),
                    "scan_id": record.get("scan_id"),
                    "method": record["method"],
                    "url": record["url"],
                    "host": record["host"],
                    "path": record["path"],
                    "status": record.get("status"),
                    "timing_ms": record.get("timing_ms"),
                    "tags": record.get("tags", []),
                },
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._publish("log.capture_error", {"phase": "response", "error": str(exc)})

    async def websocket_message(self, flow: Any) -> None:
        """Persist the newest WebSocket message only for a resolved in-scope target."""
        try:
            websocket = getattr(flow, "websocket", None)
            messages = getattr(websocket, "messages", None)
            if not messages:
                return
            message = messages[-1]
            request = getattr(flow, "request")
            url = self._request_url(request)
            target_id, scan_id = self._resolve_target(url)
            if target_id is None:
                await self._publish("log.capture_skipped", {"reason": "unresolved_target", "url": url, "kind": "websocket"})
                return
            parts = urlsplit(url)
            content = getattr(message, "content", b"")
            if isinstance(content, str):
                content = content.encode("utf-8")
            elif not isinstance(content, bytes):
                content = bytes(content)
            from_client = bool(getattr(message, "from_client", False))
            tags = ["websocket", "client-to-server" if from_client else "server-to-client"]
            record = {
                "target_id": target_id,
                "scan_id": scan_id,
                "method": "WS",
                "url": url,
                "scheme": parts.scheme,
                "host": (parts.hostname or "").lower(),
                "port": parts.port,
                "path": parts.path or "/",
                "query": parts.query,
                "request_headers": self._headers(getattr(request, "headers", {})),
                "request_body": content if from_client else b"",
                "status": getattr(getattr(flow, "response", None), "status_code", None),
                "response_headers": self._headers(getattr(getattr(flow, "response", None), "headers", {})),
                "response_body": b"" if from_client else content,
                "timing_ms": 0.0,
                "tls_info": self._tls_info(flow),
                "client_ip": self._client_ip(flow),
                "tags": tags,
                "created_at": float(getattr(message, "timestamp", time.time()) or time.time()),
            }
            flow_id = self.flows.insert_flow(record)
            await self._publish(
                "flow.captured",
                {
                    "flow_id": flow_id,
                    "target_id": target_id,
                    "scan_id": scan_id,
                    "method": "WS",
                    "url": url,
                    "direction": tags[1],
                    "size": len(content),
                    "tags": tags,
                },
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._publish("log.capture_error", {"phase": "websocket", "error": str(exc)})

    def export_flow(self, flow_id: int, format: ExportFormat) -> str:
        """Export a stored flow using the canonical capture database exporters."""
        return self.flows.export_flow(flow_id, format)

    def _completed_record(self, flow: Any) -> dict[str, Any]:
        request = getattr(flow, "request")
        response = getattr(flow, "response", None)
        record = self._request_record(flow)
        request_start = self._float_or_none(getattr(request, "timestamp_start", None))
        response_end = self._float_or_none(getattr(response, "timestamp_end", None)) if response is not None else None
        timing_ms = None
        if request_start is not None and response_end is not None:
            timing_ms = max(0.0, (response_end - request_start) * 1000.0)
        record.update(
            {
                "status": getattr(response, "status_code", None) if response is not None else None,
                "response_headers": self._headers(getattr(response, "headers", {})) if response is not None else {},
                "response_body": self._raw_content(response),
                "timing_ms": timing_ms,
                "tls_info": self._tls_info(flow),
                "client_ip": self._client_ip(flow),
                "created_at": request_start or time.time(),
            }
        )
        return record

    def _request_record(self, flow: Any) -> dict[str, Any]:
        request = getattr(flow, "request")
        url = self._request_url(request)
        parts = urlsplit(url)
        target_id, scan_id = self._resolve_target(url)
        metadata = getattr(flow, "metadata", None)
        tags = []
        if isinstance(metadata, Mapping):
            candidate = metadata.get("windeep_tags", [])
            if isinstance(candidate, list):
                tags = [str(tag) for tag in candidate]
        return {
            "target_id": target_id,
            "scan_id": scan_id,
            "method": str(getattr(request, "method", "GET")).upper(),
            "url": url,
            "scheme": parts.scheme,
            "host": (parts.hostname or "").lower(),
            "port": parts.port,
            "path": parts.path or "/",
            "query": parts.query,
            "request_headers": self._headers(getattr(request, "headers", {})),
            "request_body": self._raw_content(request),
            "tags": tags,
        }

    def _resolve_target(self, url: str) -> tuple[int | None, int | None]:
        if self.target_resolver is None:
            return None, None
        resolved = self.target_resolver(url)
        if not isinstance(resolved, tuple) or len(resolved) != 2:
            raise ValueError("target_resolver must return (target_id, scan_id)")
        return resolved

    async def _publish(self, topic: str, payload: Mapping[str, Any]) -> None:
        try:
            if self.event_bus is not None:
                await self.event_bus.publish(topic, dict(payload))
            if self.event_endpoint:
                await asyncio.to_thread(self._post_event, topic, dict(payload))
        except asyncio.CancelledError:
            raise
        except Exception:
            # Capture must never block browser traffic because the dashboard event sink is unavailable.
            return

    def _post_event(self, topic: str, payload: Mapping[str, Any]) -> None:
        if not self.event_endpoint:
            return
        body = json.dumps({"topic": topic, "payload": dict(payload)}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.event_endpoint,
            data=body,
            headers={"Content-Type": "application/json", "X-Windeep-Source": "mitmproxy"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=1.5) as response:
                response.read(1)
        except (urllib.error.URLError, TimeoutError, OSError):
            return

    @staticmethod
    def _request_url(request: Any) -> str:
        for attribute in ("pretty_url", "url"):
            value = getattr(request, attribute, None)
            if value:
                return str(value)
        raise ValueError("mitmproxy request has no URL")

    @staticmethod
    def _headers(headers: Any) -> dict[str, str]:
        if headers is None:
            return {}
        try:
            items = headers.items(multi=True)
        except TypeError:
            items = headers.items()
        except AttributeError:
            return dict(headers) if isinstance(headers, Mapping) else {}
        output: dict[str, str] = {}
        for key, value in items:
            key_text = str(key)
            value_text = str(value)
            if key_text in output:
                output[key_text] = output[key_text] + "\n" + value_text
            else:
                output[key_text] = value_text
        return output

    @staticmethod
    def _raw_content(message: Any) -> bytes:
        if message is None:
            return b""
        value = getattr(message, "raw_content", None)
        if value is None:
            value = getattr(message, "content", None)
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("utf-8")
        try:
            return bytes(value)
        except (TypeError, ValueError):
            return str(value).encode("utf-8")

    @staticmethod
    def _tls_info(flow: Any) -> dict[str, Any]:
        server = getattr(flow, "server_conn", None)
        client = getattr(flow, "client_conn", None)
        cert = getattr(server, "cert", None)
        return {
            "server_tls": bool(getattr(server, "tls_established", False)),
            "client_tls": bool(getattr(client, "tls_established", False)),
            "sni": str(getattr(server, "sni", "") or ""),
            "alpn": CaptureAddon._safe_text(getattr(server, "alpn", None)),
            "cipher": str(getattr(server, "cipher_name", "") or ""),
            "tls_version": str(getattr(server, "tls_version", "") or ""),
            "certificate": str(cert) if cert is not None else "",
        }

    @staticmethod
    def _client_ip(flow: Any) -> str | None:
        client = getattr(flow, "client_conn", None)
        peer = getattr(client, "peername", None)
        if isinstance(peer, tuple) and peer:
            return str(peer[0])
        return None

    @staticmethod
    def _safe_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("ascii", errors="replace")
        return str(value)

    @staticmethod
    def _float_or_none(value: Any) -> float | None:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _apply_request_decision(flow: Any, headers: Mapping[str, str], url: str, body: bytes) -> None:
        request = getattr(flow, "request")
        request.url = url
        target_headers = getattr(request, "headers", None)
        if target_headers is not None:
            try:
                target_headers.clear()
                for key, value in headers.items():
                    target_headers[key] = value
            except (AttributeError, TypeError):
                pass
        if hasattr(request, "raw_content"):
            request.raw_content = body
        elif hasattr(request, "content"):
            request.content = body


# When loaded directly with ``mitmdump -s app/capture/mitm_addon.py``, mitmproxy
# discovers this global list. Without an application-supplied resolver the addon
# forwards traffic but deliberately persists nothing.
addons = [CaptureAddon.from_environment()]
