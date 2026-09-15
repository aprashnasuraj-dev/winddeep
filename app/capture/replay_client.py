"""Scope-enforced asynchronous HTTP replay and response diffing for Windeep."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from app.capture.flow_database import FlowDatabase
from app.engine.event_bus import EventBus

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


@dataclass(slots=True)
class ReplayPlan:
    """Mutable replay plan built from one captured flow."""

    flow_id: int
    method: str
    url: str
    headers: dict[str, str]
    params: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def set_header(self, name: str, value: str) -> "ReplayPlan":
        """Set or replace a request header case-insensitively."""
        if not name.strip():
            raise ValueError("header name cannot be empty")
        lowered = name.casefold()
        for existing in list(self.headers):
            if existing.casefold() == lowered:
                self.headers.pop(existing)
        self.headers[name] = value
        return self

    def set_param(self, name: str, value: str) -> "ReplayPlan":
        """Set or replace a query parameter while preserving other duplicates."""
        if not name:
            raise ValueError("parameter name cannot be empty")
        self.params = [(key, item) for key, item in self.params if key != name]
        self.params.append((name, value))
        return self

    def set_body(self, value: bytes | str) -> "ReplayPlan":
        """Replace the request body."""
        self.body = value if isinstance(value, bytes) else value.encode("utf-8")
        return self

    def set_token(self, token: str, *, scheme: str = "Bearer") -> "ReplayPlan":
        """Set an Authorization token without persisting it to storage."""
        if not token.strip():
            raise ValueError("token cannot be empty")
        value = f"{scheme} {token}" if scheme else token
        return self.set_header("Authorization", value)

    def request_url(self) -> str:
        """Render the current URL including modified query parameters."""
        parts = urlsplit(self.url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(self.params, doseq=True), parts.fragment))


class ReplayClient:
    """Replay captured traffic inside configured scope and emit structured diffs."""

    def __init__(
        self,
        flows: FlowDatabase,
        event_bus: EventBus,
        *,
        scope_validator: Callable[[str], bool] | None,
        timeout: float = 30.0,
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.flows = flows
        self.event_bus = event_bus
        self.scope_validator = scope_validator
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.transport = transport

    def prepare(self, flow_id: int) -> ReplayPlan:
        """Create a mutable replay plan from a stored flow."""
        flow = self.flows.get_flow_by_id(flow_id)
        if flow is None:
            raise KeyError(f"flow not found: {flow_id}")
        parts = urlsplit(str(flow["url"]))
        headers = {
            str(key): str(value)
            for key, value in dict(flow.get("request_headers") or {}).items()
            if str(key).casefold() not in _HOP_BY_HOP
        }
        body = flow.get("request_body")
        if isinstance(body, memoryview):
            body = body.tobytes()
        elif body is None:
            body = b""
        elif not isinstance(body, bytes):
            body = str(body).encode("utf-8")
        return ReplayPlan(
            flow_id=flow_id,
            method=str(flow["method"]).upper(),
            url=str(flow["url"]),
            headers=headers,
            params=parse_qsl(parts.query, keep_blank_values=True),
            body=body,
        )

    async def execute(self, plan: ReplayPlan) -> dict[str, Any]:
        """Issue the replay and return a diff against the original response."""
        try:
            url = plan.request_url()
            if self.scope_validator is None:
                raise PermissionError("replay requires an explicit scope validator")
            if not self.scope_validator(url):
                raise PermissionError(f"replay target is outside configured scope: {url}")
            original = self.flows.get_flow_by_id(plan.flow_id)
            if original is None:
                raise KeyError(f"flow not found: {plan.flow_id}")

            timeout = httpx.Timeout(self.timeout)
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=self.verify_tls,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                response = await client.request(
                    plan.method,
                    url,
                    headers=plan.headers,
                    content=plan.body,
                )

            diff = self._diff(original, response)
            result = {
                "flow_id": plan.flow_id,
                "method": plan.method,
                "url": url,
                "status": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response.content,
                "diff": diff,
            }
            await self.event_bus.publish(
                "flow.replayed",
                {
                    "flow_id": plan.flow_id,
                    "method": plan.method,
                    "url": url,
                    "status": response.status_code,
                    "diff": diff,
                },
            )
            return result
        except asyncio.CancelledError:
            raise

    async def replay(
        self,
        flow_id: int,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        """Convenience API for preparing, mutating, and executing a replay."""
        try:
            plan = self.prepare(flow_id)
            for key, value in (headers or {}).items():
                plan.set_header(key, value)
            for key, value in (params or {}).items():
                plan.set_param(key, value)
            if body is not None:
                plan.set_body(body)
            if token is not None:
                plan.set_token(token)
            return await self.execute(plan)
        except asyncio.CancelledError:
            raise

    @staticmethod
    def _diff(original: Mapping[str, Any], response: httpx.Response) -> dict[str, Any]:
        original_body = ReplayClient._bytes(original.get("response_body"))
        new_body = response.content
        original_headers = {
            str(key).casefold(): str(value)
            for key, value in dict(original.get("response_headers") or {}).items()
        }
        new_headers = {str(key).casefold(): str(value) for key, value in response.headers.items()}
        added = {key: value for key, value in new_headers.items() if key not in original_headers}
        removed = {key: value for key, value in original_headers.items() if key not in new_headers}
        changed = {
            key: {"before": original_headers[key], "after": new_headers[key]}
            for key in original_headers.keys() & new_headers.keys()
            if original_headers[key] != new_headers[key]
        }
        original_status = original.get("status")
        return {
            "status": {
                "before": original_status,
                "after": response.status_code,
                "changed": original_status != response.status_code,
            },
            "headers": {"added": added, "removed": removed, "changed": changed},
            "body": {
                "before_sha256": hashlib.sha256(original_body).hexdigest(),
                "after_sha256": hashlib.sha256(new_body).hexdigest(),
                "before_length": len(original_body),
                "after_length": len(new_body),
                "changed": original_body != new_body,
            },
        }

    @staticmethod
    def _bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, memoryview):
            return value.tobytes()
        return str(value).encode("utf-8")
