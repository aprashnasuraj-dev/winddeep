"""Tests for the Windeep mitmproxy addon without importing mitmproxy."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.capture.interceptor import Interceptor, InterceptorRule
from app.capture.mitm_addon import CaptureAddon


class FakeFlows:
    """In-memory flow store test double."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.exports: list[tuple[int, str]] = []

    def insert_flow(self, flow: dict[str, Any]) -> int:
        self.rows.append(dict(flow))
        return len(self.rows)

    def export_flow(self, flow_id: int, format: str) -> str:
        self.exports.append((flow_id, format))
        return f"{format}:{flow_id}"


class RecordingBus:
    """Records event publications from the addon."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((topic, payload))


class FakeFlow(SimpleNamespace):
    """mitmproxy-like flow object with kill support."""

    killed: bool = False

    def kill(self) -> None:
        self.killed = True


def make_flow() -> FakeFlow:
    request = SimpleNamespace(
        method="POST",
        pretty_url="https://example.com/api/items?id=7",
        url="https://example.com/api/items?id=7",
        headers={"Content-Type": "application/json"},
        raw_content=b'{"name":"marker"}',
        timestamp_start=100.0,
    )
    response = SimpleNamespace(
        status_code=201,
        headers={"Content-Type": "application/json"},
        raw_content=b'{"id":7}',
        timestamp_end=100.125,
    )
    server_conn = SimpleNamespace(
        tls_established=True,
        sni="example.com",
        alpn=b"h2",
        cipher_name="TLS_AES_128_GCM_SHA256",
        tls_version="TLSv1.3",
        cert="test-cert",
    )
    client_conn = SimpleNamespace(tls_established=True, peername=("127.0.0.1", 53100))
    return FakeFlow(
        request=request,
        response=response,
        server_conn=server_conn,
        client_conn=client_conn,
        metadata={},
        websocket=None,
        killed=False,
    )


@pytest.mark.asyncio
async def test_response_captures_http_metadata_body_tls_and_timing() -> None:
    store = FakeFlows()
    bus = RecordingBus()
    addon = CaptureAddon(
        store,  # type: ignore[arg-type]
        event_bus=bus,  # type: ignore[arg-type]
        target_resolver=lambda _: (4, 9),
    )
    await addon.response(make_flow())
    assert len(store.rows) == 1
    row = store.rows[0]
    assert row["target_id"] == 4
    assert row["scan_id"] == 9
    assert row["method"] == "POST"
    assert row["host"] == "example.com"
    assert row["status"] == 201
    assert row["request_body"] == b'{"name":"marker"}'
    assert row["response_body"] == b'{"id":7}'
    assert row["timing_ms"] == pytest.approx(125.0)
    assert row["tls_info"]["tls_version"] == "TLSv1.3"
    assert row["client_ip"] == "127.0.0.1"
    assert bus.events[-1][0] == "flow.captured"


@pytest.mark.asyncio
async def test_request_modify_rule_changes_forwarded_request() -> None:
    store = FakeFlows()
    bus = RecordingBus()
    interceptor = Interceptor(
        [
            InterceptorRule(
                name="marker",
                action="modify",
                host="example.com",
                path="/api/*",
                set_headers={"X-Windeep": "1"},
                set_params={"id": "8"},
                body="updated",
                tags=("modified",),
            )
        ],
        scope_validator=lambda _: True,
    )
    addon = CaptureAddon(store, event_bus=bus, interceptor=interceptor)  # type: ignore[arg-type]
    flow = make_flow()
    await addon.request(flow)
    assert flow.request.url.endswith("id=8")
    assert flow.request.headers["X-Windeep"] == "1"
    assert flow.request.raw_content == b"updated"
    assert flow.metadata["windeep_tags"] == ["modified"]
    assert any(topic == "flow.intercepted" for topic, _ in bus.events)


@pytest.mark.asyncio
async def test_request_drop_rule_kills_flow() -> None:
    interceptor = Interceptor(
        [InterceptorRule(name="drop", action="drop", host="example.com")],
        scope_validator=lambda _: True,
    )
    addon = CaptureAddon(FakeFlows(), event_bus=RecordingBus(), interceptor=interceptor)  # type: ignore[arg-type]
    flow = make_flow()
    await addon.request(flow)
    assert flow.killed is True


@pytest.mark.asyncio
async def test_out_of_scope_request_is_not_intercepted() -> None:
    interceptor = Interceptor(
        [InterceptorRule(name="drop", action="drop", host="example.com")],
        scope_validator=lambda _: False,
    )
    addon = CaptureAddon(FakeFlows(), event_bus=RecordingBus(), interceptor=interceptor)  # type: ignore[arg-type]
    flow = make_flow()
    await addon.request(flow)
    assert flow.killed is False


@pytest.mark.asyncio
async def test_websocket_message_is_persisted_directionally() -> None:
    store = FakeFlows()
    bus = RecordingBus()
    flow = make_flow()
    flow.websocket = SimpleNamespace(
        messages=[SimpleNamespace(content=b"hello", from_client=True, timestamp=123.5)]
    )
    addon = CaptureAddon(
        store,  # type: ignore[arg-type]
        event_bus=bus,  # type: ignore[arg-type]
        target_resolver=lambda _: (1, 2),
    )
    await addon.websocket_message(flow)
    row = store.rows[0]
    assert row["method"] == "WS"
    assert row["request_body"] == b"hello"
    assert row["response_body"] == b""
    assert row["tags"] == ["websocket", "client-to-server"]
    assert bus.events[-1][1]["direction"] == "client-to-server"


def test_export_flow_delegates_to_canonical_store() -> None:
    store = FakeFlows()
    addon = CaptureAddon(store)  # type: ignore[arg-type]
    assert addon.export_flow(3, "har") == "har:3"
    assert store.exports == [(3, "har")]


def test_headers_preserve_duplicate_values() -> None:
    class MultiHeaders:
        def items(self, multi: bool = False):
            assert multi is True
            return [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]

    headers = CaptureAddon._headers(MultiHeaders())
    assert headers["Set-Cookie"] == "a=1\nb=2"


def test_target_resolver_contract_is_validated() -> None:
    addon = CaptureAddon(FakeFlows(), target_resolver=lambda _: 4)  # type: ignore[arg-type,return-value]
    with pytest.raises(ValueError, match="must return"):
        addon._resolve_target("https://example.com")
