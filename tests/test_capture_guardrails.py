"""Guardrail regressions for capture persistence boundaries."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.capture.mitm_addon import CaptureAddon


class FakeFlows:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def insert_flow(self, flow: dict[str, Any]) -> int:
        self.rows.append(dict(flow))
        return len(self.rows)


class RecordingBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((topic, payload))


def _flow() -> SimpleNamespace:
    request = SimpleNamespace(
        method="GET",
        pretty_url="https://outside.example/private",
        url="https://outside.example/private",
        headers={},
        raw_content=b"",
        timestamp_start=100.0,
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"secret", timestamp_end=100.1)
    return SimpleNamespace(
        request=request,
        response=response,
        server_conn=SimpleNamespace(tls_established=True, sni="outside.example", alpn=b"h2", cipher_name="", tls_version="TLSv1.3", cert=None),
        client_conn=SimpleNamespace(tls_established=True, peername=("127.0.0.1", 50000)),
        metadata={},
        websocket=None,
    )


@pytest.mark.asyncio
async def test_unresolved_http_flow_is_not_persisted() -> None:
    store = FakeFlows()
    bus = RecordingBus()
    addon = CaptureAddon(store, event_bus=bus)  # type: ignore[arg-type]
    await addon.response(_flow())
    assert store.rows == []
    assert any(topic == "log.capture_skipped" for topic, _ in bus.events)


@pytest.mark.asyncio
async def test_unresolved_websocket_flow_is_not_persisted() -> None:
    store = FakeFlows()
    bus = RecordingBus()
    flow = _flow()
    flow.websocket = SimpleNamespace(messages=[SimpleNamespace(content=b"secret", from_client=False, timestamp=101.0)])
    addon = CaptureAddon(store, event_bus=bus)  # type: ignore[arg-type]
    await addon.websocket_message(flow)
    assert store.rows == []
    assert any(topic == "log.capture_skipped" for topic, _ in bus.events)
