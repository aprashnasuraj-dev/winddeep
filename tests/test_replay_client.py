"""Tests for Windeep captured-request replay and response diffing."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.capture.flow_database import FlowDatabase
from app.capture.replay_client import ReplayClient
from app.database import Database
from app.engine.scan_context import ScanContext


class RecordingBus:
    """Records published replay events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((topic, payload))


def make_flow(tmp_path: Path) -> tuple[FlowDatabase, int]:
    db = Database(tmp_path / "replay.db")
    target_id = db.create_target("Example", "web", "https://example.com")
    flows = FlowDatabase(db)
    flow_id = flows.insert_flow(
        {
            "target_id": target_id,
            "method": "GET",
            "url": "https://example.com/api/items?id=7&mode=full",
            "scheme": "https",
            "host": "example.com",
            "port": 443,
            "path": "/api/items",
            "query": "id=7&mode=full",
            "request_headers": {"Host": "example.com", "Content-Length": "0", "Accept": "application/json"},
            "request_body": b"",
            "status": 200,
            "response_headers": {"Content-Type": "application/json", "X-Version": "1"},
            "response_body": b'{"id":7}',
            "timing_ms": 5.0,
            "tls_info": {},
            "tags": [],
        }
    )
    return flows, flow_id


def test_prepare_strips_hop_by_hop_headers_and_preserves_query(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)
    client = ReplayClient(flows, RecordingBus(), scope_validator=lambda _: True)  # type: ignore[arg-type]
    plan = client.prepare(flow_id)
    assert "Host" not in plan.headers
    assert "Content-Length" not in plan.headers
    assert plan.headers["Accept"] == "application/json"
    assert plan.params == [("id", "7"), ("mode", "full")]


def test_plan_mutations_are_case_insensitive_and_render_query(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)
    plan = ReplayClient(flows, RecordingBus(), scope_validator=lambda _: True).prepare(flow_id)  # type: ignore[arg-type]
    plan.set_header("accept", "text/plain").set_param("id", "9").set_body("marker").set_token("abc")
    assert [key.casefold() for key in plan.headers].count("accept") == 1
    assert plan.headers["accept"] == "text/plain"
    assert plan.headers["Authorization"] == "Bearer abc"
    assert "id=9" in plan.request_url()
    assert "mode=full" in plan.request_url()
    assert plan.body == b"marker"


@pytest.mark.asyncio
async def test_execute_returns_diff_and_emits_event(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)
    bus = RecordingBus()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["id"] == "8"
        return httpx.Response(
            201,
            headers={"Content-Type": "application/json", "X-Version": "2"},
            content=b'{"id":8}',
        )

    ctx = ScanContext(target="https://example.com", scope=["example.com"])
    client = ReplayClient(
        flows,
        bus,  # type: ignore[arg-type]
        scope_validator=ctx.is_in_scope,
        transport=httpx.MockTransport(handler),
    )
    plan = client.prepare(flow_id).set_param("id", "8")
    result = await client.execute(plan)

    assert result["status"] == 201
    assert result["diff"]["status"]["changed"] is True
    assert result["diff"]["body"]["changed"] is True
    assert "x-version" in result["diff"]["headers"]["changed"]
    assert bus.events[-1][0] == "flow.replayed"


@pytest.mark.asyncio
async def test_execute_refuses_missing_scope_validator(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)
    client = ReplayClient(flows, RecordingBus(), scope_validator=None)  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="explicit scope validator"):
        await client.execute(client.prepare(flow_id))


@pytest.mark.asyncio
async def test_execute_refuses_out_of_scope_plan(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)
    ctx = ScanContext(target="https://example.com", scope=["api.example.com"])
    client = ReplayClient(flows, RecordingBus(), scope_validator=ctx.is_in_scope)  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="outside configured scope"):
        await client.execute(client.prepare(flow_id))


@pytest.mark.asyncio
async def test_convenience_replay_applies_headers_params_body_and_token(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-test"] == "yes"
        assert request.headers["authorization"] == "Bearer token-1"
        assert request.url.params["mode"] == "compact"
        assert request.content == b"payload"
        return httpx.Response(200, content=b'{"id":7}')

    client = ReplayClient(
        flows,
        RecordingBus(),  # type: ignore[arg-type]
        scope_validator=lambda _: True,
        transport=httpx.MockTransport(handler),
    )
    result = await client.replay(
        flow_id,
        headers={"X-Test": "yes"},
        params={"mode": "compact"},
        body="payload",
        token="token-1",
    )
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_replay_propagates_cancellation(tmp_path: Path) -> None:
    flows, flow_id = make_flow(tmp_path)

    class CancelReplay(ReplayClient):
        async def execute(self, plan):  # type: ignore[override]
            raise asyncio.CancelledError

    client = CancelReplay(flows, RecordingBus(), scope_validator=lambda _: True)  # type: ignore[arg-type]
    with pytest.raises(asyncio.CancelledError):
        await client.replay(flow_id)
