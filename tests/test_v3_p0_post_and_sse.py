"""P0 determinism, preflight-spy, and SSE replay acceptance tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.database import Database
from app.engine.event_bus import EventBus
from app.engine.pipeline_store import PipelineStore
from app.engine.post_pipeline import DeterministicPostPipeline
from app.engine.scan_context import ScanContext
from app.engine.scheduler import TaskScheduler, TaskSpec
from app.security.preflight import PreFlightError
from app.server import create_app


@pytest.mark.asyncio
async def test_missing_preflight_never_reaches_runner_spy() -> None:
    bus = EventBus(heartbeat_interval=60)
    reached = False

    async def spy(context: object, deps: dict[str, object]) -> None:
        nonlocal reached
        reached = True

    context = type("Context", (), {"target": "https://example.com", "consent_id": "signed"})()
    scheduler = TaskScheduler(bus)
    with pytest.raises(PreFlightError):
        await scheduler.execute([TaskSpec(id="must-not-run", runner=spy)], context, scan_id="preflight-spy")
    assert reached is False
    await bus.close()


@pytest.mark.asyncio
async def test_post_stages_are_byte_identical_for_same_fixture(tmp_path: Path) -> None:
    db = Database(tmp_path / "windeep.db")
    target_id = db.create_target("Example", "web", "https://example.com", scope=["example.com"])
    scan_id = db.create_scan(target_id, "v3:p0", ["fixture"])
    left_id, _ = db.create_finding(
        target_id,
        "Sensitive information disclosure",
        "medium",
        scan_id=scan_id,
        vuln_type="information disclosure",
        tool="fixture-a",
        endpoint="https://example.com/api/meta",
        confidence=0.8,
    )
    right_id, _ = db.create_finding(
        target_id,
        "Object authorization weakness",
        "high",
        scan_id=scan_id,
        vuln_type="idor",
        tool="fixture-b",
        endpoint="https://example.com/api/object/7",
        confidence=0.9,
    )
    findings = [db.get_finding(left_id), db.get_finding(right_id)]
    assert all(item is not None for item in findings)
    fixture = [dict(item) for item in findings if item is not None]
    context = ScanContext(
        target="https://example.com",
        scope=("example.com",),
        consent_id="fixture-consent",
        target_id=str(target_id),
    )
    bus = EventBus(heartbeat_interval=60)
    stages = DeterministicPostPipeline(db, bus)
    first = await stages.run(fixture, context, target_id=target_id, scan_id=scan_id)
    second = await stages.run(fixture, context, target_id=target_id, scan_id=scan_id)
    first_bytes = json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    second_bytes = json.dumps(second, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert first_bytes == second_bytes
    assert first["ranked"]
    assert first["chains"]
    await bus.close()


def _handshake(client) -> None:
    response = client.post("/api/handshake", json={})
    assert response.status_code == 200


def test_sse_last_event_id_replays_gap_free_and_redacts_finding_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()
    _handshake(client)
    db = app.extensions["windeep.database"]
    store = PipelineStore(db)
    target_id = db.create_target("Example", "web", "https://example.com")
    scan_id = db.create_scan(target_id, "v3:p0", ["fixture"])
    store.append_scan_event(scan_id, "progress", {"progress": 10})
    store.append_scan_event(
        scan_id,
        "finding",
        {"finding": {"id": 7, "title": "fixture", "evidence": {"api_key": "must-not-leak"}}},
    )
    store.append_scan_event(scan_id, "ranked", {"finding_id": 7, "score": 81.0})

    response = client.get(
        f"/api/stream/{scan_id}",
        headers={"Last-Event-ID": "1"},
        buffered=False,
    )
    assert response.status_code == 200
    iterator = iter(response.response)
    second = next(iterator).decode("utf-8")
    third = next(iterator).decode("utf-8")
    response.close()
    assert "id: 2" in second
    assert "event: finding" not in second
    assert '"type":"finding"' in second
    assert "must-not-leak" not in second
    assert '"evidence"' not in second
    assert "id: 3" in third
    assert "event: ranked" not in third
    assert '"type":"ranked"' in third
