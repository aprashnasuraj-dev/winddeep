"""P0 acceptance tests for the v3 scheduler-backed scan pipeline."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from app.database import Database
from app.engine.event_bus import EventBus
from app.engine.pipeline_store import PipelineStore
from app.engine.scheduler import PipelineExecutionError, RetryPolicy, TaskScheduler, TaskSpec
from app.security.preflight import PreFlightError


class FakePreflight:
    def __init__(self) -> None:
        self.authorized: list[tuple[str, str]] = []
        self.rate_keys: list[str] = []

    def authorize_scan(self, *, target: str, consent_id: str) -> object:
        self.authorized.append((target, consent_id))
        return object()

    async def acquire_rate(self, key: str, *, cost: float = 1.0) -> None:
        self.rate_keys.append(key)
        await asyncio.sleep(0)

    async def acquire_host_rate(self, target: str, *, cost: float = 1.0) -> None:
        parsed = urlsplit(target if "://" in target else f"https://{target}")
        self.rate_keys.append(f"host:{parsed.hostname or target}")
        await asyncio.sleep(0)


def _context() -> SimpleNamespace:
    return SimpleNamespace(target="https://example.com", consent_id="signed-consent")


@pytest.mark.asyncio
async def test_task_contract_declares_v3_metadata_and_caps_overlap() -> None:
    bus = EventBus(heartbeat_interval=60)
    guard = FakePreflight()
    active = 0
    peak = 0
    lock = asyncio.Lock()

    async def runner(context: object, deps: dict[str, object]) -> str:
        nonlocal active, peak
        async with lock:
            active += 1
            peak = max(peak, active)
        await asyncio.sleep(0.03)
        async with lock:
            active -= 1
        return "ok"

    tasks = [
        TaskSpec(
            id=f"recon-{index}",
            kind="tool",
            runner=runner,
            depends_on=(),
            tool_name="recon-tool",
            resource_class="recon",
            timeout=1.0,
            retry_policy=RetryPolicy(max_attempts=1),
            cancellable=True,
        )
        for index in range(3)
    ]
    scheduler = TaskScheduler(bus, preflight=guard, global_concurrency=4, per_tool_concurrency={"recon-tool": 2})
    results = await scheduler.execute(tasks, _context(), scan_id="p0-overlap")
    assert sorted(results) == ["recon-0", "recon-1", "recon-2"]
    assert peak == 2
    assert guard.authorized == [("https://example.com", "signed-consent")]
    assert "recon-tool" in guard.rate_keys
    assert "host:example.com" in guard.rate_keys
    await bus.close()


@pytest.mark.asyncio
async def test_partial_failure_blocks_dependents_but_not_independent_branch() -> None:
    bus = EventBus(heartbeat_interval=60)
    independent_ran = asyncio.Event()
    dependent_ran = False

    async def fail(context: object, deps: dict[str, object]) -> None:
        raise RuntimeError("branch failed")

    async def dependent(context: object, deps: dict[str, object]) -> None:
        nonlocal dependent_ran
        dependent_ran = True

    async def independent(context: object, deps: dict[str, object]) -> str:
        independent_ran.set()
        return "survived"

    scheduler = TaskScheduler(bus, preflight=FakePreflight(), global_concurrency=3)
    with pytest.raises(PipelineExecutionError):
        await scheduler.execute(
            [
                TaskSpec(id="recon-fail", runner=fail, resource_class="recon"),
                TaskSpec(id="active-dependent", runner=dependent, depends_on=("recon-fail",), resource_class="active"),
                TaskSpec(id="recon-independent", runner=independent, resource_class="recon"),
            ],
            _context(),
            scan_id="p0-partial",
        )
    assert independent_ran.is_set()
    assert dependent_ran is False
    assert scheduler.states["recon-fail"].status == "failed"
    assert scheduler.states["active-dependent"].status == "blocked"
    assert scheduler.states["recon-independent"].status == "completed"
    await bus.close()


@pytest.mark.asyncio
async def test_retry_is_bounded_and_guardrail_denial_is_never_retried() -> None:
    bus = EventBus(heartbeat_interval=60)
    attempts = 0

    async def flaky(context: object, deps: dict[str, object]) -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("transient")
        return "ok"

    scheduler = TaskScheduler(bus, preflight=FakePreflight())
    result = await scheduler.execute(
        [TaskSpec(id="flaky", runner=flaky, timeout=1.0, retry_policy=RetryPolicy(max_attempts=2, base_delay=0.001, max_delay=0.002))],
        _context(),
        scan_id="p0-retry",
    )
    assert result["flaky"] == "ok"
    assert attempts == 2

    denied_attempts = 0

    async def denied(context: object, deps: dict[str, object]) -> None:
        nonlocal denied_attempts
        denied_attempts += 1
        raise PreFlightError("denied")

    with pytest.raises(PipelineExecutionError):
        await scheduler.execute(
            [TaskSpec(id="denied", runner=denied, retry_policy=RetryPolicy(max_attempts=4, base_delay=0.001, max_delay=0.002))],
            _context(),
            scan_id="p0-denied",
        )
    assert denied_attempts == 1
    await bus.close()


def test_scan_event_log_is_monotonic_and_gap_free(tmp_path: Path) -> None:
    db = Database(tmp_path / "windeep.db")
    store = PipelineStore(db)
    target_id = db.create_target("Example", "web", "https://example.com")
    scan_id = db.create_scan(target_id, "v3:p0", ["fixture"])
    first = store.append_scan_event(scan_id, "progress", {"progress": 10}, schema_version="windeep.sse.v1")
    second = store.append_scan_event(scan_id, "evidence", {"artifact": "sha256:fixture"}, schema_version="windeep.sse.v1")
    third = store.append_scan_event(scan_id, "ranked", {"finding_id": 7, "score": 81.0}, schema_version="windeep.sse.v1")
    assert [first["seq"], second["seq"], third["seq"]] == [1, 2, 3]
    replay = store.list_scan_events(scan_id, after_seq=1)
    assert [row["seq"] for row in replay] == [2, 3]
    assert [row["event_type"] for row in replay] == ["evidence", "ranked"]


def test_tool_finding_batch_upsert_is_idempotent_per_tool_run(tmp_path: Path) -> None:
    db = Database(tmp_path / "windeep.db")
    store = PipelineStore(db)
    target_id = db.create_target("Example", "web", "https://example.com")
    scan_id = db.create_scan(target_id, "v3:p0", ["fixture"])
    run_id = db.create_tool_run(tool_name="fixture", status="running", scan_id=scan_id, target_id=target_id)
    finding = {
        "title": "Stable issue",
        "severity": "medium",
        "vuln_type": "reflection",
        "endpoint": "https://example.com/search?q=x",
        "description": "first observation",
        "evidence": {"marker": "inert"},
        "confidence": 0.8,
    }
    first = store.upsert_tool_findings(target_id=target_id, scan_id=scan_id, tool_run_id=run_id, tool_name="fixture", findings=[finding])
    finding["description"] = "same logical issue, refreshed evidence"
    second = store.upsert_tool_findings(target_id=target_id, scan_id=scan_id, tool_run_id=run_id, tool_name="fixture", findings=[finding])
    assert first[0]["id"] == second[0]["id"]
    assert first[0]["created"] is True
    assert second[0]["created"] is False
    with db._connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM tool_finding_refs WHERE scan_id = ? AND tool_run_id = ?", (scan_id, run_id)).fetchone()[0]
    assert count == 1
