"""Tests for the dependency-aware, guardrail-first Windeep scheduler."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.engine.event_bus import EventBus
from app.engine.scheduler import PipelineConfigurationError, PipelineExecutionError, TaskScheduler, TaskSpec
from app.security.preflight import PreFlightError


class FakePreflight:
    """Minimal authorization stub for scheduler unit tests."""

    def __init__(self) -> None:
        self.authorized: list[tuple[str, str]] = []
        self.rate_keys: list[str] = []

    def authorize_scan(self, *, target: str, consent_id: str) -> object:
        self.authorized.append((target, consent_id))
        return object()

    async def acquire_rate(self, key: str, *, cost: float = 1.0) -> None:
        self.rate_keys.append(key)
        await asyncio.sleep(0)


def _context() -> SimpleNamespace:
    return SimpleNamespace(target="https://example.com", consent_id="signed-consent")


@pytest.mark.asyncio
async def test_dependencies_run_before_dependent_task() -> None:
    bus = EventBus(heartbeat_interval=60)
    order: list[str] = []

    async def first(context: object, deps: dict[str, object]) -> str:
        order.append("first")
        return "A"

    async def second(context: object, deps: dict[str, object]) -> str:
        assert deps["first"] == "A"
        order.append("second")
        return "B"

    guard = FakePreflight()
    scheduler = TaskScheduler(bus, preflight=guard, global_concurrency=2)
    results = await scheduler.execute(
        [TaskSpec("first", first), TaskSpec("second", second, dependencies=("first",))],
        _context(),
        scan_id="s1",
    )
    assert results == {"first": "A", "second": "B"}
    assert order == ["first", "second"]
    assert guard.authorized == [("https://example.com", "signed-consent")]
    await bus.close()


def test_cycle_is_rejected_before_execution() -> None:
    async def noop(context: object, deps: dict[str, object]) -> None:
        return None

    with pytest.raises(PipelineConfigurationError):
        TaskScheduler._validate([TaskSpec("a", noop, dependencies=("b",)), TaskSpec("b", noop, dependencies=("a",))])


def test_missing_dependency_is_rejected() -> None:
    async def noop(context: object, deps: dict[str, object]) -> None:
        return None

    with pytest.raises(PipelineConfigurationError):
        TaskScheduler._validate([TaskSpec("a", noop, dependencies=("missing",))])


@pytest.mark.asyncio
async def test_scheduler_blocks_without_preflight() -> None:
    bus = EventBus(heartbeat_interval=60)

    async def noop(context: object, deps: dict[str, object]) -> None:
        return None

    scheduler = TaskScheduler(bus)
    with pytest.raises(PreFlightError):
        await scheduler.execute([TaskSpec("a", noop)], _context(), scan_id="blocked")
    await bus.close()


@pytest.mark.asyncio
async def test_per_tool_concurrency_cap_is_respected() -> None:
    bus = EventBus(heartbeat_interval=60)
    active = 0
    peak = 0
    lock = asyncio.Lock()

    async def runner(context: object, deps: dict[str, object]) -> None:
        nonlocal active, peak
        async with lock:
            active += 1
            peak = max(peak, active)
        await asyncio.sleep(0.03)
        async with lock:
            active -= 1

    scheduler = TaskScheduler(bus, preflight=FakePreflight(), global_concurrency=4, per_tool_concurrency={"same": 1})
    await scheduler.execute([TaskSpec(f"t{i}", runner, tool_name="same") for i in range(3)], _context(), scan_id="s2")
    assert peak == 1
    await bus.close()


@pytest.mark.asyncio
async def test_all_tasks_pass_through_rate_governor_hook() -> None:
    bus = EventBus(heartbeat_interval=60)
    guard = FakePreflight()

    async def runner(context: object, deps: dict[str, object]) -> None:
        return None

    scheduler = TaskScheduler(bus, preflight=guard, global_concurrency=2, per_tool_concurrency={"same": 2})
    await scheduler.execute([TaskSpec("a", runner, tool_name="same"), TaskSpec("b", runner, tool_name="same")], _context(), scan_id="s3")
    assert guard.rate_keys == ["same", "same"]
    await bus.close()


@pytest.mark.asyncio
async def test_failure_cancels_pipeline_and_surfaces_task_name() -> None:
    bus = EventBus(heartbeat_interval=60)

    async def fail(context: object, deps: dict[str, object]) -> None:
        raise RuntimeError("boom")

    scheduler = TaskScheduler(bus, preflight=FakePreflight())
    with pytest.raises(PipelineExecutionError) as exc:
        await scheduler.execute([TaskSpec("explode", fail)], _context(), scan_id="s4")
    assert exc.value.task_name == "explode"
    assert scheduler.states["explode"].status == "failed"
    await bus.close()


@pytest.mark.asyncio
async def test_scheduler_propagates_cancellation() -> None:
    bus = EventBus(heartbeat_interval=60)
    started = asyncio.Event()

    async def block(context: object, deps: dict[str, object]) -> None:
        started.set()
        await asyncio.Event().wait()

    scheduler = TaskScheduler(bus, preflight=FakePreflight())
    task = asyncio.create_task(scheduler.execute([TaskSpec("block", block)], _context(), scan_id="s5"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert scheduler.states["block"].status == "cancelled"
    await bus.close()


@pytest.mark.asyncio
async def test_program_policy_blocks_automated_tool_before_runner_starts() -> None:
    bus = EventBus(heartbeat_interval=60)
    called = False

    async def runner(context: object, deps: dict[str, object]) -> None:
        nonlocal called
        called = True

    context = SimpleNamespace(
        target="https://example.com",
        consent_id="signed-consent",
        program_policy={
            "automated_tooling_allowed": False,
            "allowed_hosts": ["example.com"],
        },
        metadata={},
    )
    scheduler = TaskScheduler(bus, preflight=FakePreflight())
    with pytest.raises(PreFlightError, match="program rules prohibit automated tools/scanners"):
        await scheduler.execute(
            [TaskSpec("scanner", runner, execution_kind="automated_tool")],
            context,
            scan_id="policy-block",
        )
    assert called is False
    await bus.close()


@pytest.mark.asyncio
async def test_program_policy_keeps_local_analysis_available_when_scanners_are_forbidden() -> None:
    bus = EventBus(heartbeat_interval=60)

    async def runner(context: object, deps: dict[str, object]) -> str:
        return "local-result"

    context = SimpleNamespace(
        target="https://example.com",
        consent_id="signed-consent",
        program_policy={"automated_tooling_allowed": False},
        metadata={},
    )
    scheduler = TaskScheduler(bus, preflight=FakePreflight())
    result = await scheduler.execute(
        [TaskSpec("analysis", runner, execution_kind="local_analysis")],
        context,
        scan_id="policy-local",
    )
    assert result == {"analysis": "local-result"}
    await bus.close()


@pytest.mark.asyncio
async def test_program_policy_is_context_local_and_does_not_restrict_other_targets() -> None:
    bus = EventBus(heartbeat_interval=60)
    calls: list[str] = []

    async def runner(context: object, deps: dict[str, object]) -> str:
        calls.append(str(getattr(context, "target", "")))
        return "ok"

    scheduler = TaskScheduler(bus, preflight=FakePreflight())

    restricted = SimpleNamespace(
        target="https://bugbounty-test-researcher.atlassian.net",
        consent_id="signed-consent",
        program_policy={
            "automated_tooling_allowed": False,
            "allowed_hosts": ["bugbounty-test-researcher.atlassian.net"],
        },
        metadata={},
    )
    with pytest.raises(PreFlightError, match="program rules prohibit automated tools/scanners"):
        await scheduler.execute(
            [TaskSpec("scanner", runner, execution_kind="automated_tool")],
            restricted,
            scan_id="program-restricted",
        )

    unrelated = SimpleNamespace(
        target="https://other-authorized.example",
        consent_id="signed-consent",
        program_policy={},
        metadata={},
    )
    result = await scheduler.execute(
        [TaskSpec("scanner", runner, execution_kind="automated_tool")],
        unrelated,
        scan_id="unrelated-target",
    )

    assert result == {"scanner": "ok"}
    assert calls == ["https://other-authorized.example"]
    await bus.close()
