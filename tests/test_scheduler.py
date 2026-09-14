"""Tests for the dependency-aware Windeep scheduler."""

from __future__ import annotations

import asyncio
import time

import pytest

from app.engine.event_bus import EventBus
from app.engine.scheduler import (
    PipelineConfigurationError,
    PipelineExecutionError,
    TaskScheduler,
    TaskSpec,
)


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

    scheduler = TaskScheduler(bus, global_concurrency=2)
    results = await scheduler.execute(
        [
            TaskSpec("first", first),
            TaskSpec("second", second, dependencies=("first",)),
        ],
        object(),
        scan_id="s1",
    )
    assert results == {"first": "A", "second": "B"}
    assert order == ["first", "second"]
    await bus.close()


def test_cycle_is_rejected_before_execution() -> None:
    async def noop(context: object, deps: dict[str, object]) -> None:
        return None

    with pytest.raises(PipelineConfigurationError):
        TaskScheduler._validate(
            [
                TaskSpec("a", noop, dependencies=("b",)),
                TaskSpec("b", noop, dependencies=("a",)),
            ]
        )


def test_missing_dependency_is_rejected() -> None:
    async def noop(context: object, deps: dict[str, object]) -> None:
        return None

    with pytest.raises(PipelineConfigurationError):
        TaskScheduler._validate(
            [TaskSpec("a", noop, dependencies=("missing",))]
        )


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

    scheduler = TaskScheduler(
        bus,
        global_concurrency=4,
        per_tool_concurrency={"same": 1},
    )
    await scheduler.execute(
        [TaskSpec(f"t{i}", runner, tool_name="same") for i in range(3)],
        object(),
        scan_id="s2",
    )
    assert peak == 1
    await bus.close()


@pytest.mark.asyncio
async def test_rate_limit_spaces_tool_starts() -> None:
    bus = EventBus(heartbeat_interval=60)
    starts: list[float] = []

    async def runner(context: object, deps: dict[str, object]) -> None:
        starts.append(time.monotonic())

    scheduler = TaskScheduler(
        bus,
        global_concurrency=2,
        per_tool_concurrency={"same": 2},
        per_tool_rate={"same": 20.0},
    )
    await scheduler.execute(
        [
            TaskSpec("a", runner, tool_name="same"),
            TaskSpec("b", runner, tool_name="same"),
        ],
        object(),
        scan_id="s3",
    )
    assert len(starts) == 2
    assert starts[1] - starts[0] >= 0.04
    await bus.close()


@pytest.mark.asyncio
async def test_failure_cancels_pipeline_and_surfaces_task_name() -> None:
    bus = EventBus(heartbeat_interval=60)

    async def fail(context: object, deps: dict[str, object]) -> None:
        raise RuntimeError("boom")

    scheduler = TaskScheduler(bus)
    with pytest.raises(PipelineExecutionError) as exc:
        await scheduler.execute(
            [TaskSpec("explode", fail)], object(), scan_id="s4"
        )
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

    scheduler = TaskScheduler(bus)
    task = asyncio.create_task(
        scheduler.execute(
            [TaskSpec("block", block)], object(), scan_id="s5"
        )
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert scheduler.states["block"].status == "cancelled"
    await bus.close()
