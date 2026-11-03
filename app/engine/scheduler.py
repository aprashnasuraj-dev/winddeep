"""Dependency-aware asyncio task scheduler with mandatory Windeep guardrails."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.engine.event_bus import EventBus
from app.programs.policy import ProgramPolicyViolation, ProgramTestingPolicy
from app.security.preflight import PreFlightError, PreFlightGuard

Runner = Callable[[Any, Mapping[str, Any]], Awaitable[Any] | Any]


class PipelineConfigurationError(ValueError):
    """Raised when a task graph is invalid."""


class PipelineExecutionError(RuntimeError):
    """Raised when a task fails and the pipeline cannot continue."""

    def __init__(self, task_name: str, cause: BaseException) -> None:
        super().__init__(f"pipeline task '{task_name}' failed: {cause}")
        self.task_name = task_name
        self.cause = cause


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """One node in a scan pipeline DAG."""

    name: str
    runner: Runner
    dependencies: tuple[str, ...] = ()
    tool_name: str | None = None
    weight: float = 1.0
    continue_on_error: bool = False
    rate_cost: float = 1.0
    execution_kind: str = "automated_tool"


@dataclass(slots=True)
class TaskState:
    """Execution state retained for diagnostics and UI progress."""

    status: str = "pending"
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None


class TaskScheduler:
    """Run scan DAGs only after mandatory guardrails authorize the scan."""

    def __init__(
        self,
        event_bus: EventBus,
        *,
        preflight: PreFlightGuard | None = None,
        global_concurrency: int = 8,
        per_tool_concurrency: Mapping[str, int] | None = None,
        progress_heartbeat_interval: float = 2.0,
    ) -> None:
        if global_concurrency < 1:
            raise ValueError("global_concurrency must be >= 1")
        if progress_heartbeat_interval <= 0:
            raise ValueError("progress_heartbeat_interval must be > 0")
        self._event_bus = event_bus
        self._preflight = preflight
        self._global_semaphore = asyncio.Semaphore(global_concurrency)
        self._tool_caps = dict(per_tool_concurrency or {})
        if any(value < 1 for value in self._tool_caps.values()):
            raise ValueError("per-tool concurrency values must be >= 1")
        self._progress_heartbeat_interval = float(progress_heartbeat_interval)
        self._tool_semaphores: dict[str, asyncio.Semaphore] = {}
        self.states: dict[str, TaskState] = {}

    async def execute(self, tasks: Sequence[TaskSpec], context: Any, *, scan_id: str) -> dict[str, Any]:
        """Execute a validated DAG after scope, consent, rate, crypto and audit checks."""
        if self._preflight is None:
            raise PreFlightError("scheduler has no PreFlightGuard; scan execution is blocked")
        target = str(getattr(context, "target", "")).strip()
        consent_id = str(getattr(context, "consent_id", "")).strip()
        if not target:
            raise PreFlightError("scan context is missing a target")
        if not consent_id:
            raise PreFlightError("scan context is missing a signed consent id")
        self._preflight.authorize_scan(target=target, consent_id=consent_id)

        specs = self._validate(tasks)
        policy_payload = getattr(context, "program_policy", None)
        if policy_payload:
            if not isinstance(policy_payload, Mapping):
                raise PreFlightError("scan context program policy must be a mapping")
            try:
                policy = ProgramTestingPolicy.from_mapping(policy_payload)
                metadata = getattr(context, "metadata", {})
                if not isinstance(metadata, Mapping):
                    metadata = {}
                for spec in specs.values():
                    policy.assert_execution(spec.execution_kind, target=target, metadata=metadata)
            except (ProgramPolicyViolation, ValueError) as exc:
                raise PreFlightError(f"program policy denied scan plan: {exc}") from exc

        total_weight = sum(spec.weight for spec in specs.values()) or 1.0
        completed_weight = 0.0
        progress_lock = asyncio.Lock()
        results: dict[str, Any] = {}
        self.states = {name: TaskState() for name in specs}
        task_handles: dict[str, asyncio.Task[Any]] = {}
        await self._event_bus.publish("scan.authorized", {"scan_id": scan_id, "target": target, "consent_id": consent_id})

        async def publish_activity(*, phase: str, task: str | None = None) -> None:
            async with progress_lock:
                # Reserve 100% for the outer pipeline's evidence/sealing work.
                progress = min(99.0, round((completed_weight / total_weight) * 100.0, 2))
                completed_tasks = sum(1 for state in self.states.values() if state.status == "completed")
                failed_tasks = sum(1 for state in self.states.values() if state.status == "failed")
                cancelled_tasks = sum(1 for state in self.states.values() if state.status == "cancelled")
                now = time.time()
                running_tasks = [
                    {
                        "task": task_name,
                        "tool": specs[task_name].tool_name or task_name,
                        "elapsed_seconds": round(max(0.0, now - float(state.started_at or now)), 1),
                    }
                    for task_name, state in self.states.items()
                    if state.status == "running"
                ]
            await self._event_bus.publish(
                "scan.progress",
                {
                    "scan_id": scan_id,
                    "progress": progress,
                    "status": "running",
                    "phase": phase,
                    "task": task,
                    "completed_tasks": completed_tasks,
                    "failed_tasks": failed_tasks,
                    "cancelled_tasks": cancelled_tasks,
                    "total_tasks": len(specs),
                    "running_tasks": running_tasks[:16],
                },
            )

        async def run_node(name: str) -> Any:
            nonlocal completed_weight
            spec = specs[name]
            dependency_results: dict[str, Any] = {}
            for dependency in spec.dependencies:
                try:
                    dependency_results[dependency] = await task_handles[dependency]
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if spec.continue_on_error:
                        dependency_results[dependency] = exc
                    else:
                        raise PipelineExecutionError(name, exc) from exc

            state = self.states[name]
            state.status = "running"
            state.started_at = time.time()
            tool_key = spec.tool_name or name
            await self._event_bus.publish("tool.started", {"scan_id": scan_id, "task": name, "tool": tool_key})
            await publish_activity(phase="started", task=name)
            try:
                async with self._global_semaphore:
                    semaphore = self._tool_semaphore(tool_key)
                    async with semaphore:
                        await self._preflight.acquire_rate(tool_key, cost=spec.rate_cost)
                        value = spec.runner(context, dependency_results)
                        if inspect.isawaitable(value):
                            value = await value
                results[name] = value
                state.status = "completed"
                return value
            except asyncio.CancelledError:
                state.status = "cancelled"
                await self._event_bus.publish("tool.cancelled", {"scan_id": scan_id, "task": name})
                raise
            except Exception as exc:
                state.status = "failed"
                state.error = str(exc)
                await self._event_bus.publish("tool.failed", {"scan_id": scan_id, "task": name, "error": str(exc)})
                if spec.continue_on_error:
                    results[name] = exc
                    return exc
                raise PipelineExecutionError(name, exc) from exc
            finally:
                state.finished_at = time.time()
                terminal = state.status in {"completed", "failed", "cancelled"}
                if terminal:
                    async with progress_lock:
                        completed_weight += spec.weight
                    await publish_activity(phase="finished", task=name)
                if state.status == "completed":
                    await self._event_bus.publish("tool.completed", {"scan_id": scan_id, "task": name})

        async def progress_heartbeat() -> None:
            while True:
                await asyncio.sleep(self._progress_heartbeat_interval)
                await publish_activity(phase="heartbeat")

        for name in self._topological_order(specs):
            task_handles[name] = asyncio.create_task(run_node(name), name=f"windeep:{scan_id}:{name}")
        heartbeat_task = asyncio.create_task(
            progress_heartbeat(),
            name=f"windeep:{scan_id}:progress-heartbeat",
        )

        try:
            await asyncio.gather(*task_handles.values())
        except asyncio.CancelledError:
            for task in task_handles.values():
                task.cancel()
            for task in task_handles.values():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            await self._event_bus.publish("scan.cancelled", {"scan_id": scan_id})
            raise
        except Exception:
            for task in task_handles.values():
                if not task.done():
                    task.cancel()
            for task in task_handles.values():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            await self._event_bus.publish("scan.failed", {"scan_id": scan_id})
            raise
        finally:
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task

        await self._event_bus.publish("scan.completed", {"scan_id": scan_id, "progress": 100.0})
        return results

    def _tool_semaphore(self, tool_name: str) -> asyncio.Semaphore:
        semaphore = self._tool_semaphores.get(tool_name)
        if semaphore is None:
            semaphore = asyncio.Semaphore(self._tool_caps.get(tool_name, self._tool_caps.get("*", 1)))
            self._tool_semaphores[tool_name] = semaphore
        return semaphore

    @staticmethod
    def _validate(tasks: Sequence[TaskSpec]) -> dict[str, TaskSpec]:
        specs: dict[str, TaskSpec] = {}
        for spec in tasks:
            if not spec.name.strip():
                raise PipelineConfigurationError("task name cannot be empty")
            if spec.name in specs:
                raise PipelineConfigurationError(f"duplicate task: {spec.name}")
            if spec.weight <= 0:
                raise PipelineConfigurationError(f"task weight must be > 0: {spec.name}")
            if spec.rate_cost <= 0:
                raise PipelineConfigurationError(f"task rate_cost must be > 0: {spec.name}")
            if not spec.execution_kind.strip():
                raise PipelineConfigurationError(f"task execution_kind cannot be empty: {spec.name}")
            specs[spec.name] = spec
        for spec in specs.values():
            missing = [dependency for dependency in spec.dependencies if dependency not in specs]
            if missing:
                raise PipelineConfigurationError(f"task '{spec.name}' has missing dependencies: {missing}")
        TaskScheduler._topological_order(specs)
        return specs

    @staticmethod
    def _topological_order(specs: Mapping[str, TaskSpec]) -> list[str]:
        visiting: set[str] = set()
        visited: set[str] = set()
        order: list[str] = []

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                raise PipelineConfigurationError(f"dependency cycle includes '{name}'")
            visiting.add(name)
            for dependency in specs[name].dependencies:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)
            order.append(name)

        for name in specs:
            visit(name)
        return order
