"""Dependency-aware asyncio task scheduler with mandatory Windeep guardrails."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import inspect
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.engine.event_bus import EventBus
from app.security.preflight import PreFlightError, PreFlightGuard

Runner = Callable[[Any, Mapping[str, Any]], Awaitable[Any] | Any]
_RESOURCE_CLASSES = frozenset({"recon", "active", "web3", "browser", "llm"})


class PipelineConfigurationError(ValueError):
    """Raised when a task graph is invalid."""


class PipelineExecutionError(RuntimeError):
    """Raised after branch-isolated execution when a non-tolerated task failed."""

    def __init__(self, task_name: str, cause: BaseException) -> None:
        super().__init__(f"pipeline task '{task_name}' failed: {cause}")
        self.task_name = task_name
        self.cause = cause


class TaskBlockedError(RuntimeError):
    """Raised internally when an upstream dependency did not complete."""


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded deterministic-jitter retry policy for one task node."""

    max_attempts: int = 1
    base_delay: float = 0.25
    max_delay: float = 2.0
    jitter_ratio: float = 0.20

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.max_attempts > 8:
            raise ValueError("max_attempts must be between 1 and 8")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("retry delays must be non-negative")
        if self.base_delay > self.max_delay:
            raise ValueError("base_delay cannot exceed max_delay")
        if not 0.0 <= self.jitter_ratio <= 1.0:
            raise ValueError("jitter_ratio must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """One node in a scan pipeline DAG.

    ``name``/``dependencies`` remain supported for the v2 engine while v3 uses
    the explicit ``id``/``depends_on`` contract.  Supplying both forms with
    different values is rejected before execution.
    """

    name: str = ""
    runner: Runner | None = None
    dependencies: tuple[str, ...] = ()
    tool_name: str | None = None
    weight: float = 1.0
    continue_on_error: bool = False
    rate_cost: float = 1.0
    id: str | None = None
    kind: str = "tool"
    depends_on: tuple[str, ...] = ()
    resource_class: str = "active"
    timeout: float = 120.0
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    cancellable: bool = True

    @property
    def task_id(self) -> str:
        return str(self.id or self.name).strip()

    @property
    def dependency_ids(self) -> tuple[str, ...]:
        if self.depends_on and self.dependencies and self.depends_on != self.dependencies:
            raise PipelineConfigurationError(f"task '{self.task_id}' declares conflicting dependency aliases")
        return self.depends_on or self.dependencies


@dataclass(slots=True)
class TaskState:
    """Execution state retained for diagnostics and UI progress."""

    status: str = "pending"
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    attempts: int = 0


class TaskScheduler:
    """Run scan DAGs only after mandatory guardrails authorize the scan."""

    def __init__(
        self,
        event_bus: EventBus,
        *,
        preflight: PreFlightGuard | None = None,
        global_concurrency: int = 8,
        per_tool_concurrency: Mapping[str, int] | None = None,
    ) -> None:
        if global_concurrency < 1:
            raise ValueError("global_concurrency must be >= 1")
        self._event_bus = event_bus
        self._preflight = preflight
        self._global_semaphore = asyncio.Semaphore(global_concurrency)
        self._tool_caps = dict(per_tool_concurrency or {})
        if any(value < 1 for value in self._tool_caps.values()):
            raise ValueError("per-tool concurrency values must be >= 1")
        self._tool_semaphores: dict[str, asyncio.Semaphore] = {}
        self.states: dict[str, TaskState] = {}

    async def execute(
        self,
        tasks: Sequence[TaskSpec],
        context: Any,
        *,
        scan_id: str,
        raise_on_error: bool = True,
    ) -> dict[str, Any]:
        """Execute a validated DAG with branch-isolated failure semantics.

        Independent branches are allowed to finish when another branch fails.
        Dependents of a failed/cancelled/blocked node are themselves blocked by
        default.  After all runnable branches drain, the first non-tolerated
        failure is raised unless ``raise_on_error`` is false.
        """
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
        total_weight = sum(spec.weight for spec in specs.values()) or 1.0
        completed_weight = 0.0
        progress_lock = asyncio.Lock()
        results: dict[str, Any] = {}
        self.states = {name: TaskState() for name in specs}
        task_handles: dict[str, asyncio.Task[Any]] = {}
        await self._event_bus.publish("scan.authorized", {"scan_id": scan_id, "target": target, "consent_id": consent_id})

        async def finish_progress(name: str, spec: TaskSpec, state: TaskState) -> None:
            nonlocal completed_weight
            state.finished_at = time.time()
            async with progress_lock:
                if state.status in {"completed", "failed", "cancelled", "blocked"}:
                    completed_weight += spec.weight
                    progress = min(100.0, round((completed_weight / total_weight) * 100.0, 2))
                    await self._event_bus.publish(
                        "scan.progress",
                        {"scan_id": scan_id, "task": name, "progress": progress, "status": state.status},
                    )

        async def run_node(name: str) -> Any:
            spec = specs[name]
            state = self.states[name]
            dependency_results: dict[str, Any] = {}
            for dependency in spec.dependency_ids:
                dependency_results[dependency] = await task_handles[dependency]
                dependency_state = self.states[dependency]
                if dependency_state.status != "completed" and not spec.continue_on_error:
                    blocked = TaskBlockedError(
                        f"dependency '{dependency}' ended as {dependency_state.status}"
                    )
                    state.status = "blocked"
                    state.error = str(blocked)
                    results[name] = blocked
                    await self._event_bus.publish(
                        "tool.blocked",
                        {"scan_id": scan_id, "task": name, "dependency": dependency, "status": dependency_state.status},
                    )
                    await finish_progress(name, spec, state)
                    return blocked

            state.status = "running"
            state.started_at = time.time()
            tool_key = spec.tool_name or name
            await self._event_bus.publish(
                "tool.started",
                {
                    "scan_id": scan_id,
                    "task": name,
                    "tool": tool_key,
                    "kind": spec.kind,
                    "resource_class": spec.resource_class,
                },
            )
            try:
                value = await self._run_with_retries(
                    spec,
                    context,
                    dependency_results,
                    target=target,
                    consent_id=consent_id,
                    tool_key=tool_key,
                    state=state,
                )
                results[name] = value
                state.status = "completed"
                await self._event_bus.publish("tool.completed", {"scan_id": scan_id, "task": name})
                return value
            except asyncio.CancelledError:
                state.status = "cancelled"
                await self._event_bus.publish("tool.cancelled", {"scan_id": scan_id, "task": name})
                raise
            except Exception as exc:
                state.status = "failed"
                state.error = str(exc)
                results[name] = exc
                await self._event_bus.publish("tool.failed", {"scan_id": scan_id, "task": name, "error": str(exc)})
                return exc
            finally:
                await finish_progress(name, spec, state)

        for name in self._topological_order(specs):
            task_handles[name] = asyncio.create_task(run_node(name), name=f"windeep:{scan_id}:{name}")

        try:
            await asyncio.gather(*task_handles.values())
        except asyncio.CancelledError:
            for name, task in task_handles.items():
                if specs[name].cancellable:
                    task.cancel()
            for task in task_handles.values():
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            await self._event_bus.publish("scan.cancelled", {"scan_id": scan_id})
            raise

        hard_failures = [
            (name, results.get(name))
            for name, state in self.states.items()
            if state.status == "failed" and not specs[name].continue_on_error
        ]
        blocked = [name for name, state in self.states.items() if state.status == "blocked"]
        if hard_failures:
            first_name, first_error = hard_failures[0]
            await self._event_bus.publish(
                "scan.failed",
                {
                    "scan_id": scan_id,
                    "failed_tasks": [name for name, _ in hard_failures],
                    "blocked_tasks": blocked,
                    "partial": any(state.status == "completed" for state in self.states.values()),
                },
            )
            if raise_on_error:
                cause = first_error if isinstance(first_error, BaseException) else RuntimeError(str(first_error))
                raise PipelineExecutionError(first_name, cause)
        else:
            await self._event_bus.publish("scan.completed", {"scan_id": scan_id, "progress": 100.0})
        return results

    async def _run_with_retries(
        self,
        spec: TaskSpec,
        context: Any,
        dependency_results: Mapping[str, Any],
        *,
        target: str,
        consent_id: str,
        tool_key: str,
        state: TaskState,
    ) -> Any:
        if spec.runner is None:
            raise PipelineConfigurationError(f"task '{spec.task_id}' has no runner")
        last_error: BaseException | None = None
        for attempt in range(1, spec.retry_policy.max_attempts + 1):
            state.attempts = attempt
            try:
                authorize_tool = getattr(self._preflight, "authorize_tool", None)
                if callable(authorize_tool):
                    authorize_tool(target=target, consent_id=consent_id, tool_name=tool_key)
                async with self._global_semaphore:
                    semaphore = self._tool_semaphore(tool_key)
                    async with semaphore:
                        await self._preflight.acquire_rate(tool_key, cost=spec.rate_cost)
                        acquire_host_rate = getattr(self._preflight, "acquire_host_rate", None)
                        if callable(acquire_host_rate):
                            await acquire_host_rate(target, cost=spec.rate_cost)
                        value = spec.runner(context, dependency_results)
                        if inspect.isawaitable(value):
                            value = await asyncio.wait_for(value, timeout=spec.timeout)
                        return value
            except asyncio.CancelledError:
                raise
            except PreFlightError:
                raise
            except Exception as exc:
                last_error = exc
                if attempt >= spec.retry_policy.max_attempts:
                    raise
                await asyncio.sleep(self._retry_delay(spec.task_id, attempt, spec.retry_policy))
        if last_error is not None:
            raise last_error
        raise RuntimeError("task retry loop terminated without a result")

    @staticmethod
    def _retry_delay(task_id: str, attempt: int, policy: RetryPolicy) -> float:
        base = min(policy.max_delay, policy.base_delay * (2 ** max(0, attempt - 1)))
        if base <= 0 or policy.jitter_ratio <= 0:
            return base
        digest = hashlib.sha256(f"{task_id}:{attempt}".encode("utf-8")).digest()
        unit = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
        centered = (unit * 2.0) - 1.0
        return max(0.0, min(policy.max_delay, base * (1.0 + centered * policy.jitter_ratio)))

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
            name = spec.task_id
            if not name:
                raise PipelineConfigurationError("task id cannot be empty")
            if name in specs:
                raise PipelineConfigurationError(f"duplicate task: {name}")
            if spec.runner is None:
                raise PipelineConfigurationError(f"task '{name}' has no runner")
            if spec.weight <= 0:
                raise PipelineConfigurationError(f"task weight must be > 0: {name}")
            if spec.rate_cost <= 0:
                raise PipelineConfigurationError(f"task rate_cost must be > 0: {name}")
            if spec.timeout <= 0:
                raise PipelineConfigurationError(f"task timeout must be > 0: {name}")
            if spec.resource_class not in _RESOURCE_CLASSES:
                raise PipelineConfigurationError(
                    f"task '{name}' has unsupported resource_class '{spec.resource_class}'"
                )
            _ = spec.dependency_ids
            specs[name] = spec
        for name, spec in specs.items():
            missing = [dependency for dependency in spec.dependency_ids if dependency not in specs]
            if missing:
                raise PipelineConfigurationError(f"task '{name}' has missing dependencies: {missing}")
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
            for dependency in specs[name].dependency_ids:
                visit(dependency)
            visiting.remove(name)
            visited.add(name)
            order.append(name)

        for name in specs:
            visit(name)
        return order
