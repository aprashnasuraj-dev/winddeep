"""P0 scheduler-driven v2 scan pipeline.

This module is deliberately narrow: it wires existing Windeep engines into a
single-loop DAG without weakening preflight. It does not add signatures,
payloads, exploitation, or direct network/subprocess paths.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
import re
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from app.brain.chain_builder import ChainBuilder
from app.brain.finding_ranker import FindingRanker
from app.brain.hypothesis_engine import HypothesisEngine
from app.brain.llm_client import LLMClient
from app.brain.runtime_config import build_llm_client
from app.database import finding_fingerprint
from app.duplicates import DuplicateDetector
from app.engine.event_bus import EventBus
from app.engine.scan_context import ScanContext
from app.engine.scheduler import TaskScheduler, TaskSpec
from app.engine.tool_wrapper import ToolCancelledError, ToolExecutionError
from app.evidence.assembler import EvidenceAssembler
from app.evidence.bundles import EvidenceBundleStore
from app.evidence.raw_store import RawArtifactStore
from app.security.preflight import PreFlightError
from app.v3.verification import VerificationError, VerificationPass

_ALLOWED_RESOURCE_CLASSES = frozenset({"recon", "active", "web3", "browser", "llm"})
_EXPORT_EVENT_TYPES = frozenset({"finding", "progress", "log", "evidence", "chain", "ranked"})
_SECRET_KEY_RE = re.compile(r"(?:authorization|cookie|set-cookie|api[_-]?key|token|password|secret|credential)", re.I)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*")
_SECRET_LITERAL_RE = re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*([^\s,;]+)")


def canonical_bytes(value: Any) -> bytes:
    """Serialize stage output with stable key ordering and fixed separators."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sanitize_string(value: str) -> str:
    value = _BEARER_RE.sub("Bearer [REDACTED]", value)
    return _SECRET_LITERAL_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def sanitize_export(value: Any) -> Any:
    """Apply the P0 export-surface safety pass before SSE/broadcast output."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            text_key = str(key)
            if _SECRET_KEY_RE.search(text_key):
                result[text_key] = "[REDACTED]"
            else:
                result[text_key] = sanitize_export(value[key])
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize_export(item) for item in value]
    if isinstance(value, bytes):
        return f"<bytes:{len(value)} sha256={hashlib.sha256(value).hexdigest()}>"
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded task retry policy; guardrail denials are never retried."""

    max_attempts: int = 1
    base_delay: float = 0.25
    max_delay: float = 2.0
    jitter: float = 0.20

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.max_attempts > 8:
            raise ValueError("max_attempts must be between 1 and 8")
        if self.base_delay < 0 or self.max_delay < self.base_delay:
            raise ValueError("invalid retry delay bounds")
        if not 0.0 <= self.jitter <= 1.0:
            raise ValueError("jitter must be between 0 and 1")

    def delay(self, attempt: int) -> float:
        base = min(self.max_delay, self.base_delay * (2 ** max(0, attempt - 1)))
        spread = base * self.jitter
        return max(0.0, min(self.max_delay, base + random.uniform(-spread, spread)))


Runner = Callable[[Any, Mapping[str, Any]], Awaitable[Any] | Any]


@dataclass(frozen=True, slots=True)
class PipelineNode:
    """P0 task node contract compiled onto the existing TaskScheduler."""

    id: str
    kind: str
    runner: Runner
    depends_on: tuple[str, ...] = ()
    resource_class: str = "active"
    timeout: float = 120.0
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    cancellable: bool = True
    tool_name: str | None = None
    rate_cost: float = 1.0
    execution_kind: str = "local_analysis"

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("task id cannot be empty")
        if self.resource_class not in _ALLOWED_RESOURCE_CLASSES:
            raise ValueError(f"unsupported resource class: {self.resource_class}")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

    def to_task_spec(self) -> TaskSpec:
        return TaskSpec(
            self.id,
            self.runner,
            dependencies=self.depends_on,
            tool_name=self.tool_name or self.id,
            continue_on_error=True,
            rate_cost=self.rate_cost,
            execution_kind=self.execution_kind,
            timeout=self.timeout,
        )


def _resource_class(category: str) -> str:
    if category == "recon_passive":
        return "recon"
    if category == "web3":
        return "web3"
    return "active"


def build_tool_nodes(
    selected: Sequence[str],
    wrapper_classes: Mapping[str, Any],
    *,
    runner_factory: Callable[[str], Runner],
) -> list[PipelineNode]:
    """Build explicit dependencies: passive recon fans out; active/web wait for it."""
    passive_ids = tuple(
        f"tool:{name}"
        for name in sorted(selected)
        if str(getattr(wrapper_classes[name], "category", "")) == "recon_passive"
    )
    nodes: list[PipelineNode] = []
    for name in sorted(selected):
        cls = wrapper_classes[name]
        category = str(getattr(cls, "category", "utilities"))
        dependencies = passive_ids if category in {"recon_active", "web_vulns", "network"} else ()
        retries = max(0, int(getattr(cls, "retries", 0)))
        nodes.append(
            PipelineNode(
                id=f"tool:{name}",
                kind="tool",
                runner=runner_factory(name),
                depends_on=dependencies,
                resource_class=_resource_class(category),
                timeout=max(1.0, float(getattr(cls, "timeout", 120.0))),
                retry_policy=RetryPolicy(max_attempts=min(8, retries + 1)),
                cancellable=True,
                tool_name=name,
                execution_kind="automated_tool",
            )
        )
    return nodes


class ScanEventLog:
    """Encrypted, monotonic, replayable SSE event log."""

    def __init__(self, database: Any, crypto: Any) -> None:
        self.database = database
        self.crypto = crypto

    def ensure_schema(self) -> None:
        with self.database._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_events (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(scan_id, seq)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_replay ON scan_events(scan_id, seq)")

    def append(self, scan_id: int, event_type: str, data: Mapping[str, Any]) -> dict[str, Any]:
        if event_type not in _EXPORT_EVENT_TYPES:
            raise ValueError(f"unsupported export event type: {event_type}")
        sanitized = sanitize_export(dict(data))
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT COALESCE(MAX(seq), 0) AS seq FROM scan_events WHERE scan_id = ?", (scan_id,)).fetchone()
            seq = int(row["seq"]) + 1
            body = {"schema": "windeep.sse.v1", "scan_id": scan_id, "seq": seq, "type": event_type, "data": sanitized}
            encrypted = self.crypto.encrypt_text(canonical_bytes(body).decode("utf-8"), aad=f"windeep:sse:{scan_id}:{seq}".encode("utf-8"))
            conn.execute(
                "INSERT INTO scan_events(scan_id, seq, event_type, schema_version, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, seq, event_type, "1", encrypted, time.time()),
            )
        return body

    def list_after(self, scan_id: int, last_seq: int, *, limit: int = 1000) -> list[dict[str, Any]]:
        if last_seq < 0:
            raise ValueError("last_seq cannot be negative")
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT seq, payload FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                (scan_id, last_seq, limit),
            ).fetchall()
        events: list[dict[str, Any]] = []
        expected = last_seq + 1
        for row in rows:
            seq = int(row["seq"])
            if seq != expected:
                raise RuntimeError(f"scan event gap detected: expected {expected}, got {seq}")
            plaintext = self.crypto.decrypt_text(str(row["payload"]), aad=f"windeep:sse:{scan_id}:{seq}".encode("utf-8"))
            events.append(json.loads(plaintext))
            expected += 1
        return events


class FindingBatchWriter:
    """Persist one tool's normalized findings in one encrypted transaction."""

    def __init__(self, database: Any) -> None:
        self.database = database

    def ensure_schema(self) -> None:
        with self.database._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
                    finding_fingerprint TEXT NOT NULL,
                    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(scan_id, tool_run_id, finding_fingerprint)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id, finding_fingerprint)")

    def persist(
        self,
        *,
        scan_id: int,
        tool_run_id: int,
        target_id: int,
        tool_name: str,
        findings: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for raw in findings:
            payload = dict(raw)
            payload["title"] = str(payload.get("title") or "Untitled finding")
            payload["severity"] = str(payload.get("severity") or "info").lower()
            payload["vuln_type"] = str(payload.get("vuln_type") or "tool_output")
            payload["tool"] = tool_name
            try:
                raw_confidence = payload.get("confidence")
                confidence = 0.5 if raw_confidence is None else float(raw_confidence)
            except (TypeError, ValueError, OverflowError):
                confidence = 0.5
            payload["confidence"] = max(0.0, min(1.0, confidence)) if math.isfinite(confidence) else 0.5
            payload["evidence"] = dict(payload.get("evidence") or {})
            endpoint = str(payload.get("endpoint") or "<scope-bound target>")
            payload["steps"] = str(payload.get("steps") or "").strip() or (
                f"1. Run `{tool_name}` against the same authorized target and observation point `{endpoint}`.\n"
                "2. Keep the same approved scope and authentication context used by the recorded scan.\n"
                "3. Compare the resulting non-destructive observation with the stored evidence; do not add an exploitation step."
            )
            payload["fingerprint"] = finding_fingerprint(
                target_id=target_id,
                title=payload["title"],
                vuln_type=payload["vuln_type"],
                endpoint=str(payload.get("endpoint")) if payload.get("endpoint") else None,
            )
            payload["stable_json"] = canonical_bytes({key: value for key, value in payload.items() if key != "stable_json"}).decode("utf-8")
            normalized.append(payload)
        normalized.sort(key=lambda item: (item["fingerprint"], item["title"], str(item.get("endpoint") or "")))
        if not normalized:
            return []

        fingerprints = [item["fingerprint"] for item in normalized]
        placeholders = ",".join("?" for _ in fingerprints)
        now = time.time()
        with self.database._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing_rows = conn.execute(
                f"SELECT finding_fingerprint FROM scan_findings WHERE scan_id = ? AND tool_run_id = ? AND finding_fingerprint IN ({placeholders})",
                (scan_id, tool_run_id, *fingerprints),
            ).fetchall()
            existing_keys = {str(row["finding_fingerprint"]) for row in existing_rows}

            finding_rows: list[tuple[Any, ...]] = []
            for item in normalized:
                evidence_json = json.dumps(item["evidence"], ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
                finding_rows.append(
                    (
                        scan_id,
                        target_id,
                        item["title"],
                        item["severity"],
                        item.get("cvss_score"),
                        item.get("cvss_vector"),
                        item["vuln_type"],
                        tool_name,
                        item.get("endpoint"),
                        self.database._enc(str(item.get("description") or ""), field="finding.description"),
                        self.database._enc(evidence_json, field="finding.evidence"),
                        self.database._enc(str(item.get("request") or ""), field="finding.request"),
                        self.database._enc(str(item.get("response") or ""), field="finding.response"),
                        self.database._enc(str(item.get("steps") or ""), field="finding.steps"),
                        self.database._enc(str(item.get("impact") or ""), field="finding.impact"),
                        self.database._enc(str(item.get("remediation") or ""), field="finding.remediation"),
                        str(item.get("status") or "new"),
                        item["fingerprint"],
                        item["confidence"],
                        now,
                        now,
                    )
                )
            conn.executemany(
                """
                INSERT OR IGNORE INTO findings(
                    scan_id, target_id, title, severity, cvss_score, cvss_vector,
                    vuln_type, tool, endpoint, description, evidence, request, response,
                    steps, impact, remediation, status, fingerprint, confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                finding_rows,
            )
            id_rows = conn.execute(
                f"SELECT id, fingerprint FROM findings WHERE fingerprint IN ({placeholders})",
                tuple(fingerprints),
            ).fetchall()
            finding_ids = {str(row["fingerprint"]): int(row["id"]) for row in id_rows}
            scan_rows: list[tuple[Any, ...]] = []
            for item in normalized:
                finding_id = finding_ids[item["fingerprint"]]
                stored_payload = dict(item)
                stored_payload["finding_id"] = finding_id
                encrypted_payload = self.database._enc(
                    canonical_bytes(stored_payload).decode("utf-8"), field="scan_finding.payload"
                )
                scan_rows.append((scan_id, tool_run_id, item["fingerprint"], finding_id, encrypted_payload, now, now))
                item["finding_id"] = finding_id
                item["created"] = item["fingerprint"] not in existing_keys
            conn.executemany(
                """
                INSERT INTO scan_findings(scan_id, tool_run_id, finding_fingerprint, finding_id, payload, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, tool_run_id, finding_fingerprint) DO UPDATE SET
                    finding_id = excluded.finding_id,
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                scan_rows,
            )
        return normalized

    def read_scan_findings(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM scan_findings WHERE scan_id = ? ORDER BY finding_fingerprint, tool_run_id",
                (scan_id,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            plaintext = self.database._dec(str(row["payload"]), field="scan_finding.payload")
            items.append(json.loads(plaintext))
        return items


class AssetObservationStore:
    """Persist reconnaissance output without promoting it into vulnerability findings."""

    _ARCHIVE_TOOLS = frozenset({"gau", "waybackurls", "waymore", "waybackrobots"})

    def __init__(self, database: Any) -> None:
        self.database = database

    def ensure_schema(self) -> None:
        with self.database._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_asset_observations (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    tool_run_id INTEGER NOT NULL REFERENCES tool_runs(id) ON DELETE CASCADE,
                    observation_fingerprint TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    endpoint TEXT,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY(scan_id, tool_run_id, observation_fingerprint)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_asset_observations_scan "
                "ON scan_asset_observations(scan_id, tool, observation_fingerprint)"
            )

    @classmethod
    def _temporal_scope(cls, tool_name: str, payload: Mapping[str, Any]) -> str:
        evidence = payload.get("evidence") if isinstance(payload.get("evidence"), Mapping) else {}
        adapter = str(evidence.get("adapter") or "")
        if tool_name in cls._ARCHIVE_TOOLS or adapter == "wayback_cdx":
            return "historical"
        return "current_or_unspecified"

    def persist(
        self,
        *,
        scan_id: int,
        tool_run_id: int,
        tool_name: str,
        observations: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        now = time.time()
        normalized: list[dict[str, Any]] = []
        for raw in observations:
            payload = dict(raw)
            evidence = dict(payload.get("evidence") or {})
            endpoint = str(payload.get("endpoint") or "")
            title = str(payload.get("title") or endpoint or "Reconnaissance observation")
            temporal_scope = self._temporal_scope(tool_name, payload)
            evidence["result_role"] = "observation"
            evidence["submission_candidate"] = False
            evidence["temporal_scope"] = temporal_scope
            payload.update(
                {
                    "title": title,
                    "tool": tool_name,
                    "endpoint": endpoint or None,
                    "severity": "info",
                    "vuln_type": "asset_observation",
                    "result_role": "observation",
                    "submission_candidate": False,
                    "temporal_scope": temporal_scope,
                    "evidence": evidence,
                }
            )
            fingerprint_source = {
                "tool": tool_name,
                "endpoint": endpoint,
                "title": title,
                "temporal_scope": temporal_scope,
            }
            payload["observation_fingerprint"] = hashlib.sha256(canonical_bytes(fingerprint_source)).hexdigest()
            normalized.append(payload)

        normalized.sort(
            key=lambda item: (
                str(item["observation_fingerprint"]),
                str(item.get("endpoint") or ""),
                str(item.get("title") or ""),
            )
        )
        if not normalized:
            return []

        rows: list[tuple[Any, ...]] = []
        for item in normalized:
            encrypted = self.database._enc(
                canonical_bytes(item).decode("utf-8"),
                field="scan_asset_observation.payload",
            )
            rows.append(
                (
                    int(scan_id),
                    int(tool_run_id),
                    str(item["observation_fingerprint"]),
                    tool_name,
                    item.get("endpoint"),
                    encrypted,
                    now,
                    now,
                )
            )
        with self.database._connect() as conn:
            conn.executemany(
                """
                INSERT INTO scan_asset_observations(
                    scan_id, tool_run_id, observation_fingerprint, tool, endpoint,
                    payload, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, tool_run_id, observation_fingerprint) DO UPDATE SET
                    endpoint = excluded.endpoint,
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                rows,
            )
        return normalized

    def list_scan(self, scan_id: int) -> list[dict[str, Any]]:
        with self.database._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload FROM scan_asset_observations
                WHERE scan_id = ?
                ORDER BY tool, observation_fingerprint, tool_run_id
                """,
                (int(scan_id),),
            ).fetchall()
        return [
            json.loads(
                self.database._dec(str(row["payload"]), field="scan_asset_observation.payload")
            )
            for row in rows
        ]


class SchedulerRuntimeRegistry:
    """Own every background scan thread and its one asyncio loop."""

    @dataclass(slots=True)
    class Handle:
        cancel_event: threading.Event
        thread: threading.Thread

    def __init__(self) -> None:
        self._handles: dict[int, SchedulerRuntimeRegistry.Handle] = {}
        self._lock = threading.Lock()

    def start(self, scan_id: int, coroutine_factory: Callable[[threading.Event], Awaitable[None]]) -> None:
        cancel_event = threading.Event()
        handle_box: dict[str, SchedulerRuntimeRegistry.Handle] = {}

        def run_registered() -> None:
            try:
                with asyncio.Runner() as runner:
                    runner.run(coroutine_factory(cancel_event))
            finally:
                with self._lock:
                    current = self._handles.get(scan_id)
                    if current is handle_box.get("handle"):
                        self._handles.pop(scan_id, None)

        thread = threading.Thread(target=run_registered, daemon=True, name=f"windeep-scheduler-scan-{scan_id}")
        handle = self.Handle(cancel_event=cancel_event, thread=thread)
        handle_box["handle"] = handle
        with self._lock:
            if scan_id in self._handles:
                raise RuntimeError(f"scan {scan_id} is already registered")
            self._handles[scan_id] = handle
        thread.start()

    def stop(self, scan_id: int) -> bool:
        with self._lock:
            handle = self._handles.get(scan_id)
        if handle is None:
            return False
        handle.cancel_event.set()
        return True

    def is_active(self, scan_id: int) -> bool:
        with self._lock:
            handle = self._handles.get(scan_id)
        return bool(handle and handle.thread.is_alive())


class DependencyBlocked(RuntimeError):
    pass


def _successful_dependencies(dependencies: Mapping[str, Any]) -> dict[str, Any]:
    failures = {key: value for key, value in dependencies.items() if isinstance(value, BaseException)}
    if failures:
        detail = ", ".join(f"{key}: {value}" for key, value in sorted(failures.items()))
        raise DependencyBlocked(detail)
    return dict(dependencies)


def _host_rate_key(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"https://{target}")
    return f"host:{(parsed.hostname or target).casefold()}"


async def execute_scheduler_with_cancel(
    scheduler: TaskScheduler,
    task_specs: Sequence[TaskSpec],
    context: Any,
    *,
    scan_id: str,
    cancel_event: threading.Event,
    poll_interval: float = 0.10,
) -> dict[str, Any]:
    """Bind the thread-safe operator stop flag to the asyncio scheduler task."""
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    scheduler_task = asyncio.create_task(
        scheduler.execute(task_specs, context, scan_id=scan_id),
        name=f"windeep:{scan_id}:scheduler",
    )

    async def watch_cancel() -> None:
        while not scheduler_task.done():
            if cancel_event.is_set():
                scheduler_task.cancel()
                return
            await asyncio.sleep(poll_interval)

    watcher = asyncio.create_task(
        watch_cancel(),
        name=f"windeep:{scan_id}:cancel-watcher",
    )
    try:
        return await scheduler_task
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)


async def run_p0_scan(
    *,
    scan_id: int,
    target_row: Mapping[str, Any],
    selected: Sequence[str],
    skipped: Sequence[Mapping[str, Any]],
    mode: str,
    consent_id: str,
    tool_options: Mapping[str, Any],
    cancel_event: threading.Event,
    database: Any,
    crypto: Any,
    audit: Any,
    wrapper_classes: Mapping[str, Any],
    tools_dir: Any,
    target_scope: Callable[[dict[str, Any]], Any],
    preflight_for: Callable[..., Any],
    broadcast: Callable[[str, dict[str, Any], int | None], None],
    environment: Mapping[str, str],
    program_policy: Mapping[str, Any] | None = None,
    program_metadata: Mapping[str, Any] | None = None,
) -> None:
    """Execute one v2 scan on one scheduler-owned event loop."""
    target = str(target_row["target"])
    target_id = int(target_row["id"])
    guard = preflight_for(dict(target_row), consent_id)
    context = ScanContext(
        target=target,
        target_id=target_id,
        scope=list(target_row.get("scope") or [target]),
        out_of_scope=list(target_row.get("out_of_scope") or []),
        consent_id=consent_id,
        metadata=dict(program_metadata or {}),
        program_policy=dict(program_policy or {}),
    )
    event_bus = EventBus(heartbeat_interval=60.0)
    event_log = ScanEventLog(database, crypto)
    writer = FindingBatchWriter(database)
    observations = AssetObservationStore(database)
    raw_store = RawArtifactStore(database, crypto, audit)
    event_log.ensure_schema()
    writer.ensure_schema()
    observations.ensure_schema()

    def emit(event_type: str, data: Mapping[str, Any]) -> dict[str, Any]:
        event = event_log.append(scan_id, event_type, data)
        broadcast(event_type, dict(event["data"]), scan_id)
        return event

    progress_bridge_drained = asyncio.Event()
    tool_bridge_drained = asyncio.Event()

    async def bridge_scheduler_events(topic: str) -> None:
        """Persist scheduler activity so UI progress cannot disappear inside EventBus."""
        async for scheduler_event in event_bus.subscribe(topic):
            payload = dict(scheduler_event.payload)
            payload.pop("scan_id", None)
            if scheduler_event.topic == "scan.progress" and payload.get("phase") == "_bridge_flush":
                progress_bridge_drained.set()
                continue
            if scheduler_event.topic == "tool.bridge_flush":
                tool_bridge_drained.set()
                continue
            if scheduler_event.topic == "scan.progress":
                try:
                    progress = float(payload.get("progress", 0.0))
                except (TypeError, ValueError, OverflowError):
                    progress = 0.0
                progress = max(0.0, min(99.0, progress))
                running_tasks = payload.get("running_tasks")
                if not isinstance(running_tasks, list):
                    running_tasks = []
                runtime_summary = {
                    "task": payload.get("task"),
                    "phase": str(payload.get("phase") or "activity"),
                    "completed_tasks": int(payload.get("completed_tasks") or 0),
                    "failed_tasks": int(payload.get("failed_tasks") or 0),
                    "cancelled_tasks": int(payload.get("cancelled_tasks") or 0),
                    "total_tasks": int(payload.get("total_tasks") or 0),
                    "running_tasks": running_tasks[:16],
                    "last_event_at": time.time(),
                }
                database.update_scan(
                    scan_id,
                    status="running",
                    progress=progress,
                    results_summary={"runtime": runtime_summary},
                )
                emit(
                    "progress",
                    {
                        **payload,
                        "progress": progress,
                        "status": "running",
                        "source": "scheduler",
                    },
                )
                continue
            if scheduler_event.topic.startswith("tool."):
                phase = scheduler_event.topic.split(".", 1)[1]
                module = str(payload.get("tool") or payload.get("task") or "scheduler")
                detail = str(payload.get("error") or "").strip()
                message = f"{module} {phase}"
                if detail and phase == "failed":
                    message = f"{message}: {detail[:500]}"
                emit(
                    "log",
                    {
                        "level": "error" if phase == "failed" else "info",
                        "module": module,
                        "message": message,
                        "task": payload.get("task"),
                        "phase": phase,
                    },
                )

    database.update_scan(scan_id, status="running", started_at=time.time(), progress=0.0)
    emit("log", {"level": "info", "module": "v2-orchestrator", "message": f"{mode} DAG scan starting with {len(selected)} integration(s)."})

    def runner_factory(tool_name: str) -> Runner:
        cls = wrapper_classes[tool_name]
        timeout = max(1.0, float(getattr(cls, "timeout", 120.0)))
        retry_policy = RetryPolicy(max_attempts=min(8, max(0, int(getattr(cls, "retries", 0))) + 1))

        async def run_tool(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> list[dict[str, Any]]:
            _successful_dependencies(dependencies)
            if cancel_event.is_set():
                raise asyncio.CancelledError
            guard.authorize_scan(target=target, consent_id=consent_id)
            await guard.acquire_rate(_host_rate_key(target))
            scope = target_scope(dict(target_row))
            wrapper = cls(
                tools_dir=tools_dir,
                scope_validator=scope.is_allowed,
                environment=dict(environment),
                cancel_check=cancel_event.is_set,
            )
            run_id = database.create_tool_run(
                tool_name=tool_name,
                status="running",
                scan_id=scan_id,
                target_id=target_id,
                command=[tool_name, "<scope-bound target>"],
            )
            options = tool_options.get(tool_name) if isinstance(tool_options.get(tool_name), Mapping) else None
            last_error: BaseException | None = None
            for attempt in range(1, retry_policy.max_attempts + 1):
                if cancel_event.is_set():
                    database.finish_tool_run(run_id, status="cancelled", error="cancelled by operator")
                    raise asyncio.CancelledError
                try:
                    guard.authorize_scan(target=target, consent_id=consent_id)
                    await guard.acquire_rate(_host_rate_key(target))
                    execution = await asyncio.wait_for(wrapper.run_with_evidence(target, options=options), timeout=timeout)
                    evidence_record = raw_store.record_execution_result(
                        scan_id=scan_id,
                        tool_run_id=run_id,
                        result=execution,
                        tool_name=tool_name,
                        command_template=(tool_name, *execution.argument_template),
                        working_directory=str(tools_dir),
                    )
                    payloads = [finding.model_dump() for finding in execution.findings]
                    for payload in payloads:
                        evidence = dict(payload.get("evidence") or {})
                        evidence["_windeep_execution"] = {
                            "tool_run_id": run_id,
                            "backend": execution.backend,
                            "backend_tier": execution.backend_tier,
                            "parser": execution.parser_name,
                            "stdout_sha256": evidence_record["stdout_sha256"],
                            "stderr_sha256": evidence_record["stderr_sha256"],
                        }
                        payload["evidence"] = evidence
                    result_role = str(getattr(cls, "result_role", "finding"))
                    if result_role == "observation":
                        observed = observations.persist(
                            scan_id=scan_id,
                            tool_run_id=run_id,
                            tool_name=tool_name,
                            observations=payloads,
                        )
                        persisted: list[dict[str, Any]] = []
                    else:
                        observed = []
                        persisted = writer.persist(
                            scan_id=scan_id,
                            tool_run_id=run_id,
                            target_id=target_id,
                            tool_name=tool_name,
                            findings=payloads,
                        )
                    database.finish_tool_run(
                        run_id,
                        status="completed",
                        exit_code=execution.exit_code,
                        stdout_tail=(
                            f"{len(persisted)} finding(s), {len(observed)} observation(s); "
                            f"raw={evidence_record['stdout_sha256'][:12]}"
                        ),
                        stderr_tail=f"encrypted-raw={evidence_record['stderr_sha256'][:12]}",
                    )
                    for item in persisted:
                        public = {key: value for key, value in item.items() if key != "stable_json"}
                        emit("finding", {"finding": public})
                    emit(
                        "evidence",
                        {
                            "tool": tool_name,
                            "tool_run_id": run_id,
                            "result_role": result_role,
                            "finding_count": len(persisted),
                            "observation_count": len(observed),
                            "fingerprints": [item["fingerprint"] for item in persisted],
                            "observation_fingerprints": [
                                item["observation_fingerprint"] for item in observed
                            ],
                            "stdout_sha256": evidence_record["stdout_sha256"],
                            "stderr_sha256": evidence_record["stderr_sha256"],
                            "backend": execution.backend,
                            "backend_tier": execution.backend_tier,
                            "parser": execution.parser_name,
                        },
                    )
                    return persisted
                except (PreFlightError, PermissionError) as exc:
                    database.finish_tool_run(run_id, status="failed", error=str(exc))
                    raise
                except ToolCancelledError:
                    database.finish_tool_run(run_id, status="cancelled", error="cancelled by operator")
                    raise asyncio.CancelledError
                except asyncio.CancelledError:
                    database.finish_tool_run(run_id, status="cancelled", error="cancelled by operator")
                    raise
                except ToolExecutionError as exc:
                    if exc.result is not None:
                        raw_store.record_execution_result(
                            scan_id=scan_id,
                            tool_run_id=run_id,
                            result=exc.result,
                            tool_name=tool_name,
                            command_template=(tool_name, *exc.result.argument_template),
                            working_directory=str(tools_dir),
                        )
                    last_error = exc
                    if attempt >= retry_policy.max_attempts:
                        database.finish_tool_run(run_id, status="failed", error=str(exc))
                        raise
                    await asyncio.sleep(retry_policy.delay(attempt))
                except Exception as exc:
                    last_error = exc
                    if attempt >= retry_policy.max_attempts:
                        database.finish_tool_run(run_id, status="failed", error=str(exc))
                        raise
                    await asyncio.sleep(retry_policy.delay(attempt))
            if last_error is not None:
                raise last_error
            return []

        return run_tool

    tool_nodes = build_tool_nodes(selected, wrapper_classes, runner_factory=runner_factory)
    tool_ids = tuple(node.id for node in tool_nodes)

    async def dedup_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        guard.authorize_scan(target=target, consent_id=consent_id)
        records = writer.read_scan_findings(scan_id)
        records.sort(key=lambda item: (str(item.get("fingerprint") or ""), int(item.get("finding_id") or 0)))
        detector = DuplicateDetector(database)
        primary: dict[str, dict[str, Any]] = {}
        duplicate_groups: list[dict[str, Any]] = []
        for item in records:
            fingerprint = str(item["fingerprint"])
            if fingerprint not in primary:
                primary[fingerprint] = item
                continue
            first = primary[fingerprint]
            duplicate_groups.append(
                {
                    "fingerprint": fingerprint,
                    "primary_finding_id": int(first["finding_id"]),
                    "duplicate_finding_id": int(item["finding_id"]),
                    "similarity": detector.similarity(first, item),
                }
            )
        findings = [primary[key] for key in sorted(primary)]
        return {"findings": findings, "duplicates": sorted(duplicate_groups, key=lambda row: (row["fingerprint"], row["duplicate_finding_id"]))}

    async def chain_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        values = _successful_dependencies(dependencies)
        guard.authorize_scan(target=target, consent_id=consent_id)
        dedup = values["stage:dedup"]
        findings = dedup["findings"]
        builder = ChainBuilder(build_llm_client(), event_bus, database=database)
        edges = await builder.build(findings, target_id=target_id, scan_id=scan_id)
        edge_rows = sorted((edge.model_dump() for edge in edges), key=lambda row: (row["source_finding_id"], row["target_finding_id"], row["edge_type"]))
        for edge in edge_rows:
            emit("chain", {"edge": edge})
        return {"findings": findings, "duplicates": dedup["duplicates"], "chains": edge_rows}

    async def rank_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        values = _successful_dependencies(dependencies)
        guard.authorize_scan(target=target, consent_id=consent_id)
        chained = values["stage:chain"]
        ranked = FindingRanker().rank(chained["findings"])
        rows = [
            {
                "finding_id": int(item.finding.get("finding_id") or item.finding.get("id") or 0),
                "fingerprint": str(item.finding.get("fingerprint") or ""),
                "impact": item.impact,
                "exploitability": item.exploitability,
                "confidence": item.confidence,
                "score": item.score,
            }
            for item in ranked
        ]
        rows.sort(key=lambda row: (-row["score"], row["fingerprint"], row["finding_id"]))
        for row in rows:
            emit("ranked", row)
        return {**chained, "ranked": rows}

    async def hypothesis_stage(scan_context: ScanContext, dependencies: Mapping[str, Any]) -> dict[str, Any]:
        if cancel_event.is_set():
            raise asyncio.CancelledError
        values = _successful_dependencies(dependencies)
        guard.authorize_scan(target=target, consent_id=consent_id)
        ranked = values["stage:rank"]
        engine = HypothesisEngine(build_llm_client(), event_bus, database=database)
        hypotheses = await engine.generate(ranked["findings"], scan_context, target_id=target_id, scan_id=scan_id)
        hypothesis_rows = sorted((item.model_dump() for item in hypotheses), key=lambda row: row["id"])
        return {**ranked, "hypotheses": hypothesis_rows}

    stage_nodes = [
        PipelineNode("stage:dedup", "stage", dedup_stage, depends_on=tool_ids, resource_class="active", timeout=60.0, cancellable=True, tool_name="stage:dedup", execution_kind="local_analysis"),
        PipelineNode("stage:chain", "stage", chain_stage, depends_on=("stage:dedup",), resource_class="llm", timeout=60.0, cancellable=True, tool_name="stage:chain", execution_kind="local_analysis"),
        PipelineNode("stage:rank", "stage", rank_stage, depends_on=("stage:chain",), resource_class="active", timeout=30.0, cancellable=True, tool_name="stage:rank", execution_kind="local_analysis"),
        PipelineNode("stage:hypothesis", "stage", hypothesis_stage, depends_on=("stage:rank",), resource_class="llm", timeout=60.0, cancellable=True, tool_name="stage:hypothesis", execution_kind="local_analysis"),
    ]

    scheduler = TaskScheduler(
        event_bus,
        preflight=guard,
        global_concurrency=max(1, min(8, len(tool_nodes) or 1)),
        per_tool_concurrency={"*": 1},
    )
    bridge_tasks = [
        asyncio.create_task(bridge_scheduler_events("scan.progress"), name=f"windeep:{scan_id}:bridge-progress"),
        asyncio.create_task(bridge_scheduler_events("tool.*"), name=f"windeep:{scan_id}:bridge-tools"),
    ]
    # Give subscriptions one event-loop turn to register before the scheduler emits.
    await asyncio.sleep(0)
    try:
        try:
            results = await execute_scheduler_with_cancel(
                scheduler,
                [node.to_task_spec() for node in [*tool_nodes, *stage_nodes]],
                context,
                scan_id=str(scan_id),
                cancel_event=cancel_event,
            )
        finally:
            # FIFO flush markers ensure fast scans cannot leave queued progress/tool
            # events behind when the scheduler returns in the same loop turn.
            await event_bus.publish(
                "scan.progress",
                {"scan_id": str(scan_id), "phase": "_bridge_flush"},
            )
            await event_bus.publish(
                "tool.bridge_flush",
                {"scan_id": str(scan_id)},
            )
            try:
                await asyncio.wait_for(
                    asyncio.gather(progress_bridge_drained.wait(), tool_bridge_drained.wait()),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                emit(
                    "log",
                    {
                        "level": "warning",
                        "module": "v2-orchestrator",
                        "message": "Scheduler event bridge drain timed out; final scan state will continue from durable database state.",
                    },
                )
            finally:
                for bridge_task in bridge_tasks:
                    bridge_task.cancel()
                await asyncio.gather(*bridge_tasks, return_exceptions=True)
        errors = [
            {"task": task_id, "error": state.error or "task failed"}
            for task_id, state in sorted(scheduler.states.items())
            if state.status == "failed"
        ]
        final_stage = results.get("stage:hypothesis")
        final_payload = final_stage if isinstance(final_stage, Mapping) else {}
        finding_count = len(final_payload.get("findings", [])) if isinstance(final_payload, Mapping) else 0
        chain_count = len(final_payload.get("chains", [])) if isinstance(final_payload, Mapping) else 0
        ranked_count = len(final_payload.get("ranked", [])) if isinstance(final_payload, Mapping) else 0
        asset_observations = observations.list_scan(scan_id)
        observation_tools: dict[str, int] = {}
        historical_observations = 0
        for item in asset_observations:
            tool = str(item.get("tool") or "unknown")
            observation_tools[tool] = observation_tools.get(tool, 0) + 1
            if item.get("temporal_scope") == "historical":
                historical_observations += 1
        assembled = EvidenceAssembler(database, crypto, audit).assemble_scan(scan_id)
        evidence_closed = sum(1 for item in assembled if item.get("state") == "closed")
        evidence_incomplete = sum(1 for item in assembled if item.get("state") == "incomplete")
        evidence_blocked = [item for item in assembled if item.get("state") == "blocked"]

        verification_pass = VerificationPass(database, raw_store)
        bundle_store = EvidenceBundleStore(database, crypto, audit)
        verification_rows: list[dict[str, Any]] = []
        for item in assembled:
            if item.get("state") != "closed":
                continue
            finding_id = int(item["finding_id"])
            try:
                bundle = bundle_store.resolve(finding_id, scan_id=scan_id)
                record = verification_pass.verify_finding(
                    finding_id=finding_id,
                    scan_id=scan_id,
                    bundle=bundle,
                )
                claims = list(record.get("claims") or [])
                verification_rows.append(
                    {
                        "finding_id": finding_id,
                        "state": "verified_recorded",
                        "claims": {
                            str(claim.get("claim")): str(claim.get("state"))
                            for claim in claims
                            if isinstance(claim, Mapping)
                        },
                        "record_sha256": str(record.get("record_sha256") or ""),
                    }
                )
            except (VerificationError, KeyError, ValueError) as exc:
                verification_rows.append(
                    {
                        "finding_id": finding_id,
                        "state": "needs_review",
                        "reason": str(exc),
                    }
                )
        errors.extend(
            {
                "task": f"evidence:{item.get('finding_id')}",
                "error": str(item.get("reason") or "evidence assembly blocked"),
            }
            for item in evidence_blocked
        )
        status = "completed_with_errors" if errors else "completed"
        evidence_root = raw_store.seal_scan(
            scan_id,
            reason=f"seal terminal v2 scan evidence ({status})",
            actor="v2-orchestrator",
        )
        summary = {
            "mode": mode,
            "tools_planned": len(selected),
            "findings": finding_count,
            "chains": chain_count,
            "ranked": ranked_count,
            "asset_observations": {
                "count": len(asset_observations),
                "historical": historical_observations,
                "current_or_unspecified": len(asset_observations) - historical_observations,
                "by_tool": dict(sorted(observation_tools.items())),
                "submission_candidates": 0,
            },
            "verification": {
                "records": verification_rows,
                "verified_recorded": sum(1 for item in verification_rows if item["state"] == "verified_recorded"),
                "needs_review": sum(1 for item in verification_rows if item["state"] == "needs_review"),
            },
            "errors": errors,
            "skipped": list(skipped),
            "evidence": {
                "observations": len(assembled),
                "closed": evidence_closed,
                "incomplete": evidence_incomplete,
                "blocked": len(evidence_blocked),
                "results": assembled,
            },
            "evidence_root": {
                "merkle_root": evidence_root["merkle_root"],
                "leaf_count": evidence_root["leaf_count"],
                "audit_hash": evidence_root["audit_hash"],
            },
        }
        emit(
            "evidence",
            {
                "scan_id": scan_id,
                "sealed": True,
                "closed": evidence_closed,
                "incomplete": evidence_incomplete,
                "blocked": len(evidence_blocked),
                **summary["evidence_root"],
            },
        )
        database.update_scan(scan_id, status=status, progress=100.0, finished_at=time.time(), results_summary=summary)
        emit("progress", {"progress": 100.0, "status": status, "summary": summary})
        audit.append("v2.scan.completed", {"scan_id": scan_id, "status": status, "errors": len(errors), "evidence_root": evidence_root["merkle_root"]})
    except asyncio.CancelledError:
        reason = "operator cancellation requested" if cancel_event.is_set() else "scheduler cancellation"
        database.update_scan(scan_id, status="cancelled", finished_at=time.time(), results_summary={"cancel_reason": reason})
        emit("progress", {"status": "cancelled", "reason": reason})
        audit.append("v2.scan.cancelled", {"scan_id": scan_id, "reason": reason})
    except Exception as exc:
        database.add_scan_log(scan_id, str(exc), "error", "v2-orchestrator")
        database.update_scan(scan_id, status="failed", finished_at=time.time(), results_summary={"errors": [{"task": "v2-orchestrator", "error": str(exc)}]})
        emit("progress", {"status": "failed", "error": str(exc)})
        audit.append("v2.scan.failed", {"scan_id": scan_id, "error": str(exc)})
    finally:
        await event_bus.close()
