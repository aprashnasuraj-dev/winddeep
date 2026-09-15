"""P0 acceptance tests for the v2 DAG pipeline."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.brain.chain_builder import ChainBuilder
from app.brain.llm_client import LLMClient
from app.engine.event_bus import EventBus
from app.engine.scheduler import TaskScheduler
from app.v2_pipeline import (
    FindingBatchWriter,
    PipelineNode,
    RetryPolicy,
    ScanEventLog,
    build_tool_nodes,
    canonical_bytes,
)


class SpyPreflight:
    def __init__(self, *, deny: bool = False) -> None:
        self.deny = deny
        self.authorized: list[tuple[str, str]] = []
        self.rates: list[str] = []

    def authorize_scan(self, *, target: str, consent_id: str) -> object:
        self.authorized.append((target, consent_id))
        if self.deny:
            raise PermissionError("denied")
        return object()

    async def acquire_rate(self, key: str, *, cost: float = 1.0) -> None:
        self.rates.append(key)
        await asyncio.sleep(0)


def test_pipeline_node_declares_p0_contract() -> None:
    async def noop(context: object, dependencies: dict[str, object]) -> None:
        return None

    node = PipelineNode(
        id="tool:one",
        kind="tool",
        runner=noop,
        depends_on=("recon:a",),
        resource_class="active",
        timeout=12.0,
        retry_policy=RetryPolicy(max_attempts=2, base_delay=0.01, max_delay=0.02, jitter=0.1),
        cancellable=True,
        tool_name="one",
    )
    assert node.id == "tool:one"
    assert node.depends_on == ("recon:a",)
    assert node.resource_class == "active"
    assert node.timeout == 12.0
    assert node.retry_policy.max_attempts == 2
    assert node.cancellable is True


def test_active_and_web_nodes_depend_on_passive_recon() -> None:
    classes = {
        "passive_a": SimpleNamespace(category="recon_passive", timeout=10.0, retries=0),
        "passive_b": SimpleNamespace(category="recon_passive", timeout=10.0, retries=0),
        "active": SimpleNamespace(category="recon_active", timeout=10.0, retries=0),
        "web": SimpleNamespace(category="web_vulns", timeout=10.0, retries=0),
        "web3": SimpleNamespace(category="web3", timeout=10.0, retries=0),
    }

    async def noop(context: object, dependencies: dict[str, object]) -> None:
        return None

    nodes = build_tool_nodes(list(classes), classes, runner_factory=lambda _name: noop)
    by_tool = {node.tool_name: node for node in nodes}
    passive_ids = tuple(sorted((by_tool["passive_a"].id, by_tool["passive_b"].id)))
    assert tuple(sorted(by_tool["active"].depends_on)) == passive_ids
    assert tuple(sorted(by_tool["web"].depends_on)) == passive_ids
    assert by_tool["web3"].depends_on == ()


@pytest.mark.asyncio
async def test_independent_tools_overlap_without_exceeding_caps() -> None:
    bus = EventBus(heartbeat_interval=60)
    guard = SpyPreflight()
    active = 0
    peak = 0
    lock = asyncio.Lock()

    async def runner(context: object, deps: dict[str, object]) -> str:
        nonlocal active, peak
        async with lock:
            active += 1
            peak = max(peak, active)
        await asyncio.sleep(0.04)
        async with lock:
            active -= 1
        return "ok"

    nodes = [
        PipelineNode("a", "tool", runner, resource_class="recon", tool_name="a"),
        PipelineNode("b", "tool", runner, resource_class="recon", tool_name="b"),
    ]
    scheduler = TaskScheduler(bus, preflight=guard, global_concurrency=2, per_tool_concurrency={"*": 1})
    await scheduler.execute([node.to_task_spec() for node in nodes], SimpleNamespace(target="example.test", consent_id="c1"), scan_id="1")
    assert peak == 2
    await bus.close()


@pytest.mark.asyncio
async def test_preflight_denial_never_reaches_runner() -> None:
    bus = EventBus(heartbeat_interval=60)
    called = False

    async def runner(context: object, deps: dict[str, object]) -> None:
        nonlocal called
        called = True

    scheduler = TaskScheduler(bus, preflight=SpyPreflight(deny=True))
    with pytest.raises(PermissionError):
        await scheduler.execute(
            [PipelineNode("blocked", "tool", runner, tool_name="blocked").to_task_spec()],
            SimpleNamespace(target="example.test", consent_id="c1"),
            scan_id="2",
        )
    assert called is False
    await bus.close()


def test_canonical_stage_output_is_byte_stable() -> None:
    left = {"b": [3, 2, 1], "a": {"z": 2, "x": 1}}
    right = {"a": {"x": 1, "z": 2}, "b": [3, 2, 1]}
    assert canonical_bytes(left) == canonical_bytes(right)


def _secure_fixture(tmp_path):
    from app.security.crypto import CryptoManager
    from app.security.secure_database import SecureDatabase

    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    target_id = database.create_target("fixture", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["fixture"])
    return crypto, database, target_id, scan_id


def test_scan_event_log_replays_gap_free_and_redacts_exports(tmp_path) -> None:
    crypto, database, _target_id, scan_id = _secure_fixture(tmp_path)
    log = ScanEventLog(database, crypto)
    log.ensure_schema()
    first = log.append(scan_id, "log", {"message": "one"})
    second = log.append(scan_id, "progress", {"progress": 50})
    third = log.append(
        scan_id,
        "ranked",
        {"finding_id": 9, "score": 88.0, "Authorization": "Bearer super-secret-token", "nested": {"api_key": "known-secret"}},
    )
    assert [first["seq"], second["seq"], third["seq"]] == [1, 2, 3]
    replay = log.list_after(scan_id, 1)
    assert [event["seq"] for event in replay] == [2, 3]
    assert [event["type"] for event in replay] == ["progress", "ranked"]
    assert all(event["schema"] == "windeep.sse.v1" for event in replay)
    exported = canonical_bytes(replay).decode("utf-8")
    assert "super-secret-token" not in exported
    assert "known-secret" not in exported
    assert exported.count("[REDACTED]") >= 2


def test_batch_writer_is_idempotent_per_scan_tool_run(tmp_path) -> None:
    _crypto, database, target_id, scan_id = _secure_fixture(tmp_path)
    run_id = database.create_tool_run(tool_name="fixture", status="running", scan_id=scan_id, target_id=target_id, command=["fixture", "<scope-bound target>"])
    writer = FindingBatchWriter(database)
    writer.ensure_schema()
    finding = {
        "title": "Same finding",
        "severity": "high",
        "vuln_type": "fixture",
        "endpoint": "https://example.test/a",
        "description": "evidence-backed fixture",
        "evidence": {"source": "fixture"},
        "confidence": 0.9,
    }
    first = writer.persist(scan_id=scan_id, tool_run_id=run_id, target_id=target_id, tool_name="fixture", findings=[finding])
    second = writer.persist(scan_id=scan_id, tool_run_id=run_id, target_id=target_id, tool_name="fixture", findings=[finding])
    assert first[0]["fingerprint"] == second[0]["fingerprint"]
    with database._connect() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM scan_findings WHERE scan_id = ? AND tool_run_id = ?", (scan_id, run_id)).fetchone()["n"]
    assert count == 1
    assert json.loads(second[0]["stable_json"])["title"] == "Same finding"


@pytest.mark.asyncio
async def test_chain_builder_accepts_scan_finding_id_and_is_deterministic() -> None:
    findings = [
        {
            "finding_id": 10,
            "title": "Sensitive information disclosure",
            "severity": "medium",
            "vuln_type": "information disclosure",
            "description": "Identifiers observed in a read-only response.",
        },
        {
            "finding_id": 20,
            "title": "Object authorization inconsistency",
            "severity": "high",
            "vuln_type": "idor",
            "description": "Authorization behavior differs for an object read.",
        },
    ]
    bus = EventBus(heartbeat_interval=60)
    builder = ChainBuilder(LLMClient([]), bus)
    first = await builder.build(findings)
    second = await builder.build(findings)
    assert [edge.model_dump() for edge in first] == [edge.model_dump() for edge in second]
    assert [(edge.source_finding_id, edge.target_finding_id, edge.edge_type) for edge in first] == [(10, 20, "enables")]
    await bus.close()
