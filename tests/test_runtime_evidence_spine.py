"""Regression coverage for the execution -> raw evidence stabilization spine."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.engine.tool_wrapper import ToolExecutionError, ToolWrapperFactory
from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.server import create_app
from app.tools.backends import ExecutionResolver

ROOT = Path(__file__).resolve().parents[1]


class FakeBackend:
    key = "local_binary"
    tier = "fixture"

    def __init__(self, *, stdout: str = "finding-one\n", stderr: str = "", rc: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc

    def can_run(self, tool: object) -> bool:
        return True

    async def exec(self, tool: object, argv: list[str], stdin: bytes | None, timeout: float):
        del tool, argv, stdin, timeout
        await asyncio.sleep(0)
        return self.stdout, self.stderr, self.rc


def _wrapper(tmp_path: Path, backend: FakeBackend):
    config = tmp_path / "tools.json"
    config.write_text(json.dumps({"tools": {}}), encoding="utf-8")
    factory = ToolWrapperFactory(config)
    cls = factory._create_wrapper(
        "fixture",
        {
            "args": ["--target", "{target}"],
            "parser": "lines",
            "retries": 0,
            "requires_scope": True,
            "runtime_strategy": "auto",
        },
    )
    return cls(
        tools_dir=tmp_path / "tools",
        scope_validator=lambda value: value == "example.test",
        resolver=ExecutionResolver([backend]),
    )


@pytest.mark.asyncio
async def test_wrapper_execution_result_retains_raw_parser_input_without_rendered_target(tmp_path: Path) -> None:
    wrapper = _wrapper(tmp_path, FakeBackend(stdout="finding-one\n", stderr="diagnostic\n"))
    result = await wrapper.run_with_evidence("example.test")

    assert result.stdout == "finding-one\n"
    assert result.stderr == "diagnostic\n"
    assert result.exit_code == 0
    assert result.backend == "local_binary"
    assert result.backend_tier == "fixture"
    assert result.parser_name == "_line_parser"
    assert result.argument_template == ("--target", "{target}")
    assert "example.test" not in repr(result.argument_template)
    assert [finding.title for finding in result.findings] == ["finding-one"]

    compatibility = await wrapper.run("example.test")
    assert [finding.title for finding in compatibility] == ["finding-one"]


@pytest.mark.asyncio
async def test_failed_backend_exposes_raw_execution_result_for_fail_closed_persistence(tmp_path: Path) -> None:
    wrapper = _wrapper(tmp_path, FakeBackend(stdout="partial-output\n", stderr="fixture-error\n", rc=7))
    with pytest.raises(ToolExecutionError) as raised:
        await wrapper.run_with_evidence("example.test")

    result = raised.value.result
    assert result is not None
    assert result.stdout == "partial-output\n"
    assert result.stderr == "fixture-error\n"
    assert result.exit_code == 7
    assert result.backend == "local_binary"
    assert "fixture-error" not in str(raised.value)


def _evidence_fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "state" / "windeep.db", crypto=crypto)
    MigrationManager(
        database.path,
        ROOT / "app" / "data" / "migrations",
        backup_dir=tmp_path / "backups",
        down_migrations_dir=ROOT / "app" / "data" / "migrations_down",
    ).apply()
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    target_id = database.create_target("fixture", "domain", "example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v2:selected", ["fixture"])
    run_id = database.create_tool_run(
        tool_name="fixture",
        status="running",
        scan_id=scan_id,
        target_id=target_id,
        command=["fixture", "<scope-bound target>"],
    )
    return crypto, database, audit, scan_id, run_id


def test_raw_store_binds_execution_result_to_tool_run_without_target_duplication(tmp_path: Path) -> None:
    crypto, database, audit, scan_id, run_id = _evidence_fixture(tmp_path)
    store = RawArtifactStore(database, crypto, audit, chunk_size=32)
    result = SimpleNamespace(
        stdout="raw-finding\n",
        stderr="diagnostic\n",
        exit_code=0,
        backend="fixture",
        backend_tier="fixture",
        attempted_backends=(),
        started_at_wall=100.0,
        finished_at_wall=101.0,
        started_at_monotonic=10.0,
        finished_at_monotonic=11.0,
        stdin_supplied=False,
        parser_name="_line_parser",
        findings=(object(),),
    )
    payload = store.record_execution_result(
        scan_id=scan_id,
        tool_run_id=run_id,
        result=result,
        tool_name="fixture",
        command_template=("fixture", "--target", "{target}"),
        working_directory="/fixture",
    )

    assert payload["schema"] == "windeep.tool-execution-evidence.v2"
    assert payload["stdout_sha256"]
    assert payload["stderr_sha256"]
    assert "example.test" not in json.dumps(payload)
    loaded = store.read_tool_run(run_id)
    assert loaded["stdout"] == b"raw-finding\n"
    assert loaded["stderr"] == b"diagnostic\n"
    assert loaded["command_template"] == ["fixture", "--target", "{target}"]


def test_create_app_applies_evidence_and_v3_schema_before_routes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WINDEEP_STATE_DIR", str(tmp_path / "state"))
    app = create_app()
    database = app.extensions["windeep.database"]
    schema = app.extensions["windeep.schema"]

    assert schema["sql_version"] >= 8
    assert schema["v3_version"] == 30
    with database._connect() as conn:
        tables = {
            str(row["name"])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('scan_authorizations','artifacts','tool_run_evidence','evidence_bundles','v3_pipeline_checkpoint')"
            ).fetchall()
        }
    assert tables == {
        "scan_authorizations",
        "artifacts",
        "tool_run_evidence",
        "evidence_bundles",
        "v3_pipeline_checkpoint",
    }

    # A normal second desktop/server start must not re-apply, fork, or corrupt
    # forward-only evidence schema. This mirrors an installed app restart.
    restarted = create_app()
    assert restarted.extensions["windeep.schema"] == schema
    with restarted.extensions["windeep.database"]._connect() as conn:
        versions = [
            int(row["version"])
            for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        ]
        v3_rows = int(
            conn.execute("SELECT COUNT(*) AS n FROM v3_release_migrations WHERE version = 30").fetchone()["n"]
        )
    assert versions == list(range(1, 9))
    assert v3_rows == 1
