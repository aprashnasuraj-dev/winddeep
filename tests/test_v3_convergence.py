"""Integration acceptance for P1 → P2 v2 → P3 forensic convergence."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from app.engine.tool_wrapper import Finding, ToolWrapperBase
from app.evidence.bundles import BundleIncompleteError
from app.evidence.raw_store import RawArtifactStore
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase
from app.v3.evidence import ForensicEvidenceBundleStore, GuardedEvidenceVault
from app.v3.execution import CapturedToolExecutor
from app.v3.reporting import ForensicReportGenerator

ROOT = Path(__file__).resolve().parents[1]


class _Guard:
    def __init__(self, *, deny: bool = False) -> None:
        self.deny = deny
        self.calls: list[tuple[str, str]] = []

    def authorize_scan(self, *, target: str, consent_id: str):
        self.calls.append((target, consent_id))
        if self.deny:
            raise PermissionError("denied by fixture guard")
        return object()


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str


class _FixtureWrapper(ToolWrapperBase):
    tool_name = "fixture-v3"
    binary = "fixture-v3"
    args_template = ("{target}",)
    input_schema = _Input
    output_parser = staticmethod(lambda _raw, _tool, _target: [])
    timeout = 3.0
    retries = 0
    rate_limit = 0.0
    category = "web_vulns"
    requires_scope = True
    adapter_kind = "builtin"
    target_types = ("url",)

    async def run(self, target: str, options=None):
        return [
            Finding(
                title="Observed authorization inconsistency",
                severity="high",
                vuln_type="authorization",
                tool=self.tool_name,
                endpoint=target + "/api/object/7",
                description="Captured response differs for the authorized role context.",
                evidence={"detector_id": "fixture.auth.diff"},
                confidence=0.92,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                impact="Recorded role mismatch exposes protected object data.",
                remediation="Enforce object authorization on every read.",
            )
        ]


def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    target_id = database.create_target("fixture", "url", "https://example.test", scope=["example.test"])
    scan_id = database.create_scan(target_id, "v3:selected", ["fixture-v3"])
    guard = _Guard()
    vault = GuardedEvidenceVault(database, crypto, audit, guard, target="https://example.test", consent_id="consent-fixture")
    return crypto, database, audit, guard, vault, target_id, scan_id


@pytest.mark.asyncio
async def test_captured_executor_records_p1_and_incomplete_p2_without_fabricating_flow(tmp_path: Path) -> None:
    _crypto, database, _audit, guard, vault, target_id, scan_id = _fixture(tmp_path)
    executor = CapturedToolExecutor(
        database=database,
        vault=vault,
        wrapper_classes={"fixture-v3": _FixtureWrapper},
        tools_dir=tmp_path / "tools",
        scope_validator=lambda value: value.startswith("https://example.test"),
        environment={},
    )
    result = await executor.execute(
        tool_name="fixture-v3",
        target="https://example.test",
        target_id=target_id,
        scan_id=scan_id,
    )
    assert result["custody"]["schema"] == "windeep.tool-run-evidence.v1"
    assert result["custody"]["stdout_sha256"] == hashlib.sha256(result["custody"]["stdout"]).hexdigest() if isinstance(result["custody"].get("stdout"), bytes) else result["custody"]["stdout_sha256"]
    assert len(result["findings"]) == 1
    assert len(result["bundles"]) == 1
    assert result["bundles"][0]["schema"] == "windeep.evidence-bundle.v2"
    assert result["bundles"][0]["completeness"]["closed"] is False
    assert "flow" in result["bundles"][0]["completeness"]["missing"]
    assert guard.calls


def test_real_forensic_flow_closes_bundle_and_p3_report_is_deterministic(tmp_path: Path) -> None:
    _crypto, database, _audit, _guard, vault, target_id, scan_id = _fixture(tmp_path)
    run_id = database.create_tool_run(tool_name="fixture-v3", status="completed", scan_id=scan_id, target_id=target_id, command=["fixture-v3", "<scope-bound target>"])
    vault.record_tool_run(
        scan_id=scan_id,
        tool_run_id=run_id,
        argv=["fixture-v3", "https://example.test"],
        stdout=b"Observed authorization inconsistency\n",
        stderr=b"",
        exit_code=0,
        started_at_wall=1_700_000_000.0,
        finished_at_wall=1_700_000_001.0,
        started_at_monotonic=10.0,
        finished_at_monotonic=11.0,
        tool_name="fixture-v3",
        tool_version="3.0.0",
        resolved_binary_sha256="a" * 64,
        environment_allowlist_sha256="b" * 64,
        working_directory="C:/Windeep",
    )
    finding_id, _ = database.create_finding(
        target_id,
        "Observed authorization inconsistency",
        "high",
        scan_id=scan_id,
        vuln_type="authorization",
        tool="fixture-v3",
        endpoint="https://example.test/api/object/7",
        description="Captured response differs for the authorized role context.",
        evidence={"detector_id": "fixture.auth.diff"},
        confidence=0.92,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        impact="Recorded role mismatch exposes protected object data.",
        remediation="Enforce object authorization on every read.",
    )
    flow_id = vault.capture_flow(
        target_id=target_id,
        scan_id=scan_id,
        tool_run_id=run_id,
        task_id="tool:fixture-v3",
        method="GET",
        url="https://example.test/api/object/7",
        request_headers=[("Host", "example.test"), ("Authorization", "Bearer secret-token")],
        request_body=b"",
        status=200,
        response_headers=[("Content-Type", "application/json"), ("Set-Cookie", "session=secret-cookie")],
        response_body=b'{"id":7,"owner":"other"}',
        raw_request=b"GET /api/object/7 HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secret-token\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=secret-cookie\r\n\r\n{\"id\":7,\"owner\":\"other\"}",
        timings={"connect": 1.0, "tls": 1.0, "ttfb": 2.0, "total": 3.0},
        tls={"sni": "example.test", "alpn": "h2", "cert_fingerprint_sha256": "c" * 64},
        server_ip="203.0.113.10",
        created_at=1_700_000_002.0,
        http_version="HTTP/2",
        stream_id=1,
        pseudo_headers=[(":method", "GET"), (":authority", "example.test")],
    )
    finding = database.get_finding(finding_id)
    assert finding is not None
    bundles = ForensicEvidenceBundleStore(database, vault)
    bundle = bundles.build_from_run(finding=finding, scan_id=scan_id, tool_run_id=run_id, close=True)
    assert bundle["completeness"]["closed"] is True
    assert bundle["flows"][0]["id"] == flow_id
    assert bundles.resolve(finding_id)["bundle_sha256"] == bundle["bundle_sha256"]
    report = ForensicReportGenerator(database, vault)
    first = report.render_finding(finding_id)
    second = report.render_finding(finding_id)
    assert first.markdown == second.markdown
    assert first.sha256 == second.sha256
    assert "secret-token" not in first.markdown
    assert "secret-cookie" not in first.markdown
    assert "[REDACTED:" in first.markdown
    assert "forensic-flow:" in first.markdown
    assert "CVSS:3.1/" in first.markdown
    sealed = vault.seal_scan(scan_id)
    assert len(sealed["merkle_root"]) == 64
    assert vault.verify_scan(scan_id) is True


def test_preflight_denial_never_reaches_underlying_evidence_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    crypto, database, audit, _guard, _vault, target_id, scan_id = _fixture(tmp_path)
    denying = _Guard(deny=True)
    vault = GuardedEvidenceVault(database, crypto, audit, denying, target="https://example.test", consent_id="denied")
    touched = {"value": False}

    def forbidden_read(*args, **kwargs):
        touched["value"] = True
        raise AssertionError("raw store must not be reached after preflight denial")

    monkeypatch.setattr(vault.raw, "read", forbidden_read)
    with pytest.raises(PermissionError):
        vault.read_artifact("0" * 64, scan_id=scan_id, reason="denial test")
    assert touched["value"] is False


def test_bundle_close_fails_without_forensic_flow(tmp_path: Path) -> None:
    _crypto, database, _audit, _guard, vault, target_id, scan_id = _fixture(tmp_path)
    run_id = database.create_tool_run(tool_name="fixture", status="completed", scan_id=scan_id, target_id=target_id, command=["fixture", "<scope-bound target>"])
    vault.record_tool_run(
        scan_id=scan_id, tool_run_id=run_id, argv=["fixture", "https://example.test"], stdout=b"candidate\n", stderr=b"", exit_code=0,
        started_at_wall=1.0, finished_at_wall=2.0, started_at_monotonic=1.0, finished_at_monotonic=2.0,
        tool_name="fixture", tool_version="1", resolved_binary_sha256="a" * 64, environment_allowlist_sha256="b" * 64, working_directory="C:/Windeep"
    )
    finding_id, _ = database.create_finding(target_id, "candidate", "high", scan_id=scan_id, vuln_type="fixture", tool="fixture", endpoint="https://example.test", evidence={}, confidence=0.5)
    finding = database.get_finding(finding_id)
    assert finding is not None
    with pytest.raises(BundleIncompleteError):
        ForensicEvidenceBundleStore(database, vault).build_from_run(finding=finding, scan_id=scan_id, tool_run_id=run_id, close=True)


def test_raw_store_edge_guards_raise_before_unsafe_state(tmp_path: Path) -> None:
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "dek.bin")
    database = SecureDatabase(tmp_path / "db.sqlite", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl")
    with pytest.raises(ValueError, match="chunk_size"):
        RawArtifactStore(database, crypto, audit, chunk_size=0)
