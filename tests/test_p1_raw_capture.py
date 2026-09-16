"""P1 acceptance: forensic raw capture, custody, redaction, HAR, and replay."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.capture.forensic import ForensicFlowStore
from app.evidence.raw_store import EvidenceKeyDestroyedError, RawArtifactStore
from app.evidence.redaction import EvidenceRedactor
from app.migrations import MigrationManager
from app.security.audit import AuditLog
from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path):
    crypto = CryptoManager(wrapped_key_path=tmp_path / "crypto" / "master.bin")
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    MigrationManager(database.path, ROOT / "app" / "data" / "migrations", backup_dir=tmp_path / "backups").apply()
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
    store = RawArtifactStore(database, crypto, audit, chunk_size=32)
    flows = ForensicFlowStore(database, store, audit)
    return crypto, database, audit, store, flows, target_id, scan_id, run_id


def _request_bytes() -> bytes:
    return (
        b"POST /api/items?mode=full HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Authorization: Bearer request-secret\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"X-Client-Hint: fixture\r\n\r\n"
        b"b=2&a=1&a=3"
    )


def _response_bytes() -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Set-Cookie: session=response-cookie\r\n\r\n"
        b'{"token":"response-secret","ok":true}'
    )


def test_content_addressed_artifacts_are_hash_stable_chunked_and_restart_safe(tmp_path: Path) -> None:
    crypto, database, audit, store, _flows, _target_id, scan_id, run_id = _fixture(tmp_path)
    payload = (b"0123456789abcdef" * 10) + b"tail"
    first = store.put(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="tool.stdout",
        media_type="text/plain",
        content=payload,
        reason="capture tool stdout",
    )
    second = store.put(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="tool.stdout",
        media_type="text/plain",
        content=payload,
        reason="deduplicated re-capture",
    )
    assert first.sha256 == hashlib.sha256(payload).hexdigest()
    assert second.id == first.id
    assert first.chunk_count > 1
    restarted = RawArtifactStore(database, crypto, audit, chunk_size=32)
    assert restarted.read(first.sha256, scan_id=scan_id, reason="restart verification") == payload
    with database._connect() as conn:
        row = conn.execute("SELECT ciphertext FROM artifact_chunks WHERE artifact_id = ? ORDER BY chunk_index LIMIT 1", (first.id,)).fetchone()
    assert row is not None
    assert payload[:32] not in bytes(row["ciphertext"])


def test_tool_run_custody_preserves_exact_outputs_and_metadata(tmp_path: Path) -> None:
    _crypto, _database, _audit, store, _flows, _target_id, scan_id, run_id = _fixture(tmp_path)
    record = store.record_tool_run(
        scan_id=scan_id,
        tool_run_id=run_id,
        argv=["fixture", "https://example.test/private"],
        stdout=b"line-1\nline-2\n",
        stderr=b"warning\n",
        exit_code=0,
        started_at_wall=1_700_000_000.0,
        finished_at_wall=1_700_000_001.0,
        started_at_monotonic=10.0,
        finished_at_monotonic=11.0,
        tool_name="fixture",
        tool_version="1.2.3",
        resolved_binary_sha256="a" * 64,
        environment_allowlist_sha256="b" * 64,
        working_directory="C:/Windeep/tools",
    )
    resolved = store.read_tool_run(run_id)
    assert resolved["argv"] == ["fixture", "https://example.test/private"]
    assert resolved["export_argv"] == ["fixture", "<scope-bound target>"]
    assert resolved["stdout"] == b"line-1\nline-2\n"
    assert resolved["stderr"] == b"warning\n"
    assert resolved["exit_code"] == 0
    assert resolved["tool_version"] == "1.2.3"
    assert record["stdout_sha256"] == hashlib.sha256(b"line-1\nline-2\n").hexdigest()


def test_forensic_flow_preserves_raw_bytes_h2_metadata_and_exact_reconstruction(tmp_path: Path) -> None:
    _crypto, _database, _audit, _store, flows, target_id, scan_id, run_id = _fixture(tmp_path)
    raw_request = _request_bytes()
    raw_response = _response_bytes()
    flow_id = flows.capture(
        target_id=target_id,
        scan_id=scan_id,
        tool_run_id=run_id,
        task_id="tool:fixture",
        method="POST",
        url="https://example.test/api/items?mode=full",
        request_headers=[
            ("Host", "example.test"),
            ("Authorization", "Bearer request-secret"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("X-Client-Hint", "fixture"),
        ],
        request_body=b"b=2&a=1&a=3",
        status=200,
        response_headers=[("Content-Type", "application/json"), ("Set-Cookie", "session=response-cookie")],
        response_body=b'{"token":"response-secret","ok":true}',
        raw_request=raw_request,
        raw_response=raw_response,
        http_version="HTTP/2",
        stream_id=7,
        pseudo_headers=[(":method", "POST"), (":scheme", "https"), (":authority", "example.test"), (":path", "/api/items?mode=full")],
        timings={"connect": 1.0, "tls": 2.0, "ttfb": 3.0, "total": 4.0},
        tls={"sni": "example.test", "alpn": "h2", "cert_fingerprint_sha256": "c" * 64},
        server_ip="203.0.113.10",
        created_at=1_700_000_010.0,
    )
    assert flows.reconstruct_request(flow_id) == raw_request
    assert flows.reconstruct_response(flow_id) == raw_response
    detail = flows.get(flow_id)
    assert detail["http_version"] == "HTTP/2"
    assert detail["stream_id"] == 7
    assert detail["pseudo_headers"][0] == [":method", "POST"]
    assert detail["tls"]["alpn"] == "h2"


def test_har_export_is_deterministic_complete_and_redacted(tmp_path: Path) -> None:
    _crypto, _database, _audit, store, flows, target_id, scan_id, run_id = _fixture(tmp_path)
    flow_id = flows.capture(
        target_id=target_id,
        scan_id=scan_id,
        tool_run_id=run_id,
        task_id="tool:fixture",
        method="POST",
        url="https://example.test/api/items?token=query-secret",
        request_headers=[("Authorization", "Bearer request-secret"), ("Content-Type", "application/json")],
        request_body=b'{"password":"body-secret","value":1}',
        status=200,
        response_headers=[("Content-Type", "application/json"), ("Set-Cookie", "session=response-cookie")],
        response_body=b'{"token":"response-secret"}',
        raw_request=_request_bytes(),
        raw_response=_response_bytes(),
        http_version="HTTP/2",
        stream_id=3,
        pseudo_headers=[(":method", "POST")],
        timings={"connect": 1.0, "tls": 2.0, "ttfb": 3.0, "total": 4.0},
        tls={"sni": "example.test", "alpn": "h2", "cert_fingerprint_sha256": "d" * 64},
        server_ip="203.0.113.10",
        created_at=1_700_000_020.0,
    )
    redactor = EvidenceRedactor(store)
    first = flows.export_har(scan_id=scan_id, redactor=redactor, operator_terms=["query-secret"])
    second = flows.export_har(scan_id=scan_id, redactor=redactor, operator_terms=["query-secret"])
    assert first == second
    text = first.decode("utf-8")
    for secret in ("request-secret", "body-secret", "response-cookie", "response-secret", "query-secret"):
        assert secret not in text
    assert "[REDACTED:" in text
    har = json.loads(first)
    assert har["log"]["version"] == "1.2"
    assert len(har["log"]["pages"]) == 1
    entry = har["log"]["entries"][0]
    assert entry["_windeep"]["flow_id"] == flow_id
    assert entry["_windeep"]["scan_id"] == scan_id
    assert entry["_windeep"]["tool_run_id"] == run_id
    assert entry["_windeep"]["http2_downgraded"] is True
    assert entry["serverIPAddress"] == "203.0.113.10"
    assert set(entry["timings"]) >= {"connect", "ssl", "wait", "receive"}


def test_redaction_map_is_stable_persisted_and_itself_content_addressed(tmp_path: Path) -> None:
    _crypto, database, _audit, store, _flows, _target_id, scan_id, run_id = _fixture(tmp_path)
    artifact = store.put(
        scan_id=scan_id,
        tool_run_id=run_id,
        kind="fixture.secret",
        media_type="text/plain",
        content=b"Authorization: Bearer alpha\ntoken=beta\ncustom-gamma\n",
        reason="redaction fixture",
    )
    redactor = EvidenceRedactor(store)
    first = redactor.redact_artifact(artifact.sha256, scan_id=scan_id, path="tool.stdout", operator_terms=["custom-gamma"])
    second = redactor.redact_artifact(artifact.sha256, scan_id=scan_id, path="tool.stdout", operator_terms=["custom-gamma"])
    assert first.content == second.content
    assert first.map_sha256 == second.map_sha256
    assert b"alpha" not in first.content and b"beta" not in first.content and b"custom-gamma" not in first.content
    assert len(first.entries) >= 3
    with database._connect() as conn:
        rows = conn.execute("SELECT placeholder FROM redaction_map WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    assert rows
    assert all(str(row["placeholder"]).startswith("[REDACTED:") for row in rows)
    assert store.read(first.map_sha256, scan_id=scan_id, reason="verify redaction-map artifact")


def test_every_artifact_access_is_hash_chained_in_custody_log(tmp_path: Path) -> None:
    _crypto, _database, audit, store, _flows, _target_id, scan_id, run_id = _fixture(tmp_path)
    artifact = store.put(scan_id=scan_id, tool_run_id=run_id, kind="fixture", media_type="application/octet-stream", content=b"evidence", reason="create")
    store.read(artifact.sha256, scan_id=scan_id, reason="inspect")
    store.export(artifact.sha256, scan_id=scan_id, reason="export")
    events = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    custody = [item for item in events if item["event"] == "evidence.custody"]
    assert [item["data"]["action"] for item in custody[:3]] == ["create", "access", "export"]
    assert all(item["data"]["content_hash"] == artifact.sha256 for item in custody[:3])
    assert all("monotonic" in item["data"] for item in custody[:3])
    assert audit.verify_chain()[0] is True


def test_merkle_root_seals_and_verifies_scan_evidence(tmp_path: Path) -> None:
    _crypto, database, audit, store, flows, target_id, scan_id, run_id = _fixture(tmp_path)
    store.put(scan_id=scan_id, tool_run_id=run_id, kind="a", media_type="text/plain", content=b"one", reason="fixture")
    flows.capture(
        target_id=target_id,
        scan_id=scan_id,
        tool_run_id=run_id,
        task_id="tool:fixture",
        method="GET",
        url="https://example.test/health",
        request_headers=[("Accept", "application/json")],
        request_body=b"",
        status=200,
        response_headers=[("Content-Type", "application/json")],
        response_body=b'{"ok":true}',
        raw_request=b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n",
        raw_response=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
        timings={"total": 2.0},
        tls={"sni": "example.test", "alpn": "h2"},
        server_ip="203.0.113.10",
        created_at=1_700_000_030.0,
    )
    sealed = store.seal_scan(scan_id, reason="scan close")
    assert len(sealed["merkle_root"]) == 64
    assert sealed["leaf_count"] >= 3
    assert store.verify_scan_root(scan_id) is True
    ok, _count = audit.verify_chain()
    assert ok is True
    with database._connect() as conn:
        row = conn.execute("SELECT merkle_root FROM scan_evidence_roots WHERE scan_id = ? ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
    assert row is not None and row["merkle_root"] == sealed["merkle_root"]


def test_retention_delete_is_tombstone_plus_key_destruction(tmp_path: Path) -> None:
    _crypto, database, audit, store, _flows, _target_id, scan_id, run_id = _fixture(tmp_path)
    artifact = store.put(scan_id=scan_id, tool_run_id=run_id, kind="fixture", media_type="text/plain", content=b"destroy-me", reason="fixture")
    store.seal_scan(scan_id, reason="before retention delete")
    store.set_retention(scan_id, "keep-forever")
    store.delete_scan_evidence(scan_id, reason="operator retention request")
    with pytest.raises(EvidenceKeyDestroyedError):
        store.read(artifact.sha256, scan_id=scan_id, reason="post-destruction read")
    with database._connect() as conn:
        row = conn.execute("SELECT tombstoned_at FROM artifacts WHERE id = ?", (artifact.id,)).fetchone()
        key = conn.execute("SELECT wrapped_key, destroyed_at FROM scan_evidence_keys WHERE scan_id = ?", (scan_id,)).fetchone()
    assert row is not None and row["tombstoned_at"] is not None
    assert key is not None and key["wrapped_key"] is None and key["destroyed_at"] is not None
    events = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    deletes = [item for item in events if item["event"] == "evidence.scan_deleted"]
    assert deletes and deletes[-1]["data"]["invalidated_merkle_root"]
