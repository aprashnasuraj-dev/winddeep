"""Encrypted capture persistence regression tests for the release gate."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.crypto import CryptoManager, FileProtector
from app.security.secure_database import SecureDatabase
from app.security.secure_flow_database import SecureFlowDatabase


def _store(tmp_path: Path) -> tuple[SecureDatabase, SecureFlowDatabase, int]:
    protector = FileProtector(tmp_path / "master.key")
    crypto = CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=protector)
    database = SecureDatabase(tmp_path / "windeep.db", crypto=crypto)
    target_id = database.create_target("Capture QA", "web", "example.com", scope=["example.com"])
    return database, SecureFlowDatabase(database), target_id


def _flow(target_id: int) -> dict[str, object]:
    return {
        "target_id": target_id,
        "scan_id": None,
        "method": "POST",
        "url": "https://example.com/api?q=needle",
        "scheme": "https",
        "host": "example.com",
        "port": 443,
        "path": "/api",
        "query": "q=needle",
        "request_headers": {"Authorization": "Bearer qa-secret", "Content-Type": "text/plain"},
        "request_body": b"request needle secret",
        "status": 201,
        "response_headers": {"Content-Type": "text/plain"},
        "response_body": b"response needle secret",
        "timing_ms": 12.5,
        "tls_info": {"tls_version": "TLSv1.3"},
        "client_ip": "127.0.0.1",
        "tags": ["qa", "encrypted"],
        "created_at": 1_700_000_000.0,
    }


def test_secure_flow_round_trip_search_and_exports(tmp_path: Path) -> None:
    database, flows, target_id = _store(tmp_path)
    flow_id = flows.insert_flow(_flow(target_id))

    row = flows.get_flow_by_id(flow_id)
    assert row is not None
    assert row["query"] == "q=needle"
    assert row["request_headers"]["Authorization"] == "Bearer qa-secret"
    assert row["request_body"] == b"request needle secret"
    assert row["response_body"] == b"response needle secret"
    assert row["tls_info"]["tls_version"] == "TLSv1.3"
    assert row["client_ip"] == "127.0.0.1"
    assert row["tags"] == ["qa", "encrypted"]

    by_target = flows.get_flows_by_target(target_id, limit=5)
    assert [item["id"] for item in by_target] == [flow_id]
    assert flows.get_flow_by_id(999999) is None

    searched = flows.search_flows("needle", target_id=target_id, method="post", host="EXAMPLE.COM", limit=10)
    assert [item["id"] for item in searched] == [flow_id]
    assert flows.search_flows("absent", target_id=target_id) == []

    raw = flows.export_flow(flow_id, "raw")
    assert "POST /api?q=needle HTTP/1.1" in raw
    assert "response needle secret" in raw
    assert "curl" in flows.export_flow(flow_id, "curl")
    assert "http" in flows.export_flow(flow_id, "httpie")
    har = json.loads(flows.export_flow(flow_id, "har"))
    assert har["log"]["entries"][0]["response"]["status"] == 201

    with database._connect() as conn:
        stored = dict(conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone())
    joined = " ".join(str(value) for value in stored.values())
    assert "qa-secret" not in joined
    assert "request needle secret" not in joined
    assert "response needle secret" not in joined

    assert flows.delete_flow(flow_id) is True
    assert flows.delete_flow(flow_id) is False


def test_secure_flow_validates_pagination_and_required_fields(tmp_path: Path) -> None:
    _, flows, target_id = _store(tmp_path)
    with pytest.raises(ValueError, match="missing flow fields"):
        flows.insert_flow({"target_id": target_id, "method": "GET"})
    with pytest.raises(ValueError, match="limit"):
        flows.get_flows_by_target(target_id, limit=0)
    with pytest.raises(ValueError, match="offset"):
        flows.search_flows("x", offset=-1)
    with pytest.raises(KeyError):
        flows.export_flow(999999, "raw")
