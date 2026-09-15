"""Tests for encrypted-at-rest Windeep SQLite persistence."""

from __future__ import annotations

import sqlite3

from app.security.crypto import CryptoManager, FileProtector
from app.security.secure_database import SecureDatabase
from app.security.secure_flow_database import SecureFlowDatabase


def _database(tmp_path) -> SecureDatabase:
    protector = FileProtector(tmp_path / "master.key")
    crypto = CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=protector)
    return SecureDatabase(tmp_path / "windeep.db", crypto=crypto)


def _target(db: SecureDatabase) -> int:
    return db.create_target("Example", "web", "https://example.com", scope=["example.com"])


def test_finding_sensitive_fields_are_encrypted_on_disk(tmp_path) -> None:
    db = _database(tmp_path)
    target_id = _target(db)
    finding_id, created = db.create_finding(
        target_id,
        "Sensitive finding",
        "high",
        endpoint="https://example.com/account",
        evidence={"token": "top-secret-token"},
        request="Authorization: Bearer top-secret-token",
        response="private-response-value",
    )
    assert created
    with sqlite3.connect(db.path) as conn:
        row = conn.execute("SELECT evidence, request, response FROM findings WHERE id = ?", (finding_id,)).fetchone()
    assert row is not None
    joined = " ".join(str(value) for value in row)
    assert "top-secret-token" not in joined
    assert "private-response-value" not in joined
    assert "enc:v1:" in joined


def test_finding_round_trip_is_transparent(tmp_path) -> None:
    db = _database(tmp_path)
    target_id = _target(db)
    finding_id, _ = db.create_finding(target_id, "Round trip", "medium", evidence={"proof": "value"}, request="REQ", response="RESP")
    item = db.get_finding(finding_id)
    assert item is not None
    assert item["evidence"] == {"proof": "value"}
    assert item["request"] == "REQ"
    assert item["response"] == "RESP"


def test_flow_bodies_and_headers_are_encrypted_on_disk(tmp_path) -> None:
    db = _database(tmp_path)
    target_id = _target(db)
    flow_id = db.insert_flow(
        {
            "target_id": target_id,
            "method": "POST",
            "url": "https://example.com/api",
            "scheme": "https",
            "host": "example.com",
            "path": "/api",
            "query": "secret=query-value",
            "request_headers": {"Authorization": "Bearer secret-token"},
            "request_body": b"secret-request-body",
            "status": 200,
            "response_headers": {"X-Private": "secret-header"},
            "response_body": b"secret-response-body",
        }
    )
    with sqlite3.connect(db.path) as conn:
        row = conn.execute("SELECT query, request_headers, request_body, response_headers, response_body FROM flows WHERE id = ?", (flow_id,)).fetchone()
    assert row is not None
    raw = b" ".join(value if isinstance(value, bytes) else str(value).encode() for value in row)
    assert b"secret-token" not in raw
    assert b"secret-request-body" not in raw
    assert b"secret-response-body" not in raw


def test_secure_flow_database_decrypts_for_export(tmp_path) -> None:
    db = _database(tmp_path)
    target_id = _target(db)
    flow_id = db.insert_flow(
        {
            "target_id": target_id,
            "method": "GET",
            "url": "https://example.com/private",
            "host": "example.com",
            "path": "/private",
            "request_headers": {"X-Test": "visible-after-decrypt"},
            "response_body": b"hello",
            "status": 200,
        }
    )
    flows = SecureFlowDatabase(db)
    item = flows.get_flow_by_id(flow_id)
    assert item is not None
    assert item["request_headers"]["X-Test"] == "visible-after-decrypt"
    assert item["response_body"] == b"hello"
    assert "visible-after-decrypt" in flows.export_flow(flow_id, "raw")


def test_finding_deduplication_still_operates_on_metadata(tmp_path) -> None:
    db = _database(tmp_path)
    target_id = _target(db)
    first, created_first = db.create_finding(target_id, "Same", "low", vuln_type="header", endpoint="https://example.com/")
    second, created_second = db.create_finding(target_id, "Same", "low", vuln_type="header", endpoint="https://example.com/", evidence={"different": "encrypted"})
    assert created_first is True
    assert created_second is False
    assert second == first
