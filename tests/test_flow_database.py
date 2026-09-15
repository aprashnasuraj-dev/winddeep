"""Tests for Windeep captured-flow persistence and exporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.capture.flow_database import FlowDatabase
from app.database import Database


def make_store(tmp_path: Path) -> tuple[Database, FlowDatabase, int]:
    database = Database(tmp_path / "flows.db")
    target_id = database.create_target("Example", "web", "https://example.com")
    return database, FlowDatabase(database), target_id


def insert_sample(store: FlowDatabase, target_id: int, *, url: str = "https://example.com/api/items?id=7") -> int:
    return store.insert_flow(
        {
            "target_id": target_id,
            "method": "POST",
            "url": url,
            "scheme": "https",
            "host": "example.com",
            "port": 443,
            "path": "/api/items",
            "query": "id=7",
            "request_headers": {"Content-Type": "application/json", "X-Test": "one"},
            "request_body": b'{"name":"marker"}',
            "status": 201,
            "response_headers": {"Content-Type": "application/json", "X-Reply": "yes"},
            "response_body": b'{"id":7}',
            "timing_ms": 12.5,
            "tls_info": {"tls_version": "TLSv1.3"},
            "client_ip": "127.0.0.1",
            "tags": ["api"],
            "created_at": 1_700_000_000.0,
        }
    )


def test_insert_and_get_decodes_structured_fields(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    flow_id = insert_sample(store, target_id)
    row = store.get_flow_by_id(flow_id)
    assert row is not None
    assert row["request_headers"]["X-Test"] == "one"
    assert row["tls_info"] == {"tls_version": "TLSv1.3"}
    assert row["tags"] == ["api"]


def test_target_listing_is_paginated_newest_first(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    first = insert_sample(store, target_id, url="https://example.com/api/items?id=1")
    second = insert_sample(store, target_id, url="https://example.com/api/items?id=2")
    rows = store.get_flows_by_target(target_id, limit=1)
    assert [row["id"] for row in rows] == [second]
    assert first != second


def test_search_uses_literal_percent_and_filters(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    insert_sample(store, target_id, url="https://example.com/api/items?discount=10%25")
    rows = store.search_flows("10%25", target_id=target_id, method="POST", host="example.com")
    assert len(rows) == 1
    assert "discount=10%25" in rows[0]["url"]


def test_raw_export_contains_request_and_response(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    flow_id = insert_sample(store, target_id)
    raw = store.export_flow(flow_id, "raw")
    assert "POST /api/items?id=7 HTTP/1.1" in raw
    assert '"name":"marker"' in raw
    assert "--- RESPONSE ---" in raw
    assert "HTTP/1.1 201" in raw


def test_curl_and_httpie_exports_include_body(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    flow_id = insert_sample(store, target_id)
    curl = store.export_flow(flow_id, "curl")
    httpie = store.export_flow(flow_id, "httpie")
    assert curl.startswith("curl -i -X")
    assert "--data-binary" in curl
    assert httpie.startswith("http ")
    assert "<<<" in httpie


def test_har_export_is_valid_and_preserves_status(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    flow_id = insert_sample(store, target_id)
    har = json.loads(store.export_flow(flow_id, "har"))
    entry = har["log"]["entries"][0]
    assert har["log"]["version"] == "1.2"
    assert entry["request"]["method"] == "POST"
    assert entry["response"]["status"] == 201
    assert entry["time"] == pytest.approx(12.5)


def test_delete_flow_is_idempotent(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    flow_id = insert_sample(store, target_id)
    assert store.delete_flow(flow_id) is True
    assert store.delete_flow(flow_id) is False
    assert store.get_flow_by_id(flow_id) is None


def test_invalid_pagination_and_export_are_rejected(tmp_path: Path) -> None:
    _, store, target_id = make_store(tmp_path)
    flow_id = insert_sample(store, target_id)
    with pytest.raises(ValueError):
        store.get_flows_by_target(target_id, limit=0)
    with pytest.raises(ValueError):
        store.get_flows_by_target(target_id, offset=-1)
    with pytest.raises(ValueError, match="unsupported export"):
        store.export_flow(flow_id, "xml")  # type: ignore[arg-type]
