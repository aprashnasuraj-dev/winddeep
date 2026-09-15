"""Tests for Windeep LanceDB-backed Brain memory."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.brain.memory import HashEmbedding, MemoryStore


def test_hash_embedding_is_deterministic_and_normalized() -> None:
    embedder = HashEmbedding(64)
    first = embedder.embed("authorization object ownership record")
    second = embedder.embed("authorization object ownership record")
    assert first == second
    norm = sum(value * value for value in first) ** 0.5
    assert norm == pytest.approx(1.0)


def test_hash_embedding_empty_text_returns_zero_vector() -> None:
    vector = HashEmbedding(32).embed("   !!!   ")
    assert vector == [0.0] * 32


def test_sanitize_redacts_bearer_and_key_material(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory")
    text = "Authorization: Bearer super-secret-token api_key=abcd1234 password=hunter2"
    sanitized = store._sanitize(text)
    assert "super-secret-token" not in sanitized
    assert "abcd1234" not in sanitized
    assert "hunter2" not in sanitized
    assert sanitized.count("<redacted>") >= 3


@pytest.mark.asyncio
async def test_embed_finding_builds_sanitized_record(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory")
    captured: list[dict[str, Any]] = []

    def fake_insert(record: dict[str, Any]) -> None:
        captured.append(dict(record))

    monkeypatch.setattr(store, "_insert_sync", fake_insert)
    memory_id = await store.embed_finding(
        {
            "id": 8,
            "title": "Session issue",
            "vuln_type": "session",
            "endpoint": "https://example.com/me",
            "description": "Authorization: Bearer secret-value",
            "evidence": {"api_key": "not-a-real-secret"},
        },
        target_id=2,
    )

    assert memory_id == captured[0]["id"]
    assert captured[0]["kind"] == "finding"
    assert captured[0]["target_id"] == 2
    assert captured[0]["finding_id"] == 8
    assert "secret-value" not in captured[0]["text"]
    assert len(captured[0]["vector"]) == 256


@pytest.mark.asyncio
async def test_find_similar_filters_kind_and_converts_distance(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory")

    def fake_search(vector: list[float], limit: int) -> list[dict[str, Any]]:
        assert len(vector) == 256
        assert limit == 9
        return [
            {
                "id": "a",
                "text": "first",
                "kind": "finding",
                "metadata_json": '{"vuln_type":"idor"}',
                "_distance": 0.10,
            },
            {
                "id": "b",
                "text": "rejected",
                "kind": "rejection",
                "metadata_json": "{}",
                "_distance": 0.05,
            },
            {
                "id": "c",
                "text": "second",
                "kind": "finding",
                "metadata_json": "{}",
                "_distance": 0.25,
            },
        ]

    monkeypatch.setattr(store, "_search_sync", fake_search)
    rows = await store.find_similar("authorization object", limit=3, kind="finding")
    assert [row["id"] for row in rows] == ["a", "c"]
    assert rows[0]["similarity"] == pytest.approx(0.9)
    assert rows[0]["metadata"] == {"vuln_type": "idor"}


@pytest.mark.asyncio
async def test_learn_from_rejection_records_generalized_memory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory")
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(store, "_insert_sync", lambda record: captured.append(dict(record)))

    memory_id = await store.learn_from_rejection(
        {"id": 4, "title": "Unverified signal", "vuln_type": "configuration"},
        {"reason": "scanner-only; needs manual evidence"},
        target_id=1,
    )

    assert memory_id == captured[0]["id"]
    assert captured[0]["kind"] == "rejection"
    assert "scanner-only" in captured[0]["text"]


@pytest.mark.asyncio
async def test_find_similar_rejects_unbounded_limit(tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory")
    with pytest.raises(ValueError, match="limit must be between"):
        await store.find_similar("x", limit=101)


@pytest.mark.asyncio
async def test_cancellation_propagates_from_insert(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = MemoryStore(tmp_path / "memory")

    async def cancelled_to_thread(*args: Any, **kwargs: Any) -> Any:
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "to_thread", cancelled_to_thread)
    with pytest.raises(asyncio.CancelledError):
        await store.embed_finding({"title": "x", "vuln_type": "info"})
