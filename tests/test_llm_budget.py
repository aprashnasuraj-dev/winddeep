"""Tests for Windeep local-first LLM budgeting and encrypted response caching."""

from __future__ import annotations

import sqlite3

import pytest

from app.brain.budget import (
    BudgetedLLMClient,
    LLMBudgetStore,
    TokenBudgetExceeded,
    TokenBudgetLimits,
    default_brain_config,
    estimate_tokens,
)
from app.brain.llm_client import LLMResponse, ProviderConfig
from app.database import Database
from app.migrations import MigrationManager
from app.security.crypto import CryptoManager, FileProtector


def _store(tmp_path, limits: TokenBudgetLimits | None = None):
    database = Database(tmp_path / "windeep.db")
    MigrationManager(database.path, "app/data/migrations", backup_dir=tmp_path / "backups").apply()
    crypto = CryptoManager(
        wrapped_key_path=tmp_path / "dek.bin",
        protector=FileProtector(tmp_path / "master.key"),
    )
    return database, LLMBudgetStore(database, crypto, limits)


def test_default_brain_provider_is_local_ollama(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config = default_brain_config()
    assert config["providers"][0]["provider"] == "ollama"
    assert config["providers"][0]["endpoint"].startswith("http://127.0.0.1:")
    assert config["providers"][0]["enabled"] is True
    assert all(not provider["enabled"] for provider in config["providers"][1:])


def test_estimate_tokens_is_bounded_and_nonzero() -> None:
    assert estimate_tokens("") == 1
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcdefgh") == 2


@pytest.mark.asyncio
async def test_scan_budget_blocks_projected_overage(tmp_path) -> None:
    database, store = _store(tmp_path, TokenBudgetLimits(per_scan_tokens=100, per_day_tokens=1000))
    target_id = database.create_target("t", "web", "example.com")
    scan_id = database.create_scan(target_id, "full", [])
    store.record_usage(
        scan_id=scan_id,
        provider="local",
        model="m",
        input_tokens=60,
        output_tokens=20,
        cached=False,
    )
    with pytest.raises(TokenBudgetExceeded, match="scan LLM token budget"):
        await store.assert_budget(scan_id=scan_id, projected_tokens=21)


@pytest.mark.asyncio
async def test_daily_budget_blocks_projected_overage(tmp_path) -> None:
    _, store = _store(tmp_path, TokenBudgetLimits(per_scan_tokens=100, per_day_tokens=120))
    store.record_usage(
        scan_id=None,
        provider="local",
        model="m",
        input_tokens=70,
        output_tokens=30,
        cached=False,
    )
    with pytest.raises(TokenBudgetExceeded, match="daily LLM token budget"):
        await store.assert_budget(scan_id=None, projected_tokens=21)


def test_cache_content_is_encrypted_on_disk(tmp_path) -> None:
    database, store = _store(tmp_path)
    response = LLMResponse(provider="local", model="m", content="sensitive-response", raw={"x": "private"})
    store.put_cached("a" * 64, response)
    with sqlite3.connect(database.path) as conn:
        raw = conn.execute("SELECT response_json FROM llm_cache WHERE cache_key = ?", ("a" * 64,)).fetchone()[0]
    assert raw.startswith("enc:v1:")
    assert "sensitive-response" not in raw
    restored = store.get_cached("a" * 64)
    assert restored is not None
    assert restored.content == "sensitive-response"


@pytest.mark.asyncio
async def test_budgeted_client_uses_cache_on_second_call(tmp_path) -> None:
    _, store = _store(tmp_path)

    class FakeClient:
        providers = (
            ProviderConfig(name="local", provider="ollama", model="m", max_output_tokens=32),
        )

        def __init__(self) -> None:
            self.calls = 0

        async def complete_text(self, prompt: str, *, system: str = "", heuristic=None) -> LLMResponse:
            self.calls += 1
            return LLMResponse(provider="local", model="m", content='{"ok":true}', raw={})

    client = FakeClient()
    budgeted = BudgetedLLMClient(client, store)  # type: ignore[arg-type]
    first = await budgeted.complete_text("same prompt")
    second = await budgeted.complete_text("same prompt")
    assert first.content == second.content
    assert client.calls == 1
    with store.database._connect() as conn:
        cached_rows = conn.execute("SELECT COUNT(*) FROM llm_usage WHERE cached = 1").fetchone()[0]
    assert cached_rows == 1
