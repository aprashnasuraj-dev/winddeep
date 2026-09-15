"""Tests for the Windeep multi-provider LLM client."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from app.brain.llm_client import (
    InvalidModelResponse,
    LLMClient,
    ProviderConfig,
    ProviderUnavailable,
)


@pytest.mark.asyncio
async def test_openai_compatible_json_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-key"
        body = json.loads(request.content)
        assert body["model"] == "test-model"
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"ok": true}'}}]},
        )

    client = LLMClient(
        [ProviderConfig(name="primary", provider="openai", model="test-model")],
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    assert await client.complete_json("hello") == {"ok": True}


@pytest.mark.asyncio
async def test_anthropic_text_block_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "anthropic-key"
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": '{"answer": 7}'}]},
        )

    client = LLMClient(
        [ProviderConfig(name="claude", provider="anthropic", model="claude-test")],
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    assert await client.complete_json("hello") == {"answer": 7}


@pytest.mark.asyncio
async def test_ollama_success_without_api_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "127.0.0.1"
        return httpx.Response(
            200,
            json={"message": {"content": '{"local": true}'}},
        )

    client = LLMClient(
        [ProviderConfig(name="local", provider="ollama", model="qwen")],
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    assert await client.complete_json("hello") == {"local": True}


@pytest.mark.asyncio
async def test_fallback_chain_uses_second_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, json={"error": "temporary"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"provider": "secondary"}'}}]},
        )

    client = LLMClient(
        [
            ProviderConfig(name="primary", provider="openai", model="one"),
            ProviderConfig(name="secondary", provider="openai", model="two"),
        ],
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    assert await client.complete_json("hello") == {"provider": "secondary"}
    assert calls == 2


@pytest.mark.asyncio
async def test_rule_based_heuristic_used_when_providers_fail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "down"})

    client = LLMClient(
        [ProviderConfig(name="local", provider="ollama", model="offline")],
        retries=0,
        transport=httpx.MockTransport(handler),
    )
    result = await client.complete_json(
        "hello",
        heuristic=lambda: {"hypotheses": [{"id": "rule-1"}]},
    )
    assert result["hypotheses"][0]["id"] == "rule-1"


def test_extract_json_accepts_fenced_json() -> None:
    value = LLMClient._extract_json("```json\n{\"x\": 1}\n```")
    assert value == {"x": 1}


def test_extract_json_rejects_non_json() -> None:
    with pytest.raises(InvalidModelResponse):
        LLMClient._extract_json("plain text only")


@pytest.mark.asyncio
async def test_retired_github_models_requires_custom_endpoint() -> None:
    client = LLMClient(
        [ProviderConfig(name="legacy", provider="github_models", model="old-model")],
        retries=0,
    )
    with pytest.raises(ProviderUnavailable, match="no model provider succeeded"):
        await client.complete_text("hello")


def test_input_budget_truncates_middle() -> None:
    client = LLMClient([], max_input_tokens=256)
    prompt = "a" * 2000
    bounded = client._bound_input(prompt)
    assert len(bounded) <= 1024
    assert "input truncated" in bounded


@pytest.mark.asyncio
async def test_cancellation_propagates() -> None:
    class CancelClient(LLMClient):
        async def _call_provider(self, provider: ProviderConfig, prompt: str, system: str):  # type: ignore[override]
            raise asyncio.CancelledError

    client = CancelClient(
        [ProviderConfig(name="cancel", provider="ollama", model="x")],
        retries=0,
    )
    with pytest.raises(asyncio.CancelledError):
        await client.complete_text("hello")
