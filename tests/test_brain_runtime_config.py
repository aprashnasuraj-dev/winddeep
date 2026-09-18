from __future__ import annotations

import os

import httpx

from app.brain.runtime_config import brain_provider_config, brain_reasoner_name, build_llm_client


def test_brain_runtime_config_returns_rule_based_without_keys(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    assert brain_provider_config({}) == {"providers": []}
    assert brain_reasoner_name({}) == "rule-based"
    assert build_llm_client({}).providers == ()


def test_brain_runtime_config_uses_explicit_anthropic_settings(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    settings = {
        "brain_llm_provider": "anthropic",
        "brain_llm_model": "claude-test",
        "anthropic_api_key": "secret",
    }

    config = brain_provider_config(settings)

    assert config["providers"][0]["provider"] == "anthropic"
    assert config["providers"][0]["model"] == "claude-test"
    assert config["providers"][0]["api_key"] == "secret"
    assert config["providers"][0]["api_key_env"] == "ANTHROPIC_API_KEY"
    assert "ANTHROPIC_API_KEY" not in os.environ
    assert brain_reasoner_name(settings) == "anthropic:claude-test"


def test_brain_runtime_config_autodetects_openai_env(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "env-secret")

    config = brain_provider_config({})

    assert config["providers"][0]["provider"] == "openai"
    assert config["providers"][0]["model"] == "gpt-4o-mini"
    assert config["providers"][0]["endpoint"] == "https://api.openai.com/v1/chat/completions"


def test_build_llm_client_accepts_transport() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]}))
    client = build_llm_client({"brain_llm_provider": "openai", "openai_api_key": "secret"}, transport=transport)

    assert client.providers[0].provider == "openai"
    assert client._transport is transport
