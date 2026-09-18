"""Build a brain LLM client from Windeep settings and environment.

Historically the scan pipeline and intelligence surfaces constructed the brain
with ``LLMClient([])`` (an empty provider list). That silently disabled every
natural-language ("human-like") narrative: the client always fell through to the
deterministic rule-based fallback and there was no supported way for an operator
to enable a real model. This module gives the whole app one place to turn a
provider name + API key (from encrypted settings or the environment) into a
configured :class:`~app.brain.llm_client.LLMClient`.

When no provider/key is configured the returned client has zero providers, so
every brain surface degrades gracefully to the rule-based reasoner instead of
failing. When a key is present, the same code path activates the model.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

import httpx

from app.brain.llm_client import LLMClient

_DEFAULT_MODELS = {
    "anthropic": "claude-3-5-sonnet-latest",
    "openai": "gpt-4o-mini",
}
_DEFAULT_ENDPOINTS = {
    # Anthropic's endpoint is handled inside the client; OpenAI needs an explicit
    # chat-completions endpoint.
    "openai": "https://api.openai.com/v1/chat/completions",
}
_KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def _first_configured(settings: Mapping[str, Any]) -> str:
    """Return the provider the operator selected, or auto-detect from keys."""
    explicit = str(settings.get("brain_llm_provider") or "").strip().lower()
    if explicit in _KEY_ENV:
        return explicit
    # Auto-detect: prefer whichever key is present (settings first, then env).
    for provider, env_name in _KEY_ENV.items():
        settings_key = f"{provider}_api_key"
        value = settings.get(settings_key)
        if isinstance(value, str) and value.strip() and value != "configured":
            return provider
        if os.getenv(env_name):
            return provider
    return ""


def _resolve_key(provider: str, settings: Mapping[str, Any]) -> str | None:
    settings_key = f"{provider}_api_key"
    value = settings.get(settings_key)
    if isinstance(value, str) and value.strip() and value != "configured":
        return value.strip()
    return os.getenv(_KEY_ENV.get(provider, "")) or None


def brain_provider_config(settings: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a provider config mapping suitable for ``LLMClient.from_config``.

    An empty ``{"providers": []}`` means "no model configured" and the client
    will use its deterministic heuristic fallback.
    """
    settings = dict(settings or {})
    provider = _first_configured(settings)
    if not provider:
        return {"providers": []}
    key = _resolve_key(provider, settings)
    if not key:
        return {"providers": []}
    model = str(settings.get("brain_llm_model") or "").strip()
    if not model or model == "configured":
        model = _DEFAULT_MODELS[provider]
    entry: dict[str, Any] = {
        "name": provider,
        "provider": provider,
        "model": model,
        "api_key": key,
        "api_key_env": _KEY_ENV[provider],
        "enabled": True,
    }
    endpoint = _DEFAULT_ENDPOINTS.get(provider)
    if endpoint:
        entry["endpoint"] = endpoint
    return {"providers": [entry]}


def build_llm_client(
    settings: Mapping[str, Any] | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> LLMClient:
    """Build a configured brain LLM client (falls back to rule-based when unset)."""
    return LLMClient.from_config(brain_provider_config(settings), transport=transport)


def brain_reasoner_name(settings: Mapping[str, Any] | None = None) -> str:
    """Human-readable label for whichever reasoner is active."""
    config = brain_provider_config(settings)
    providers = config.get("providers") or []
    if providers:
        first = providers[0]
        return f"{first['provider']}:{first['model']}"
    return "rule-based"


__all__ = ["brain_provider_config", "build_llm_client", "brain_reasoner_name"]
