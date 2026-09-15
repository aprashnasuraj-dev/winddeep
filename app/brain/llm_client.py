"""Unified asynchronous LLM client for the Windeep Brain.

The client supports OpenAI, Anthropic, Ollama, and generic OpenAI-compatible
endpoints. The historical ``github_models`` provider name is retained for
configuration compatibility; GitHub Models itself was retired in July 2026,
so a custom endpoint must be supplied for that provider key.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

Heuristic = Callable[[], Any | Awaitable[Any]]


class LLMError(RuntimeError):
    """Base error for Brain provider failures."""


class ProviderUnavailable(LLMError):
    """Raised when a configured provider cannot be used."""


class InvalidModelResponse(LLMError):
    """Raised when a provider response cannot be normalized."""


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Configuration for one model provider in fallback order."""

    name: str
    provider: str
    model: str
    endpoint: str | None = None
    api_key_env: str | None = None
    enabled: bool = True
    max_output_tokens: int = 2048
    temperature: float = 0.1

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProviderConfig":
        """Build a validated provider configuration from JSON-like data."""
        name = str(value.get("name") or value.get("provider") or "provider")
        provider = str(value.get("provider") or "").strip().lower()
        model = str(value.get("model") or "").strip()
        if not provider:
            raise ValueError(f"provider is required for {name}")
        if not model:
            raise ValueError(f"model is required for {name}")
        max_output_tokens = int(value.get("max_output_tokens", 2048))
        if max_output_tokens < 1:
            raise ValueError("max_output_tokens must be positive")
        temperature = float(value.get("temperature", 0.1))
        if not 0.0 <= temperature <= 2.0:
            raise ValueError("temperature must be between 0 and 2")
        return cls(
            name=name,
            provider=provider,
            model=model,
            endpoint=str(value["endpoint"]).strip() if value.get("endpoint") else None,
            api_key_env=str(value["api_key_env"]).strip() if value.get("api_key_env") else None,
            enabled=bool(value.get("enabled", True)),
            max_output_tokens=max_output_tokens,
            temperature=temperature,
        )


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Normalized provider response."""

    provider: str
    model: str
    content: str
    raw: dict[str, Any]


class LLMClient:
    """Provider-agnostic client with retries, budgets, and heuristic fallback."""

    def __init__(
        self,
        providers: Sequence[ProviderConfig],
        *,
        timeout: float = 120.0,
        retries: int = 2,
        max_input_tokens: int = 24_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if retries < 0:
            raise ValueError("retries must be >= 0")
        if max_input_tokens < 256:
            raise ValueError("max_input_tokens must be >= 256")
        self.providers = tuple(providers)
        self.timeout = timeout
        self.retries = retries
        self.max_input_tokens = max_input_tokens
        self._transport = transport

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> "LLMClient":
        """Build a client from a config mapping containing an ordered providers list."""
        raw = config.get("providers", [])
        if not isinstance(raw, list):
            raise ValueError("brain.providers must be a list")
        providers = [ProviderConfig.from_mapping(item) for item in raw if isinstance(item, Mapping)]
        return cls(
            providers,
            timeout=float(config.get("timeout", 120.0)),
            retries=int(config.get("retries", 2)),
            max_input_tokens=int(config.get("max_input_tokens", 24_000)),
            transport=transport,
        )

    async def complete_text(
        self,
        prompt: str,
        *,
        system: str = "",
        heuristic: Heuristic | None = None,
    ) -> LLMResponse:
        """Return normalized text from the first available provider."""
        try:
            bounded_prompt = self._bound_input(prompt)
            failures: list[str] = []
            for provider in self.providers:
                if not provider.enabled:
                    continue
                try:
                    return await self._call_with_retries(provider, bounded_prompt, system)
                except asyncio.CancelledError:
                    raise
                except (LLMError, httpx.HTTPError, ValueError, KeyError) as exc:
                    failures.append(f"{provider.name}: {type(exc).__name__}: {exc}")
            if heuristic is not None:
                fallback = heuristic()
                if inspect.isawaitable(fallback):
                    fallback = await fallback
                content = fallback if isinstance(fallback, str) else json.dumps(fallback, ensure_ascii=False)
                return LLMResponse(
                    provider="heuristic",
                    model="rule-based",
                    content=content,
                    raw={"failures": failures},
                )
            detail = "; ".join(failures) if failures else "no enabled providers"
            raise ProviderUnavailable(f"no model provider succeeded: {detail}")
        except asyncio.CancelledError:
            raise

    async def complete_json(
        self,
        prompt: str,
        *,
        system: str = "",
        heuristic: Heuristic | None = None,
    ) -> Any:
        """Return parsed JSON, falling back to the supplied rule-based heuristic."""
        try:
            response = await self.complete_text(prompt, system=system, heuristic=heuristic)
            try:
                return self._extract_json(response.content)
            except InvalidModelResponse:
                if heuristic is None or response.provider == "heuristic":
                    raise
                fallback = heuristic()
                if inspect.isawaitable(fallback):
                    fallback = await fallback
                return fallback
        except asyncio.CancelledError:
            raise

    async def _call_with_retries(
        self,
        provider: ProviderConfig,
        prompt: str,
        system: str,
    ) -> LLMResponse:
        try:
            last_error: BaseException | None = None
            for attempt in range(self.retries + 1):
                try:
                    return await self._call_provider(provider, prompt, system)
                except asyncio.CancelledError:
                    raise
                except (LLMError, httpx.HTTPError, ValueError, KeyError) as exc:
                    last_error = exc
                    if attempt >= self.retries:
                        break
                    await asyncio.sleep(min(8.0, 0.5 * (2**attempt)))
            raise LLMError(f"provider {provider.name} failed: {last_error}")
        except asyncio.CancelledError:
            raise

    async def _call_provider(
        self,
        provider: ProviderConfig,
        prompt: str,
        system: str,
    ) -> LLMResponse:
        try:
            kind = provider.provider
            if kind == "github_models" and provider.endpoint is None:
                raise ProviderUnavailable(
                    "GitHub Models inference was retired on 2026-07-30; "
                    "configure a custom compatible endpoint or choose another provider"
                )
            if kind in {"openai", "openai_compatible", "github_models"}:
                return await self._call_openai_compatible(provider, prompt, system)
            if kind == "anthropic":
                return await self._call_anthropic(provider, prompt, system)
            if kind == "ollama":
                return await self._call_ollama(provider, prompt, system)
            raise ProviderUnavailable(f"unsupported provider: {kind}")
        except asyncio.CancelledError:
            raise

    async def _call_openai_compatible(
        self,
        provider: ProviderConfig,
        prompt: str,
        system: str,
    ) -> LLMResponse:
        try:
            endpoint = provider.endpoint
            if endpoint is None:
                if provider.provider == "openai":
                    endpoint = "https://api.openai.com/v1/chat/completions"
                else:
                    raise ProviderUnavailable(f"endpoint required for {provider.provider}")
            api_key = self._api_key(provider)
            headers = {"content-type": "application/json"}
            if api_key:
                headers["authorization"] = f"Bearer {api_key}"
            messages: list[dict[str, str]] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            payload = {
                "model": provider.model,
                "messages": messages,
                "temperature": provider.temperature,
                "max_tokens": provider.max_output_tokens,
            }
            data = await self._post_json(endpoint, payload, headers)
            content = data["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise InvalidModelResponse("OpenAI-compatible content is not text")
            return LLMResponse(provider=provider.name, model=provider.model, content=content, raw=data)
        except asyncio.CancelledError:
            raise
        except (IndexError, TypeError, KeyError) as exc:
            raise InvalidModelResponse(f"invalid OpenAI-compatible response: {exc}") from exc

    async def _call_anthropic(
        self,
        provider: ProviderConfig,
        prompt: str,
        system: str,
    ) -> LLMResponse:
        try:
            endpoint = provider.endpoint or "https://api.anthropic.com/v1/messages"
            api_key = self._api_key(provider)
            if not api_key:
                raise ProviderUnavailable("Anthropic API key is not configured")
            headers = {
                "content-type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
            payload: dict[str, Any] = {
                "model": provider.model,
                "max_tokens": provider.max_output_tokens,
                "temperature": provider.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                payload["system"] = system
            data = await self._post_json(endpoint, payload, headers)
            blocks = data.get("content", [])
            text = "".join(
                str(block.get("text", ""))
                for block in blocks
                if isinstance(block, Mapping) and block.get("type") == "text"
            ).strip()
            if not text:
                raise InvalidModelResponse("Anthropic response contained no text block")
            return LLMResponse(provider=provider.name, model=provider.model, content=text, raw=data)
        except asyncio.CancelledError:
            raise

    async def _call_ollama(
        self,
        provider: ProviderConfig,
        prompt: str,
        system: str,
    ) -> LLMResponse:
        try:
            endpoint = provider.endpoint or "http://127.0.0.1:11434/api/chat"
            messages: list[dict[str, str]] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            payload = {
                "model": provider.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": provider.temperature, "num_predict": provider.max_output_tokens},
            }
            data = await self._post_json(endpoint, payload, {"content-type": "application/json"})
            content = data["message"]["content"]
            if not isinstance(content, str):
                raise InvalidModelResponse("Ollama content is not text")
            return LLMResponse(provider=provider.name, model=provider.model, content=content, raw=data)
        except asyncio.CancelledError:
            raise
        except (TypeError, KeyError) as exc:
            raise InvalidModelResponse(f"invalid Ollama response: {exc}") from exc

    async def _post_json(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> dict[str, Any]:
        try:
            timeout = httpx.Timeout(self.timeout)
            async with httpx.AsyncClient(timeout=timeout, transport=self._transport) as client:
                response = await client.post(endpoint, json=dict(payload), headers=dict(headers))
                response.raise_for_status()
                data = response.json()
            if not isinstance(data, dict):
                raise InvalidModelResponse("provider returned non-object JSON")
            return data
        except asyncio.CancelledError:
            raise
        except json.JSONDecodeError as exc:
            raise InvalidModelResponse("provider returned invalid JSON") from exc

    def _api_key(self, provider: ProviderConfig) -> str | None:
        if provider.api_key_env:
            return os.getenv(provider.api_key_env) or None
        defaults = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "github_models": "GITHUB_TOKEN",
        }
        env_name = defaults.get(provider.provider)
        return os.getenv(env_name) if env_name else None

    def _bound_input(self, prompt: str) -> str:
        max_chars = self.max_input_tokens * 4
        if len(prompt) <= max_chars:
            return prompt
        marker = "\n...[input truncated to configured Brain token budget]...\n"
        head = max_chars // 2
        tail = max_chars - head - len(marker)
        return prompt[:head] + marker + prompt[-max(0, tail):]

    @staticmethod
    def _extract_json(content: str) -> Any:
        text = content.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        decoder = json.JSONDecoder()
        candidates = [index for index, char in enumerate(text) if char in "[{"]
        for index in candidates:
            try:
                value, _ = decoder.raw_decode(text[index:])
                return value
            except json.JSONDecodeError:
                continue
        raise InvalidModelResponse("model response did not contain valid JSON")
