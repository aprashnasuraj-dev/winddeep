"""LLM budgets, encrypted response caching, and local-first defaults for Windeep."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.brain.llm_client import Heuristic, LLMClient, LLMResponse, ProviderConfig
from app.database import Database
from app.security.crypto import CryptoManager


class TokenBudgetExceeded(RuntimeError):
    """Raised before an LLM call would exceed configured scan or daily limits."""


class BudgetSchemaError(RuntimeError):
    """Raised when P1 migration tables have not been applied."""


@dataclass(frozen=True, slots=True)
class TokenBudgetLimits:
    """Hard model token ceilings and cache lifetime."""

    per_scan_tokens: int = 50_000
    per_day_tokens: int = 200_000
    cache_ttl_seconds: int = 24 * 60 * 60

    def __post_init__(self) -> None:
        if self.per_scan_tokens < 1:
            raise ValueError("per_scan_tokens must be positive")
        if self.per_day_tokens < self.per_scan_tokens:
            raise ValueError("per_day_tokens must be >= per_scan_tokens")
        if self.cache_ttl_seconds < 1:
            raise ValueError("cache_ttl_seconds must be positive")


def estimate_tokens(text: str) -> int:
    """Return a conservative provider-independent token estimate.

    Windeep budgets before a provider call, so it cannot depend on a remote
    tokenizer. UTF-8 bytes/4 is used with a one-token floor. Provider-reported
    usage can replace this estimate later when available.
    """
    return max(1, math.ceil(len(text.encode("utf-8")) / 4))


def default_brain_config() -> dict[str, Any]:
    """Return local-first Brain configuration with Ollama enabled by default."""
    return {
        "timeout": 120.0,
        "retries": 2,
        "max_input_tokens": 24_000,
        "providers": [
            {
                "name": "ollama-local",
                "provider": "ollama",
                "model": os.getenv("WINDEEP_OLLAMA_MODEL", "qwen3:8b"),
                "endpoint": os.getenv("WINDEEP_OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/chat"),
                "enabled": True,
                "max_output_tokens": 2048,
                "temperature": 0.1,
            },
            {
                "name": "openai-secondary",
                "provider": "openai",
                "model": os.getenv("WINDEEP_OPENAI_MODEL", "gpt-5-mini"),
                "api_key_env": "OPENAI_API_KEY",
                "enabled": bool(os.getenv("OPENAI_API_KEY")),
                "max_output_tokens": 2048,
                "temperature": 0.1,
            },
            {
                "name": "anthropic-tertiary",
                "provider": "anthropic",
                "model": os.getenv("WINDEEP_ANTHROPIC_MODEL", "claude-sonnet-4-5"),
                "api_key_env": "ANTHROPIC_API_KEY",
                "enabled": bool(os.getenv("ANTHROPIC_API_KEY")),
                "max_output_tokens": 2048,
                "temperature": 0.1,
            },
        ],
    }


class LLMBudgetStore:
    """SQLite-backed token accounting and AES-GCM encrypted response cache."""

    def __init__(self, database: Database, crypto: CryptoManager, limits: TokenBudgetLimits | None = None) -> None:
        self.database = database
        self.crypto = crypto
        self.limits = limits or TokenBudgetLimits()
        self._lock = asyncio.Lock()
        self._require_schema()

    def _require_schema(self) -> None:
        with self.database._connect() as conn:
            names = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = ? AND name IN (?, ?)",
                    ("table", "llm_usage", "llm_cache"),
                ).fetchall()
            }
        if names != {"llm_usage", "llm_cache"}:
            raise BudgetSchemaError("llm_usage/llm_cache tables are missing; apply database migrations first")

    @staticmethod
    def _day_start(now: float | None = None) -> float:
        instant = datetime.fromtimestamp(now or time.time(), tz=timezone.utc)
        start = instant.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.timestamp()

    def usage(self, *, scan_id: int | None = None, since: float | None = None) -> int:
        """Return charged input+output tokens for a scan or time window."""
        clauses = ["cached = 0"]
        values: list[Any] = []
        if scan_id is not None:
            clauses.append("scan_id = ?")
            values.append(scan_id)
        if since is not None:
            clauses.append("created_at >= ?")
            values.append(since)
        where = " AND ".join(clauses)
        with self.database._connect() as conn:
            row = conn.execute(
                f"SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM llm_usage WHERE {where}",
                tuple(values),
            ).fetchone()
        return int(row[0] if row is not None else 0)

    async def assert_budget(self, *, scan_id: int | None, projected_tokens: int) -> None:
        """Fail before a call if its maximum projected use would exceed a hard ceiling."""
        if projected_tokens < 1:
            raise ValueError("projected_tokens must be positive")
        async with self._lock:
            daily = self.usage(since=self._day_start())
            if daily + projected_tokens > self.limits.per_day_tokens:
                raise TokenBudgetExceeded(
                    f"daily LLM token budget exceeded: used={daily}, projected={projected_tokens}, limit={self.limits.per_day_tokens}"
                )
            if scan_id is not None:
                scan = self.usage(scan_id=scan_id)
                if scan + projected_tokens > self.limits.per_scan_tokens:
                    raise TokenBudgetExceeded(
                        f"scan LLM token budget exceeded: used={scan}, projected={projected_tokens}, limit={self.limits.per_scan_tokens}"
                    )

    def record_usage(
        self,
        *,
        scan_id: int | None,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cached: bool,
    ) -> int:
        """Persist one normalized usage record."""
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts cannot be negative")
        with self.database._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO llm_usage(scan_id, provider, model, input_tokens, output_tokens, cached, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, provider, model, input_tokens, output_tokens, int(cached), time.time()),
            )
            return int(cursor.lastrowid)

    def cache_key(self, *, prompt: str, system: str, providers: tuple[ProviderConfig, ...]) -> str:
        """Create a stable cache key without storing raw prompt text."""
        provider_fingerprint = [
            {
                "name": item.name,
                "provider": item.provider,
                "model": item.model,
                "endpoint": item.endpoint,
                "temperature": item.temperature,
                "max_output_tokens": item.max_output_tokens,
                "enabled": item.enabled,
            }
            for item in providers
        ]
        material = json.dumps(
            {"prompt": prompt, "system": system, "providers": provider_fingerprint},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def get_cached(self, cache_key: str) -> LLMResponse | None:
        """Return a decrypted unexpired cached response."""
        now = time.time()
        with self.database._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM llm_cache WHERE cache_key = ? AND expires_at > ?",
                (cache_key, now),
            ).fetchone()
        if row is None:
            return None
        plaintext = self.crypto.decrypt_text(str(row[0]), aad=b"windeep:llm-cache")
        data = json.loads(plaintext)
        return LLMResponse(
            provider=str(data["provider"]),
            model=str(data["model"]),
            content=str(data["content"]),
            raw=dict(data.get("raw") or {}),
        )

    def put_cached(self, cache_key: str, response: LLMResponse) -> None:
        """Encrypt and upsert a cached normalized provider response."""
        now = time.time()
        raw_json = json.dumps(
            {
                "provider": response.provider,
                "model": response.model,
                "content": response.content,
                "raw": response.raw,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        encrypted = self.crypto.encrypt_text(raw_json, aad=b"windeep:llm-cache")
        with self.database._connect() as conn:
            conn.execute(
                """
                INSERT INTO llm_cache(cache_key, provider, model, response_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    provider = excluded.provider,
                    model = excluded.model,
                    response_json = excluded.response_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    cache_key,
                    response.provider,
                    response.model,
                    encrypted,
                    now,
                    now + self.limits.cache_ttl_seconds,
                ),
            )

    def purge_expired(self) -> int:
        """Delete expired cache rows and return the number removed."""
        with self.database._connect() as conn:
            cursor = conn.execute("DELETE FROM llm_cache WHERE expires_at <= ?", (time.time(),))
            return int(cursor.rowcount)


class BudgetedLLMClient:
    """LLMClient facade enforcing cache-first hard token budgets."""

    def __init__(self, client: LLMClient, store: LLMBudgetStore) -> None:
        self.client = client
        self.store = store
        self.providers = client.providers

    async def complete_text(
        self,
        prompt: str,
        *,
        system: str = "",
        heuristic: Heuristic | None = None,
        scan_id: int | None = None,
        use_cache: bool = True,
    ) -> LLMResponse:
        """Return cached/model text while charging only actual model calls."""
        try:
            cache_key = self.store.cache_key(prompt=prompt, system=system, providers=self.providers)
            if use_cache:
                cached = self.store.get_cached(cache_key)
                if cached is not None:
                    self.store.record_usage(
                        scan_id=scan_id,
                        provider=cached.provider,
                        model=cached.model,
                        input_tokens=0,
                        output_tokens=0,
                        cached=True,
                    )
                    return cached
            input_tokens = estimate_tokens(system + "\n" + prompt)
            enabled = [provider for provider in self.providers if provider.enabled]
            projected_output = max((provider.max_output_tokens for provider in enabled), default=2048)
            await self.store.assert_budget(scan_id=scan_id, projected_tokens=input_tokens + projected_output)
            response = await self.client.complete_text(prompt, system=system, heuristic=heuristic)
            output_tokens = estimate_tokens(response.content)
            self.store.record_usage(
                scan_id=scan_id,
                provider=response.provider,
                model=response.model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached=False,
            )
            if use_cache and response.provider != "heuristic":
                self.store.put_cached(cache_key, response)
            return response
        except asyncio.CancelledError:
            raise

    async def complete_json(
        self,
        prompt: str,
        *,
        system: str = "",
        heuristic: Heuristic | None = None,
        scan_id: int | None = None,
        use_cache: bool = True,
    ) -> Any:
        """Return parsed JSON using the same budget/cache controls as text calls."""
        try:
            response = await self.complete_text(
                prompt,
                system=system,
                heuristic=heuristic,
                scan_id=scan_id,
                use_cache=use_cache,
            )
            try:
                return LLMClient._extract_json(response.content)
            except Exception:
                if heuristic is None or response.provider == "heuristic":
                    raise
                fallback = heuristic()
                if asyncio.iscoroutine(fallback):
                    fallback = await fallback
                return fallback
        except asyncio.CancelledError:
            raise
