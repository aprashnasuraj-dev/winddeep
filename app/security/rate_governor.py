"""Async token-bucket rate governance for Windeep."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass(slots=True)
class RatePolicy:
    """Token bucket parameters for one traffic class."""

    rate_per_second: float
    burst: float

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")
        if self.burst < 1:
            raise ValueError("burst must be >= 1")


class _TokenBucket:
    def __init__(self, policy: RatePolicy) -> None:
        self.policy = policy
        self.tokens = policy.burst
        self.updated_at = time.monotonic()
        self.lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.policy.burst, self.tokens + elapsed * self.policy.rate_per_second)
        self.updated_at = now

    async def acquire(self, cost: float = 1.0) -> None:
        if cost <= 0:
            raise ValueError("cost must be > 0")
        if cost > self.policy.burst:
            raise ValueError("cost cannot exceed bucket burst")
        try:
            while True:
                async with self.lock:
                    self._refill()
                    if self.tokens >= cost:
                        self.tokens -= cost
                        return
                    missing = cost - self.tokens
                    delay = missing / self.policy.rate_per_second
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise


class RateGovernor:
    """Enforce a global budget plus optional per-tool/per-host token buckets."""

    def __init__(
        self,
        *,
        global_policy: RatePolicy | None = None,
        default_key_policy: RatePolicy | None = None,
    ) -> None:
        self._global_policy = global_policy or RatePolicy(rate_per_second=10.0, burst=10.0)
        self._default_key_policy = default_key_policy or RatePolicy(rate_per_second=5.0, burst=5.0)
        self._global = _TokenBucket(self._global_policy)
        self._policies: dict[str, RatePolicy] = {}
        self._buckets: dict[str, _TokenBucket] = {}
        self._map_lock = asyncio.Lock()

    def set_policy(self, key: str, policy: RatePolicy) -> None:
        """Assign a custom policy to a key for future acquisitions."""
        normalized = key.strip().casefold()
        if not normalized:
            raise ValueError("rate key must not be empty")
        self._policies[normalized] = policy
        self._buckets.pop(normalized, None)

    async def acquire(self, key: str, *, cost: float = 1.0) -> None:
        """Acquire global and keyed capacity, propagating cancellation cleanly."""
        normalized = key.strip().casefold()
        if not normalized:
            raise ValueError("rate key must not be empty")
        try:
            await self._global.acquire(cost)
            bucket = await self._bucket(normalized)
            await bucket.acquire(cost)
        except asyncio.CancelledError:
            raise

    async def _bucket(self, key: str) -> _TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        async with self._map_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(self._policies.get(key, self._default_key_policy))
                self._buckets[key] = bucket
            return bucket

    def healthcheck(self) -> dict[str, object]:
        """Return current rate-governor configuration for pre-flight inspection."""
        return {
            "ok": True,
            "global_rps": self._global_policy.rate_per_second,
            "global_burst": self._global_policy.burst,
            "default_key_rps": self._default_key_policy.rate_per_second,
            "custom_policies": len(self._policies),
        }
