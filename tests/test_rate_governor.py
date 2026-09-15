"""Tests for asynchronous Windeep token-bucket governance."""

from __future__ import annotations

import asyncio
import time

import pytest

from app.security.rate_governor import RateGovernor, RatePolicy


def test_rate_policy_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        RatePolicy(rate_per_second=0, burst=1)


def test_rate_policy_rejects_small_burst() -> None:
    with pytest.raises(ValueError):
        RatePolicy(rate_per_second=1, burst=0.5)


@pytest.mark.asyncio
async def test_burst_capacity_is_immediate() -> None:
    governor = RateGovernor(global_policy=RatePolicy(100, 10), default_key_policy=RatePolicy(100, 3))
    started = time.monotonic()
    await governor.acquire("tool")
    await governor.acquire("tool")
    await governor.acquire("tool")
    assert time.monotonic() - started < 0.1


@pytest.mark.asyncio
async def test_custom_policy_delays_after_burst() -> None:
    governor = RateGovernor(global_policy=RatePolicy(100, 10), default_key_policy=RatePolicy(100, 10))
    governor.set_policy("slow", RatePolicy(rate_per_second=20, burst=1))
    await governor.acquire("slow")
    started = time.monotonic()
    await governor.acquire("slow")
    assert time.monotonic() - started >= 0.04


@pytest.mark.asyncio
async def test_wait_is_cancellable() -> None:
    governor = RateGovernor(global_policy=RatePolicy(100, 10), default_key_policy=RatePolicy(1, 1))
    await governor.acquire("slow")
    task = asyncio.create_task(governor.acquire("slow"))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
