"""Tests for the Windeep async event bus."""

from __future__ import annotations

import asyncio

import pytest

from app.engine.event_bus import EventBus


@pytest.mark.asyncio
async def test_exact_subscription_receives_event() -> None:
    bus = EventBus(heartbeat_interval=60)
    stream = bus.subscribe("scan.progress")
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await bus.publish("scan.progress", {"progress": 25})
    event = await asyncio.wait_for(pending, 1)
    assert event.topic == "scan.progress"
    assert event.payload["progress"] == 25
    await stream.aclose()
    await bus.close()


@pytest.mark.asyncio
async def test_wildcard_subscription_matches_topic_family() -> None:
    bus = EventBus(heartbeat_interval=60)
    stream = bus.subscribe("tool.*")
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await bus.publish("tool.started", {"tool": "demo"})
    event = await asyncio.wait_for(pending, 1)
    assert event.topic == "tool.started"
    await stream.aclose()
    await bus.close()


@pytest.mark.asyncio
async def test_unrelated_topics_do_not_cross_deliver() -> None:
    bus = EventBus(heartbeat_interval=60)
    stream = bus.subscribe("finding.*")
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await bus.publish("scan.progress", {"progress": 10})
    await asyncio.sleep(0.02)
    assert not pending.done()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    await stream.aclose()
    await bus.close()


@pytest.mark.asyncio
async def test_heartbeat_is_emitted() -> None:
    bus = EventBus(heartbeat_interval=0.01)
    stream = bus.subscribe("log.*")
    event = await asyncio.wait_for(anext(stream), 0.2)
    assert event.topic == "log.heartbeat"
    assert event.payload == {"kind": "heartbeat"}
    await stream.aclose()
    await bus.close()


@pytest.mark.asyncio
async def test_slow_subscriber_queue_drops_oldest_event() -> None:
    bus = EventBus(queue_size=1, heartbeat_interval=60)
    stream = bus.subscribe("scan.*")
    first = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await bus.publish("scan.progress", {"progress": 1})
    assert (await first).payload["progress"] == 1
    await bus.publish("scan.progress", {"progress": 2})
    await bus.publish("scan.progress", {"progress": 3})
    assert (await asyncio.wait_for(anext(stream), 1)).payload["progress"] == 3
    await stream.aclose()
    await bus.close()


@pytest.mark.asyncio
async def test_v6_backpressure_metrics_remain_bounded_under_10k_event_burst() -> None:
    bus = EventBus(queue_size=32, heartbeat_interval=60)
    stream = bus.subscribe("scan.*")
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    await bus.publish("scan.progress", {"seq": -1})
    await pending

    for index in range(10_000):
        await bus.publish("scan.progress", {"seq": index})

    stats = await bus.stats()
    assert stats["queue_size"] == 32
    assert stats["published_events"] == 10_001
    assert stats["dropped_events"] > 0
    assert stats["subscribers"] == 1

    # Loss-tolerant backpressure must retain the newest state, not stale history.
    newest = None
    while True:
        try:
            newest = await asyncio.wait_for(anext(stream), timeout=0.01)
        except asyncio.TimeoutError:
            break
    assert newest is not None
    assert newest.payload["seq"] == 9_999
    await stream.aclose()
    await bus.close()


@pytest.mark.asyncio
async def test_invalid_topic_root_is_rejected() -> None:
    bus = EventBus(heartbeat_interval=60)
    with pytest.raises(ValueError):
        await bus.publish("unknown.event", {})
    await bus.close()
