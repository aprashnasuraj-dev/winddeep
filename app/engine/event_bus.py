"""Async in-process publish/subscribe event bus for Windeep.

The bus is intentionally transport-agnostic. HTTP SSE and WebSocket adapters
can consume subscriptions without coupling scanners, tools, or the AI layer to
Flask. Wildcard matching uses shell-style patterns such as ``scan.*``.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

_ALLOWED_ROOTS = frozenset({"scan", "tool", "finding", "log", "flow", "brain", "report"})


@dataclass(frozen=True, slots=True)
class Event:
    """Immutable event delivered to subscribers."""

    id: str
    topic: str
    payload: dict[str, Any]
    timestamp: float


class EventBus:
    """Fan-out async event bus with wildcard subscriptions and heartbeats."""

    def __init__(self, *, queue_size: int = 512, heartbeat_interval: float = 30.0) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be >= 1")
        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be > 0")
        self._queue_size = queue_size
        self._heartbeat_interval = heartbeat_interval
        self._subscriptions: dict[str, set[asyncio.Queue[Event]]] = {}
        self._lock = asyncio.Lock()
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._closed = False

    @staticmethod
    def _validate_topic(topic: str, *, allow_wildcard: bool = False) -> None:
        if not topic or "." not in topic:
            raise ValueError("topic must use '<root>.<name>' form")
        root = topic.split(".", 1)[0]
        if root not in _ALLOWED_ROOTS:
            raise ValueError(f"unsupported topic root: {root}")
        if not allow_wildcard and any(char in topic for char in "*?["):
            raise ValueError("published topics cannot contain wildcard characters")

    async def start(self) -> None:
        """Start the heartbeat task if it is not already running."""
        if self._closed:
            raise RuntimeError("event bus is closed")
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="windeep-event-heartbeat")

    async def close(self) -> None:
        """Stop heartbeats and mark the bus closed."""
        self._closed = True
        task = self._heartbeat_task
        self._heartbeat_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        async with self._lock:
            self._subscriptions.clear()

    async def publish(self, topic: str, payload: Mapping[str, Any] | None = None) -> Event:
        """Publish an event to every exact/wildcard subscription that matches."""
        if self._closed:
            raise RuntimeError("event bus is closed")
        self._validate_topic(topic)
        event = Event(
            id=uuid.uuid4().hex,
            topic=topic,
            payload=dict(payload or {}),
            timestamp=time.time(),
        )
        async with self._lock:
            queues = {
                queue
                for pattern, subscribers in self._subscriptions.items()
                if fnmatch.fnmatchcase(topic, pattern)
                for queue in subscribers
            }

        for queue in queues:
            self._put_loss_tolerant(queue, event)
        return event

    async def subscribe(self, topic: str) -> AsyncIterator[Event]:
        """Yield events matching an exact topic or wildcard pattern.

        Slow consumers do not block producers. If a subscriber queue fills, the
        oldest pending event is dropped so the stream remains live and bounded.
        """
        if self._closed:
            raise RuntimeError("event bus is closed")
        self._validate_topic(topic, allow_wildcard=True)
        await self.start()
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        async with self._lock:
            self._subscriptions.setdefault(topic, set()).add(queue)
        try:
            while True:
                try:
                    yield await queue.get()
                except asyncio.CancelledError:
                    raise
        finally:
            async with self._lock:
                subscribers = self._subscriptions.get(topic)
                if subscribers is not None:
                    subscribers.discard(queue)
                    if not subscribers:
                        self._subscriptions.pop(topic, None)

    async def subscriber_count(self) -> int:
        """Return the number of currently registered subscription queues."""
        async with self._lock:
            return sum(len(queues) for queues in self._subscriptions.values())

    @staticmethod
    def _put_loss_tolerant(queue: asyncio.Queue[Event], event: Event) -> None:
        try:
            queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass
        with contextlib.suppress(asyncio.QueueEmpty):
            queue.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(event)

    async def _heartbeat_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._heartbeat_interval)
                await self.publish("log.heartbeat", {"kind": "heartbeat"})
        except asyncio.CancelledError:
            raise


DEFAULT_EVENT_BUS = EventBus()
