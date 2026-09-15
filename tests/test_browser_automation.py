"""Tests for scope-enforced Windeep browser automation policy."""

from __future__ import annotations

import pytest

from app.browser.automation import BrowserAutomationEngine
from app.security.audit import AuditLog
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer, ScopeViolation


def _engine(tmp_path, **kwargs) -> BrowserAutomationEngine:
    return BrowserAutomationEngine(
        scope=ScopeEnforcer("example.com", allow=["example.com", "*.example.com"]),
        rate_governor=RateGovernor(global_policy=RatePolicy(100, 20), default_key_policy=RatePolicy(100, 20)),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        **kwargs,
    )


def test_non_local_proxy_is_rejected(tmp_path) -> None:
    with pytest.raises(ValueError):
        _engine(tmp_path, proxy_url="http://proxy.example.com:8080")


def test_open_rejects_out_of_scope_before_browser_start(tmp_path) -> None:
    engine = _engine(tmp_path)
    with pytest.raises(ScopeViolation):
        import asyncio
        asyncio.run(engine.open("https://outside.test"))


@pytest.mark.asyncio
async def test_allowed_route_continues(tmp_path) -> None:
    engine = _engine(tmp_path)

    class Route:
        continued = False
        aborted = False

        async def continue_(self) -> None:
            self.continued = True

        async def abort(self, reason: str) -> None:
            self.aborted = True

    class Request:
        url = "https://api.example.com/script.js"

    route = Route()
    await engine._route(route, Request())
    assert route.continued is True
    assert route.aborted is False


@pytest.mark.asyncio
async def test_out_of_scope_subresource_is_aborted(tmp_path) -> None:
    engine = _engine(tmp_path)

    class Route:
        continued = False
        aborted = False
        reason = ""

        async def continue_(self) -> None:
            self.continued = True

        async def abort(self, reason: str) -> None:
            self.aborted = True
            self.reason = reason

    class Request:
        url = "https://tracker.outside.test/pixel"

    route = Route()
    await engine._route(route, Request())
    assert route.aborted is True
    assert route.reason == "blockedbyclient"
    assert engine.audit.verify_chain()[1] == 1


@pytest.mark.asyncio
async def test_open_uses_existing_context_and_closes_page(tmp_path) -> None:
    engine = _engine(tmp_path)

    class Response:
        status = 204

    class Page:
        url = "https://example.com/final"
        closed = False

        async def goto(self, url: str, *, wait_until: str, timeout: int):
            assert url == "https://example.com/start"
            return Response()

        async def title(self) -> str:
            return "Example"

        async def close(self) -> None:
            self.closed = True

    page = Page()

    class Context:
        async def new_page(self):
            return page

    engine._context = Context()
    result = await engine.open("https://example.com/start")
    assert result.status == 204
    assert result.final_url == "https://example.com/final"
    assert page.closed is True
