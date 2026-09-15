"""Additional lifecycle coverage for the guarded Playwright adapter."""

from __future__ import annotations

import asyncio

import pytest

from app.browser.automation import BrowserAutomationEngine
from app.security.audit import AuditLog
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer


def _engine(tmp_path) -> BrowserAutomationEngine:
    return BrowserAutomationEngine(
        scope=ScopeEnforcer("example.com", allow=["example.com", "*.example.com"]),
        rate_governor=RateGovernor(global_policy=RatePolicy(100, 20), default_key_policy=RatePolicy(100, 20)),
        audit=AuditLog(tmp_path / "browser-audit.jsonl"),
    )


@pytest.mark.asyncio
async def test_start_wires_local_proxy_and_route(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path)
    calls: dict[str, object] = {}

    class Context:
        async def route(self, pattern, handler):
            calls["pattern"] = pattern
            calls["handler"] = handler

        async def close(self):
            calls["context_closed"] = True

    context = Context()

    class Browser:
        async def new_context(self, *, proxy):
            calls["proxy"] = proxy
            return context

        async def close(self):
            calls["browser_closed"] = True

    browser = Browser()

    class Chromium:
        async def launch(self, *, headless):
            calls["headless"] = headless
            return browser

    class PlaywrightSession:
        chromium = Chromium()

        async def stop(self):
            calls["playwright_stopped"] = True

    playwright_session = PlaywrightSession()

    class Starter:
        async def start(self):
            return playwright_session

    from playwright import async_api as playwright_async_api

    monkeypatch.setattr(playwright_async_api, "async_playwright", lambda: Starter())
    await engine.start()
    assert calls["proxy"] == {"server": "http://127.0.0.1:8080"}
    assert calls["pattern"] == "**/*"
    assert calls["headless"] is True
    await engine.close()
    assert calls["context_closed"] is True
    assert calls["browser_closed"] is True
    assert calls["playwright_stopped"] is True
    assert engine._context is None and engine._browser is None and engine._playwright is None


@pytest.mark.asyncio
async def test_marker_check_builds_inert_candidate_and_closes_page(tmp_path) -> None:
    engine = _engine(tmp_path)

    class Response:
        status = 200

    class Locator:
        async def inner_text(self, *, timeout):
            assert timeout == 1234
            return "SAFE MARKER rendered"

    class Page:
        url = "https://example.com/search"
        closed = False
        visited = ""

        async def goto(self, url, *, wait_until, timeout):
            self.visited = url
            assert wait_until == "networkidle"
            assert timeout == 1234
            return Response()

        async def content(self):
            return "<html>SAFE MARKER rendered</html>"

        def locator(self, selector):
            assert selector == "body"
            return Locator()

        async def close(self):
            self.closed = True

    page = Page()

    class Context:
        async def new_page(self):
            return page

    engine._context = Context()
    result = await engine.reflected_marker_check(
        "https://example.com/search?existing=1#frag",
        parameter="q",
        marker="SAFE MARKER",
        timeout_ms=1234,
    )
    assert "existing=1" in page.visited
    assert "q=SAFE+MARKER" in page.visited
    assert page.visited.endswith("#frag")
    assert result["marker_in_dom"] is True
    assert result["marker_in_text"] is True
    assert page.closed is True


@pytest.mark.asyncio
async def test_marker_check_rejects_missing_inputs(tmp_path) -> None:
    engine = _engine(tmp_path)
    with pytest.raises(ValueError):
        await engine.reflected_marker_check("https://example.com", parameter="", marker="x")
    with pytest.raises(ValueError):
        await engine.reflected_marker_check("https://example.com", parameter="q", marker="")


@pytest.mark.asyncio
async def test_route_aborts_when_rate_wait_is_cancelled(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path)

    async def cancelled(_key):
        raise asyncio.CancelledError()

    monkeypatch.setattr(engine.rate_governor, "acquire", cancelled)

    class Route:
        reason = None

        async def continue_(self):
            raise AssertionError("request must not continue")

        async def abort(self, reason):
            self.reason = reason

    class Request:
        url = "https://example.com/resource.js"

    route = Route()
    with pytest.raises(asyncio.CancelledError):
        await engine._route(route, Request())
    assert route.reason == "aborted"


@pytest.mark.asyncio
async def test_close_is_idempotent_with_no_resources(tmp_path) -> None:
    engine = _engine(tmp_path)
    await engine.close()
    await engine.close()
