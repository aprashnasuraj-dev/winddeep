"""Additional browser lifecycle coverage for the release gate."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from app.browser.automation import BrowserAutomationEngine
from app.security.audit import AuditLog
from app.security.rate_governor import RateGovernor, RatePolicy
from app.security.scope import ScopeEnforcer


def _engine(tmp_path: Path) -> BrowserAutomationEngine:
    return BrowserAutomationEngine(
        scope=ScopeEnforcer("example.com", allow=["example.com", "*.example.com"]),
        rate_governor=RateGovernor(global_policy=RatePolicy(100, 20), default_key_policy=RatePolicy(100, 20)),
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )


@pytest.mark.asyncio
async def test_start_and_close_use_local_proxy_and_route(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    events: list[object] = []

    class Context:
        async def route(self, pattern, callback):
            events.append((pattern, callback))
        async def close(self):
            events.append("context-close")

    class Browser:
        async def new_context(self, **kwargs):
            events.append(kwargs)
            return Context()
        async def close(self):
            events.append("browser-close")

    class Chromium:
        async def launch(self, **kwargs):
            events.append(kwargs)
            return Browser()

    class Playwright:
        chromium = Chromium()
        async def stop(self):
            events.append("playwright-stop")

    class Manager:
        async def start(self):
            return Playwright()

    fake = types.ModuleType("playwright.async_api")
    fake.async_playwright = lambda: Manager()
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake)

    engine = _engine(tmp_path)
    await engine.start()
    assert any(isinstance(value, dict) and value.get("proxy", {}).get("server") == "http://127.0.0.1:8080" for value in events)
    assert any(isinstance(value, tuple) and value[0] == "**/*" for value in events)
    assert engine.audit.verify_chain()[1] == 1

    await engine.close()
    assert "context-close" in events
    assert "browser-close" in events
    assert "playwright-stop" in events
    assert engine._context is None and engine._browser is None and engine._playwright is None
    await engine.close()


@pytest.mark.asyncio
async def test_reflected_marker_check_is_inert_and_normalized(tmp_path: Path) -> None:
    engine = _engine(tmp_path)

    class Response:
        status = 200

    class Locator:
        async def inner_text(self, *, timeout: int):
            assert timeout == 1234
            return "hello QA-MARKER"

    class Page:
        closed = False
        async def goto(self, url: str, *, wait_until: str, timeout: int):
            assert "probe=QA-MARKER" in url
            assert wait_until == "networkidle"
            assert timeout == 1234
            return Response()
        async def content(self):
            return "<html><body>QA-MARKER</body></html>"
        def locator(self, selector: str):
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
        "https://example.com/search?existing=1",
        parameter="probe",
        marker="QA-MARKER",
        timeout_ms=1234,
    )
    assert result["status"] == 200
    assert result["marker_in_dom"] is True
    assert result["marker_in_text"] is True
    assert "existing=1" in str(result["url"])
    assert page.closed is True
    assert engine.audit.verify_chain()[1] == 1

    with pytest.raises(ValueError):
        await engine.reflected_marker_check("https://example.com/", parameter=" ", marker="x")
    with pytest.raises(ValueError):
        await engine.reflected_marker_check("https://example.com/", parameter="q", marker="")


@pytest.mark.asyncio
async def test_open_handles_no_response_status(tmp_path: Path) -> None:
    engine = _engine(tmp_path)

    class Page:
        url = "https://example.com/end"
        async def goto(self, *args, **kwargs):
            return None
        async def title(self):
            return "No content"
        async def close(self):
            pass

    class Context:
        async def new_page(self):
            return Page()

    engine._context = Context()
    result = await engine.open("https://example.com/start")
    assert result.status is None
    assert result.title == "No content"
