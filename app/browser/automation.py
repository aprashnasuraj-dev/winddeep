"""Scope-enforced Playwright browser automation routed through the capture proxy."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.security.audit import AuditLog
from app.security.rate_governor import RateGovernor
from app.security.scope import ScopeEnforcer, ScopeViolation


class BrowserAutomationError(RuntimeError):
    """Raised when browser automation cannot safely execute."""


@dataclass(slots=True)
class BrowserResult:
    """Normalized result from one browser navigation."""

    url: str
    title: str
    status: int | None
    final_url: str


class BrowserAutomationEngine:
    """Drive Chromium with scope interception and mandatory mitmproxy routing."""

    def __init__(
        self,
        *,
        scope: ScopeEnforcer,
        rate_governor: RateGovernor,
        audit: AuditLog,
        proxy_url: str = "http://127.0.0.1:8080",
        headless: bool = True,
    ) -> None:
        if not proxy_url.startswith(("http://127.0.0.1:", "http://localhost:", "http://[::1]:")):
            raise ValueError("browser proxy must be a local capture proxy")
        self.scope = scope
        self.rate_governor = rate_governor
        self.audit = audit
        self.proxy_url = proxy_url
        self.headless = headless
        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._context: Any | None = None

    async def start(self) -> None:
        """Start a Chromium context configured to use the local capture proxy."""
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserAutomationError("Playwright is not installed; run `playwright install chromium`") from exc
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.headless)
            self._context = await self._browser.new_context(proxy={"server": self.proxy_url})
            await self._context.route("**/*", self._route)
            self.audit.append("browser.started", {"proxy": self.proxy_url, "headless": self.headless})
        except asyncio.CancelledError:
            await self.close()
            raise
        except Exception:
            await self.close()
            raise

    async def _route(self, route: Any, request: Any) -> None:
        try:
            self.scope.assert_allowed(request.url)
            await self.rate_governor.acquire(urlsplit(request.url).hostname or "browser")
            await route.continue_()
        except ScopeViolation:
            self.audit.append("browser.request.blocked", {"url": request.url})
            await route.abort("blockedbyclient")
        except asyncio.CancelledError:
            await route.abort("aborted")
            raise

    async def open(self, url: str, *, wait_until: str = "networkidle", timeout_ms: int = 30_000) -> BrowserResult:
        """Navigate to an authorized URL and return normalized browser metadata."""
        self.scope.assert_allowed(url)
        if self._context is None:
            await self.start()
        assert self._context is not None
        page = await self._context.new_page()
        try:
            response = await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            title = await page.title()
            result = BrowserResult(url=url, title=title, status=response.status if response is not None else None, final_url=page.url)
            self.audit.append("browser.navigation", {"url": url, "final_url": page.url, "status": result.status})
            return result
        except asyncio.CancelledError:
            raise
        finally:
            await page.close()

    async def reflected_marker_check(
        self,
        url: str,
        *,
        parameter: str,
        marker: str,
        timeout_ms: int = 30_000,
    ) -> dict[str, object]:
        """Check whether an inert marker reaches rendered DOM text or markup.

        This is a browser-fidelity validation primitive rather than an exploit
        generator. Callers can use it to determine whether later manual review
        is warranted without automatically executing script payloads.
        """
        if not parameter.strip() or not marker:
            raise ValueError("parameter and marker are required")
        self.scope.assert_allowed(url)
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[parameter] = marker
        candidate = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
        self.scope.assert_allowed(candidate)
        if self._context is None:
            await self.start()
        assert self._context is not None
        page = await self._context.new_page()
        try:
            response = await page.goto(candidate, wait_until="networkidle", timeout=timeout_ms)
            content = await page.content()
            body_text = await page.locator("body").inner_text(timeout=timeout_ms)
            result = {
                "url": candidate,
                "status": response.status if response is not None else None,
                "marker_in_dom": marker in content,
                "marker_in_text": marker in body_text,
            }
            self.audit.append("browser.marker_check", result)
            return result
        except asyncio.CancelledError:
            raise
        finally:
            await page.close()

    async def close(self) -> None:
        """Close browser resources idempotently."""
        try:
            if self._context is not None:
                await self._context.close()
            if self._browser is not None:
                await self._browser.close()
            if self._playwright is not None:
                await self._playwright.stop()
        except asyncio.CancelledError:
            raise
        finally:
            self._context = None
            self._browser = None
            self._playwright = None
