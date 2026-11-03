"""Headless V6 dashboard stress and reconnect qualification.

The harness launches only the local Windeep server, creates a synthetic running
scan in its private state directory, and uses Playwright against loopback. It
does not contact or scan any external target.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

from app.security.crypto import CryptoManager
from app.security.secure_database import SecureDatabase


ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_health(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"local Windeep server did not become healthy: {last}")


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return float(ordered[index])


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    from playwright.async_api import async_playwright

    temp = tempfile.TemporaryDirectory(prefix="windeep-v6-browser-")
    state = Path(temp.name) / "state"
    state.mkdir(parents=True, exist_ok=True)
    crypto = CryptoManager(wrapped_key_path=state / "crypto" / "dek.bin")
    database = SecureDatabase(state / "windeep.db", crypto=crypto)
    target_id = database.create_target(
        "v6-local-ui-fixture",
        "domain",
        "fixture.local",
        scope=["fixture.local"],
        out_of_scope=[],
    )
    scan_id = database.create_scan(target_id, "v6:ui-stress", ["synthetic"])
    database.update_scan(
        scan_id,
        status="running",
        progress=15.0,
        results_summary={
            "runtime": {
                "phase": "heartbeat",
                "completed_tasks": 1,
                "total_tasks": 10,
                "running_tasks": [{"tool": "synthetic", "task": "synthetic", "elapsed_seconds": 1.0}],
                "last_event_at": time.time(),
            }
        },
    )

    port = args.port or _free_port()
    env = dict(os.environ)
    env.update(
        {
            "WINDEEP_STATE_DIR": str(state),
            "WINDEEP_PORT": str(port),
            "WINDEEP_UI": "server",
            "WINDEEP_NO_BROWSER": "1",
            "PYTHONPATH": str(ROOT),
            "PYTHONUNBUFFERED": "1",
        }
    )
    server_log = ROOT / Path(args.output).with_suffix(".server.log")
    server_log.parent.mkdir(parents=True, exist_ok=True)
    log_handle = server_log.open("w", encoding="utf-8")
    server = subprocess.Popen(
        [sys.executable, "launcher.py", "server"],
        cwd=ROOT,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )

    console_errors: list[str] = []
    request_failures: list[str] = []
    reconcile_seconds: list[float] = []
    nav_latency_ms: list[float] = []
    max_fetches_per_burst = 0
    cycles = 0
    browser = None
    try:
        base = f"http://127.0.0.1:{port}"
        _wait_health(f"{base}/api/health")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("requestfailed", lambda req: request_failures.append(req.url))
            await page.goto(base, wait_until="domcontentloaded", timeout=30_000)
            await page.wait_for_function(
                "() => document.getElementById('sessionState')?.textContent.includes('Local session protected')",
                timeout=30_000,
            )
            card = page.locator(f'[data-scan-id="{scan_id}"]')
            await card.wait_for(state="visible", timeout=30_000)
            if "15%" not in await card.inner_text():
                raise AssertionError("initial durable scan state did not render")

            available = await page.evaluate("() => typeof scheduleUiRefresh === 'function'")
            if not available:
                raise AssertionError("dashboard refresh coalescer is not available")

            await page.evaluate(
                """() => {
                    window.__v6FetchCount = 0;
                    const original = window.fetch.bind(window);
                    window.fetch = (...args) => {
                        window.__v6FetchCount += 1;
                        return original(...args);
                    };
                }"""
            )

            deadline = time.monotonic() + float(args.duration_seconds)
            while time.monotonic() < deadline:
                cycles += 1
                before = int(await page.evaluate("() => window.__v6FetchCount || 0"))
                await page.evaluate(
                    """(count) => {
                        for (let i = 0; i < count; i += 1) {
                            scheduleUiRefresh({scans:true, findings:true, overview:true});
                        }
                    }""",
                    int(args.events_per_cycle),
                )

                nav = page.locator("#nav button").first
                started = time.perf_counter()
                await nav.click(timeout=2_000)
                nav_latency_ms.append((time.perf_counter() - started) * 1000.0)
                await page.wait_for_timeout(2200)
                after = int(await page.evaluate("() => window.__v6FetchCount || 0"))
                max_fetches_per_burst = max(max_fetches_per_burst, after - before)
                if after - before > args.max_fetches_per_burst:
                    raise AssertionError(
                        f"UI refresh storm was not bounded: {after - before} fetches "
                        f"for {args.events_per_cycle} scheduled refresh events"
                    )

                progress = min(95.0, 15.0 + cycles * 7.0)
                await context.set_offline(True)
                database.update_scan(
                    scan_id,
                    status="running",
                    progress=progress,
                    results_summary={
                        "runtime": {
                            "phase": "heartbeat",
                            "completed_tasks": min(9, cycles + 1),
                            "total_tasks": 10,
                            "running_tasks": [
                                {
                                    "tool": "synthetic",
                                    "task": "synthetic",
                                    "elapsed_seconds": float(cycles * 5),
                                }
                            ],
                            "last_event_at": time.time(),
                        }
                    },
                )
                await page.wait_for_timeout(900)
                await context.set_offline(False)
                reconcile_started = time.perf_counter()
                await page.wait_for_function(
                    """({scanId, expected}) => {
                        const card = document.querySelector('[data-scan-id="' + scanId + '"]');
                        return card && card.textContent.includes(String(Math.round(expected)) + '%');
                    }""",
                    {"scanId": scan_id, "expected": progress},
                    timeout=15_000,
                )
                reconcile_seconds.append(time.perf_counter() - reconcile_started)

                remaining = deadline - time.monotonic()
                if remaining > 0:
                    await page.wait_for_timeout(int(min(5.0, remaining) * 1000))

            database.update_scan(
                scan_id,
                status="completed",
                progress=100.0,
                finished_at=time.time(),
                results_summary={
                    "runtime": {
                        "phase": "finished",
                        "completed_tasks": 10,
                        "total_tasks": 10,
                        "running_tasks": [],
                        "last_event_at": time.time(),
                    }
                },
            )
            await page.evaluate("() => scheduleUiRefresh({scans:true, findings:true, overview:true})")
            await page.wait_for_function(
                """(scanId) => {
                    const card = document.querySelector('[data-scan-id="' + scanId + '"]');
                    return card && card.textContent.includes('100%') && card.textContent.includes('completed');
                }""",
                scan_id,
                timeout=20_000,
            )
            screenshot = ROOT / args.screenshot
            screenshot.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(screenshot), full_page=True)

            if nav_latency_ms and _percentile(nav_latency_ms, 0.95) > args.max_nav_p95_ms:
                raise AssertionError(
                    f"navigation P95 {_percentile(nav_latency_ms, 0.95):.1f} ms "
                    f"exceeded {args.max_nav_p95_ms:.1f} ms"
                )
            if reconcile_seconds and max(reconcile_seconds) > args.max_reconcile_seconds:
                raise AssertionError(
                    f"durable reconciliation took {max(reconcile_seconds):.2f}s "
                    f"(limit {args.max_reconcile_seconds:.2f}s)"
                )

            await browser.close()
            browser = None

        return {
            "schema": "windeep.v6.browser-stress.v1",
            "duration_seconds": float(args.duration_seconds),
            "cycles": cycles,
            "events_per_cycle": int(args.events_per_cycle),
            "scheduled_refresh_events": int(cycles * args.events_per_cycle),
            "max_fetches_per_burst": max_fetches_per_burst,
            "navigation_latency_ms": {
                "p50": round(_percentile(nav_latency_ms, 0.50), 2),
                "p95": round(_percentile(nav_latency_ms, 0.95), 2),
                "max": round(max(nav_latency_ms) if nav_latency_ms else 0.0, 2),
            },
            "reconcile_seconds": {
                "p50": round(_percentile(reconcile_seconds, 0.50), 3),
                "p95": round(_percentile(reconcile_seconds, 0.95), 3),
                "max": round(max(reconcile_seconds) if reconcile_seconds else 0.0, 3),
            },
            "console_error_count": len(console_errors),
            "request_failure_count": len(request_failures),
            "terminal_state_verified": True,
            "server_log": str(server_log.relative_to(ROOT)),
            "decision": "GO",
        }
    finally:
        if browser is not None:
            with contextlib.suppress(Exception):
                await browser.close()
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        log_handle.close()
        temp.cleanup()


async def main_async() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration-seconds", type=float, default=90.0)
    parser.add_argument("--events-per-cycle", type=int, default=1000)
    parser.add_argument("--max-fetches-per-burst", type=int, default=40)
    parser.add_argument("--max-nav-p95-ms", type=float, default=1000.0)
    parser.add_argument("--max-reconcile-seconds", type=float, default=15.0)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--output", default="reports/v6_browser_stress.json")
    parser.add_argument("--screenshot", default="reports/v6_browser_stress.png")
    args = parser.parse_args()
    if args.duration_seconds <= 0:
        raise ValueError("duration must be positive")
    if args.events_per_cycle < 1000:
        raise ValueError("events_per_cycle must be >= 1000")
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = await _run(args)
    except Exception as exc:
        payload = {
            "schema": "windeep.v6.browser-stress.v1",
            "decision": "NO-GO",
            "error": str(exc),
        }
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
