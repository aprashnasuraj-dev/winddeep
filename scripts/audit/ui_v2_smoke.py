"""Playwright smoke audit for every primary Windeep v3 dashboard view.

The audit uses only a synthetic local target and a synthetic sleeping executable
for cancellation. It performs no network security scan.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
PORT = int(os.environ.get("WINDEEP_PORT", "7332"))
BASE = f"http://127.0.0.1:{PORT}"


def wait_text(page: Page, selector: str, needle: str, timeout: int = 10_000) -> None:
    page.locator(selector).filter(has_text=needle).first.wait_for(state="visible", timeout=timeout)


def main() -> int:
    tools_dir = ROOT / "tools"
    tools_dir.mkdir(exist_ok=True)
    fake = tools_dir / "assetfinder"
    previous = fake.read_bytes() if fake.exists() else None
    previous_mode = fake.stat().st_mode if fake.exists() else None
    fake.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(15)\nprint('late.example.test')\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    errors: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(accept_downloads=True)
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            page.goto(BASE, wait_until="networkidle", timeout=30_000)
            page.locator("#sessionState").filter(has_text="Local session protected").wait_for(timeout=15_000)
            assert "Windeep v3" in page.title()

            views = ["overview", "targets", "scans", "tools", "testpacks", "findings", "reports", "intelligence", "settings"]
            for view in views:
                page.locator(f'button[data-view="{view}"]').click()
                page.locator(f"#{view}.active").wait_for(state="visible")

            # Target CRUD and active-target propagation.
            page.locator('button[data-view="targets"]').click()
            page.locator("#targetName").fill("UI Smoke Domain")
            page.locator("#targetType").select_option("domain")
            page.locator("#targetValue").fill("example.test")
            page.locator("#targetScope").fill("example.test")
            page.locator("#targetNotes").fill("synthetic local UI smoke fixture")
            page.locator("#addTarget").click()
            wait_text(page, "#targetList", "UI Smoke Domain")
            wait_text(page, "#activeTargetPill", "UI Smoke Domain")

            # Tool matrix must render the complete catalog.
            page.locator('button[data-view="tools"]').click()
            page.wait_for_function("document.querySelectorAll('.tool-card').length === 137", timeout=15_000)
            assert page.locator(".tool-card").count() == 137

            # Signed consent, selected-tool execution, and process-level stop.
            page.locator('button[data-view="scans"]').click()
            page.locator("#authorizedBy").fill("ui-smoke")
            page.locator("#issueConsent").click()
            wait_text(page, "#consentState", "Consent")
            page.locator("#scanMode").select_option("selected")
            page.locator("#scanToolSelect").select_option(["assetfinder"])
            page.locator("#previewPlan").click()
            wait_text(page, "#scanPlan", "1 selected")
            with page.expect_response(
                lambda response: response.url.endswith("/api/v2/scans") and response.request.method == "POST",
                timeout=10_000,
            ) as response_info:
                page.locator("#startScan").click()
            scan_response = response_info.value
            if scan_response.status != 202:
                raise AssertionError(f"v2 scan start returned {scan_response.status}: {scan_response.text()}")
            payload = scan_response.json()
            assert int(payload["scan_id"]) > 0
            assert int(payload["plan"]["selected_count"]) == 1
            page.locator("[data-scan-stop]").first.wait_for(state="visible", timeout=10_000)
            page.locator("[data-scan-stop]").first.click()
            wait_text(page, "#scanList", "cancelled", timeout=10_000)

            # Test-pack UI and guarded execution surface.
            page.locator('button[data-view="testpacks"]').click()
            assert page.locator("[data-pack-select]").count() == 8
            page.locator("#runPack").click()
            wait_text(page, "#packStatus", "checks evaluated", timeout=10_000)

            # V3 finding views must exist even when the scan produced no findings.
            page.locator('button[data-view="findings"]').click()
            page.locator("#refreshFindings").click()
            page.locator("#findingList").wait_for(state="visible")
            page.locator("#v3FindingTabs").wait_for(state="visible", timeout=10_000)
            for tab in ("actionable", "needs-review", "not-actionable"):
                page.locator(f'#v3FindingTabs button[data-v3-tab="{tab}"]').wait_for(state="visible")

            # V3 report renders directly from the authorized scan and states the all-findings contract.
            page.locator('button[data-view="reports"]').click()
            page.locator("#reportTitle").fill("UI smoke v3 report")
            page.locator("#generateReport").click()
            wait_text(page, "#reportPreview", "Windeep v3 scan report", timeout=10_000)
            wait_text(page, "#reportPreview", "Every normalized finding from this scan is included", timeout=10_000)
            wait_text(page, "#reportPreview", "Findings", timeout=10_000)

            # Intelligence and settings surfaces must remain functional.
            page.locator('button[data-view="intelligence"]').click()
            page.locator("#refreshIntelligence").click()
            page.locator("#intelSummary").wait_for(state="visible")
            page.locator('button[data-view="settings"]').click()
            page.locator("#globalRps").fill("4")
            page.locator("#saveSettings").click()
            wait_text(page, "#settingsState", "saved", timeout=10_000)

            # Return to overview and ensure product status stayed healthy.
            page.locator('button[data-view="overview"]').click()
            wait_text(page, "#sessionState", "Local session protected")
            assert not errors, f"browser page errors: {errors}"
            browser.close()
    finally:
        if previous is None:
            fake.unlink(missing_ok=True)
        else:
            fake.write_bytes(previous)
            if previous_mode is not None:
                fake.chmod(previous_mode)
    print("Windeep v3 UI smoke audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
