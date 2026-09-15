# Windows Install Audit

Audit date: 2026-09-15  
QA branch: `release/qa-gate-v0.1.0`

Overall: **FAIL / BLOCKED BEFORE ARTIFACT BUILD**

The clean-Windows audit script is implemented at `scripts/audit/windows_install_audit.ps1`, but a production installer has **not** been built or certified from the current repository because the earlier fail-closed release phases correctly stop the pipeline first.

## What the script validates when the release reaches build stage

| Check | Required result |
|---|---|
| Windows platform | Windows 10/11 |
| Silent Inno install | exit code 0 |
| Installed executable | `{app}\Windeep.exe` exists |
| Installed metadata | `VERSION` exists |
| Bundled external tools | `{app}\tools` exists |
| Embedded runtime | `{app}\runtime\python\python.exe` exists |
| Installed app health | random loopback port `/api/health` returns `status=ok` and `localhost_only=true` |
| Silent uninstall | exit code 0 |
| Portable executable | `dist\Windeep\Windeep.exe` exists |
| Portable external tools | `dist\Windeep\tools` exists |
| Portable embedded runtime | `dist\Windeep\runtime\python\python.exe` exists |
| Portable app health | random loopback `/api/health` passes |

The QA branch also stages Playwright Chromium into `runtime\playwright-browsers`; the launcher points Playwright to that packaged location so a clean machine does not require an after-install browser download.

## Why the audit is currently blocked

1. Tool registry: 75 actual definitions vs 137 declared.
2. Five registry include files are missing.
3. `installer/tools-manifest.json` is empty, so the required `tools` tree cannot be produced reproducibly.
4. Full dashboard asset is absent.
5. 160 test packs are absent.
6. Production server does not expose the operational engine/tool/browser/capture/Brain paths.
7. Capture encrypted-at-rest persistence is not wired into the standalone capture path.
8. Phase A/B/F must therefore return FAIL/NO-GO before packaging.

## Result

No `Windeep-Setup.exe` is represented as release-certified by this report. This is intentional: the Windows audit must never be converted into a paper PASS when the build cannot meet the product and guardrail contract.
