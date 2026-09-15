# Windows Install Audit

Audit date: 2026-09-15  
Audited branch: `main`

Overall: **FAIL / BLOCKED BEFORE ARTIFACT BUILD**

The clean-Windows audit implementation is complete at `scripts/audit/windows_install_audit.ps1`, but no installer is represented as release-certified from the current repository because the earlier fail-closed gates stop the release before packaging.

## What the clean-machine audit now validates

| Check | Required result |
|---|---|
| Windows platform | Windows 10/11 |
| Silent Inno install | exit code 0 |
| Installed executable | `{app}\Windeep.exe` exists |
| Exact release identity | installed and portable `VERSION` equal repository `VERSION` |
| Registry payload | installed and portable `tools_config.json` exists |
| External tools | `tools` directory exists and every manifest-declared safe probe passes |
| Embedded Python | `runtime\python\python.exe --version` succeeds and reports Python 3.11.x |
| Browser runtime | `runtime\playwright-browsers` contains staged browser files |
| Installed app health | random loopback `/api/health` returns `status=ok` and `localhost_only=true` |
| Listener binding | Windeep process listens only on `127.0.0.1` / `::1` for the audit port |
| Silent uninstall | exit code 0 |
| Uninstall cleanup | installed `Windeep.exe` is removed |
| Portable executable | `dist\Windeep\Windeep.exe` exists |
| Portable runtime/tools | same runtime, browser and tool-probe checks pass |
| Portable app health | random loopback `/api/health` passes |

The audit starts no target scan. Tool checks use only the non-invasive liveness probes declared in `installer/tools-manifest.json`.

## Why execution is currently blocked

1. Root registry declares 137 tools, but only 75 definitions exist.
2. Five tool category registry files are missing.
3. `installer/tools-manifest.json` is empty, and the hardened setup script now correctly rejects an empty production manifest.
4. Full desktop dashboard asset is absent.
5. 160 test packs are absent.
6. The operational server/API path is incomplete.
7. Secure persistence is not yet certified on the complete operational capture path.
8. Phase A/B/F therefore remain NO-GO before `Windeep-Setup.exe` is built.

## Result

No `Windeep-Setup.exe` or `Windeep-Portable.zip` is currently claimed as release-certified. This is intentional: a clean-machine audit must test the real packaged product, not convert missing product assets into a paper PASS.
