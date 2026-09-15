# Windeep Phase A — Static Release Audit

Audit date: 2026-09-15  
Audited baseline: `main` at `7188586ea8462d440bc2278654dc9a364699ba1c`  
QA branch: `release/qa-gate-v0.1.0`

## Decision

**FAIL — release is NO-GO.**

The core libraries contain substantial implemented code, but the repository does not yet represent the complete Windows desktop product described by the project blueprint/README. The release workflow added on the QA branch deliberately fails closed until the blockers below are resolved.

## Module completeness matrix

| Area | Files / capability reviewed | Status | Release finding |
|---|---|---|---|
| Local server / auth bootstrap | `app/server.py`, `app/security/auth.py` | PARTIAL | Local-only binding, protected session and CSRF are implemented. The production server currently exposes bootstrap/health/handshake/consent/preflight/session routes but not the operational dashboard/scanning APIs. |
| Scope / consent / rate / audit / crypto | `scope.py`, `consent.py`, `rate_governor.py`, `audit.py`, `crypto.py`, `preflight.py` | IMPLEMENTED | Strong primitives exist: deny-wins scope, signed consent, bounded rates, audit logging, AES-256-GCM and Windows DPAPI. End-to-end enforcement cannot be certified because the operational scan path is not wired into the production server. |
| Engine | `event_bus.py`, `scheduler.py`, `scan_context.py`, `tool_wrapper.py` | IMPLEMENTED-BUT-UNWIRED | Scheduler requires `PreFlightGuard`; event bus and wrapper framework are implemented. No production server route constructs/executes this pipeline. |
| Database | `database.py`, `migrations.py`, `app/data/migrations/0001_p1_operational_tables.sql` | IMPLEMENTED | SQLite CRUD, CVSS/deduplication, forward-only checksummed migrations and backup logic exist. Operational server wiring is absent. |
| Encrypted persistence | `secure_database.py`, `secure_flow_database.py` | IMPLEMENTED-BUT-UNWIRED | Encrypted finding/flow storage exists, but standalone capture currently constructs plaintext `Database`/`FlowDatabase`; encryption-at-rest is therefore not guaranteed on the shipped capture path. |
| Capture / replay | `flow_database.py`, `interceptor.py`, `mitm_addon.py`, `replay_client.py` | PARTIAL | Replay and interceptor fail closed on scope. QA branch fixes unresolved-target HTTP/WS capture so it is no longer persisted. Remaining blocker: encrypted storage and production target resolver are not wired. |
| Browser automation | `app/browser/automation.py` | IMPLEMENTED-BUT-UNWIRED | Scope/rate/audit controls exist. Clean-machine Chromium runtime was missing; QA branch now stages Playwright Chromium under `runtime/playwright-browsers`. No production server/UI path invokes it. |
| Authentication assurance | `app/auth/protocols.py`, `session_analysis.py`, `suite.py` | IMPLEMENTED-BUT-UNWIRED | 50 guarded auth techniques exist. These are not the promised 160 test packs and are not exposed through the shipped server/UI. |
| AI Brain | `budget.py`, `chain_builder.py`, `finding_ranker.py`, `hypothesis_engine.py`, `llm_client.py`, `memory.py`, `prompt_guard.py`, `prompts.py`, `self_critic.py` | IMPLEMENTED-BUT-UNWIRED | Public Brain API and prompt-injection defenses exist. No production server/UI integration. Historical `github_models` provider is retained only as a compatibility key and is explicitly treated as retired unless a custom endpoint is supplied. |
| Program scope import | `app/programs/scope_importer.py` | IMPLEMENTED-BUT-UNWIRED | Parser/import subsystem exists; no production dashboard route exposes it. |
| Duplicate/submission support | `app/duplicates.py`, `app/submissions.py` | IMPLEMENTED-BUT-UNWIRED | Local/external duplicate helpers and submission state machine exist. No shipped UI/API integration. |
| Tool wrappers | `app/engine/tool_wrapper.py` + JSON registries | FAIL | Root registry declares 137 tools, but only 75 definitions are present because five declared registry files are missing. Wrapper scope validation is conditional on construction with a validator, so production wiring must guarantee the guarded scheduler path. |
| Test packs | expected `app/modules/test_packs.py` / 160 tests | MISSING | No 160-test HunterTest pack implementation or API is present. |
| Dashboard UI | expected `app/static/index.html` | MISSING | Full desktop dashboard is absent. `app/server.py` serves a minimal bootstrap page only. |
| Windows packaging | `Windeep.spec`, Inno script, runtime installers | IMPROVED ON QA BRANCH | QA branch converts PyInstaller to relocatable onedir, recursively installs the whole tree, adds embedded Python + Playwright Chromium, and adds clean-Windows audit script. Product assets/tools remain incomplete. |

## Hard release blockers

1. **Tool registry mismatch:** `tools_config.json` declares `tool_count: 137`, but the three existing category files contain 75 definitions total (25 passive recon + 20 active recon + 30 web-vulnerability). Missing declared includes: `mobile.json`, `web3.json`, `secrets.json`, `network.json`, `utilities.json`.
2. **Installer tool manifest is empty:** `installer/tools-manifest.json` contains no tools. `installer/setup_tools.ps1` therefore downloads nothing. A single-install Windows release cannot claim bundled tool support.
3. **Full UI is absent:** no `app/static/index.html` exists; the production server returns bootstrap HTML.
4. **160 test packs are absent:** no `app/modules/test_packs.py` or equivalent 160-test registry/API exists.
5. **Operational integration is absent:** scheduler, event bus, tool-wrapper factory, browser automation, Brain, capture, findings/reporting and submissions are not wired into production server routes.
6. **Encryption integration incomplete:** secure DB adapters exist, but standalone capture is still constructed with plaintext persistence.
7. **Capture runtime contract is inconsistent:** the capture addon documentation targets current mitmproxy 12.x / Python 3.12+, while the main Python 3.11 dependency range can resolve an older Python-3.11-compatible mitmproxy 11.0.x. For release, current standalone Windows mitmproxy should be pinned and hash-verified in the tool manifest rather than relying on ambient pip resolution.
8. **Coverage gate not yet executed on this branch:** the final tag workflow requires >=85% coverage; no claim of passing is made until Actions executes it.
9. **Clean Windows installer test not yet executable:** packaging is deliberately blocked before artifact creation while the blockers above remain.

## Guardrail findings

| Guardrail | Static result | Notes |
|---|---|---|
| Scope | **PARTIAL / NOT CERTIFIED E2E** | Scope engine is strong and scheduler requires preflight; wrapper can be constructed without a scope validator and the production scan path is not wired. |
| Consent | **PASS at primitive level** | Ed25519-signed, time-bounded, exact-scope-bound consent records are implemented. |
| Rate | **PASS at primitive level** | Global and keyed async token buckets are implemented; scheduler invokes rate acquisition. |
| Encryption | **FAIL integration** | AES-256-GCM + DPAPI implementation exists, but capture persistence does not use secure DB facade in the standalone path. |
| Auth | **PASS for local bootstrap** | Loopback-only access, opaque protected sessions and CSRF checks are implemented. Operational APIs are not yet present. |

## Release-only fixes applied on QA branch

- Added `scripts/audit/release_audit.py` with fail-closed Phases A/B/D/E/F.
- Added `scripts/audit/windows_install_audit.ps1` for silent install, loopback health, portable smoke test and uninstall validation.
- Added `requirements-dev.txt` for deterministic QA tooling.
- Converted `Windeep.spec` to a relocatable onedir package and included configs/tools/runtime assets.
- Changed Inno Setup to recursively package `dist\Windeep\*`.
- Added verified CPython 3.11.9 embeddable runtime staging.
- Added Playwright Chromium staging into the release runtime.
- Added CycloneDX SBOM generation for Python packages plus manifest-declared external tools.
- Added final tag-triggered G1–G21 release workflow with draft-first publishing, checksums and GitHub Sigstore attestations.
- Hardened capture to skip unresolved HTTP/WebSocket traffic instead of storing it.

## Release engineering conclusion

Do **not** tag `v0.1.0` as a production-complete release. The correct current decision is **NO-GO**. The release pipeline must remain fail-closed until registry/manifest/UI/test-pack/server-integration/encrypted-capture blockers are resolved and Windows CI produces passing audit evidence.
