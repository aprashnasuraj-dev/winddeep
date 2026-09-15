# Windeep Phase A — Static Release Audit

Audit date: 2026-09-15  
Audited branch: `main`  
Audited baseline before report refresh: `8c75b4dc8a93cef21c74ca94c1c01d3f5cdc7d24`

## Decision

**FAIL — release remains NO-GO.**

Release engineering is now fail-closed and substantially stronger, but the repository is not yet the complete Windows desktop product described by the master blueprint. The missing items below are product-completion work, not packaging details, so the release workflow must not manufacture a production release around them.

## Module completeness matrix

| Area | Files / capability reviewed | Status | Release finding |
|---|---|---|---|
| Windows launcher | `launcher.py` | IMPLEMENTED | Resolves packaged root, adds bundled tools/runtime to process PATH, sets packaged Playwright path and Windows state directory, and fails with an actionable startup error. |
| Local server / dashboard auth | `app/server.py`, `app/security/auth.py` | PARTIAL | Localhost-only binding, session protection, CSRF and hardened headers are implemented. Operational target/scan/finding/tool/report/test-pack APIs are not present. |
| Scope / consent / rate / audit / crypto | `app/security/scope.py`, `consent.py`, `rate_governor.py`, `audit.py`, `crypto.py`, `preflight.py` | IMPLEMENTED PRIMITIVES | Deny-wins scope, signed consent, bounded rates, audit logging and protected key material are present. Phase D exercises them locally. |
| Encrypted persistence | `app/security/secure_database.py`, `secure_flow_database.py` | IMPLEMENTED-BUT-UNWIRED | Secure facades exist, but the shipped operational capture/server path does not establish encrypted-at-rest persistence end-to-end. |
| Engine | `app/engine/event_bus.py`, `scheduler.py`, `scan_context.py`, `tool_wrapper.py` | IMPLEMENTED-BUT-UNWIRED | Event bus, guarded scheduler context and dynamic wrappers are implemented; no production server route wires the operational scan path. |
| Database | `app/database.py`, `app/migrations.py`, `app/data/migrations/*` | IMPLEMENTED | SQLite data/migration code exists. Dashboard operational CRUD wiring is absent from the current server. |
| Capture / replay | `app/capture/flow_database.py`, `interceptor.py`, `mitm_addon.py`, `replay_client.py` | PARTIAL | Scope-aware components exist; production target resolution and secure persistence integration are not complete. |
| Browser automation | `app/browser/automation.py` | IMPLEMENTED-BUT-UNWIRED | Browser automation exists and release runtime staging now includes Playwright Chromium, but no production UI/API path invokes it. |
| Authentication assurance | `app/auth/protocols.py`, `session_analysis.py`, `suite.py` | IMPLEMENTED-BUT-UNWIRED | Guarded auth analysis exists but is not the promised 160-test pack implementation and is not exposed through the shipped UI/API. |
| AI Brain | `app/brain/*` | IMPLEMENTED-BUT-UNWIRED | Budgeting, hypothesis/chaining, memory, LLM client, prompt guard, ranking and self-critique modules exist. Production dashboard/API integration is absent. |
| Program scope import | `app/programs/scope_importer.py` | IMPLEMENTED-BUT-UNWIRED | Import/parser subsystem exists; no current dashboard route exposes it. |
| Duplicate/submission support | `app/duplicates.py`, `app/submissions.py` | IMPLEMENTED-BUT-UNWIRED | Local support code exists; no shipped production UI/API integration. |
| Tool wrapper framework | `app/engine/tool_wrapper.py` | IMPLEMENTED | Subprocess execution is shell-free and bounded; wrappers require an explicit scope validator when configured with `requires_scope=true`. |
| Tool registries | `tools_config.json`, `app/tools/config/*.json` | **FAIL** | Root registry declares 137 tools, but only 75 definitions exist. Five declared category files are missing. |
| External tool installer | `installer/setup_tools.ps1`, `installer/tools-manifest.json` | **FAIL-CLOSED / NO DATA** | Stager now verifies versions, HTTPS source, license metadata, SHA-256, safe archive extraction and liveness probes, but the manifest is empty. |
| Test packs | expected `app/modules/test_packs.py` or equivalent | **MISSING** | No 160-test pack registry/implementation exists anywhere in repository history. |
| Dashboard UI | expected `app/static/index.html` | **MISSING** | Full desktop dashboard never existed in repository history; current `/` endpoint serves a minimal bootstrap page. |
| PyInstaller package | `Windeep.spec` | READY AS INFRASTRUCTURE | Relocatable onedir build includes config/data/tools/runtime directories when present. |
| Inno Setup | `installer/BugBountyInstaller.iss` | READY AS INFRASTRUCTURE | Recursively installs the built `dist/Windeep` tree as `Windeep-Setup.exe`. |
| Embedded runtime | `installer/install_python.ps1` | READY AS INFRASTRUCTURE | Pinned CPython 3.11.9 embeddable runtime plus staged Playwright Chromium. |
| Clean-Windows verification | `scripts/audit/windows_install_audit.ps1` | READY AS INFRASTRUCTURE | Verifies installer + portable tree, exact VERSION, registry, Python, Chromium, every manifest probe, loopback health/binding and uninstall cleanup. |
| Tag release workflow | `.github/workflows/release.yml` | READY AS INFRASTRUCTURE | G1-G21 flow is present with current supported action majors, >=85% coverage gate, SBOM, SHA-256 files and Sigstore-backed attestations. |

## Hard release blockers

1. `tools_config.json` declares **137** tools while only **75** definitions are present.
2. Missing registries: `mobile.json`, `web3.json`, `secrets.json`, `network.json`, `utilities.json`.
3. `installer/tools-manifest.json` is empty; therefore no external-tool payload can be reproducibly bundled or liveness-tested.
4. Full dashboard `app/static/index.html` is absent and has no historical commit to recover.
5. The promised 160 test packs are absent and have no historical commit to recover.
6. `app/server.py` does not expose the operational targets/scans/findings/reports/tools/settings/SSE/test-pack APIs described by the product blueprint.
7. Engine, browser, capture, Brain, database and submission components are not wired into a complete production execution path.
8. Secure persistence is not certified end-to-end on the operational capture path.
9. The >=85% coverage gate must be demonstrated by GitHub Actions on the exact release commit.
10. The clean Windows installer audit cannot pass until a non-empty, complete tool manifest and complete product tree exist.

## Guardrail assessment

| Guardrail | Current result | Release interpretation |
|---|---|---|
| Scope | PASS at primitive/local-preflight level | Explicit allow/deny scope and out-of-scope rejection exist; complete operational scan-path enforcement remains unverified because that path is not wired. |
| Consent | PASS at primitive/local-preflight level | Signed, time-bounded consent is present and tied to scope. |
| Rate | PASS at primitive level | Bounded rate controls exist; every registered wrapper is required by Phase A to declare a positive rate limit. |
| Encryption | PARTIAL / NOT CERTIFIED E2E | Crypto and secure DB facades exist; current product wiring does not prove all captured operational data uses them. |
| Auth | PASS for local bootstrap | Loopback-only access, session authentication and CSRF checks are implemented. |

## Release engineering completed in this audit session

- Hardened `scripts/audit/release_audit.py` to inventory Python modules, detect stubs/placeholders, verify wrapper metadata/bounds, require UI/test-pack/API wiring, validate installer manifest integrity, enforce >=85% coverage in Phase F, and verify tag/VERSION identity.
- Hardened `installer/setup_tools.ps1` to reject empty/incomplete manifests and verify pinned payloads and non-invasive probes.
- Hardened `scripts/audit/windows_install_audit.ps1` to validate installed and portable runtime/tool payloads, loopback binding, exact VERSION and uninstall cleanup.
- Refreshed `.github/workflows/release.yml` while retaining the required G1-G21 release order.
- Confirmed the missing dashboard/test-pack assets are not recoverable from existing repository history/branches.

## Release engineering conclusion

**Do not tag `v0.1.0` as a production-complete release.** The correct release decision remains **NO-GO**. The pipeline is intentionally configured to stop before package/release publication while the product-completion blockers above exist.
