# Windeep Phase B — Tool Liveness & Packaging Audit

Audit date: 2026-09-15  
Audited branch: `main`

## Decision

**FAIL — release tool payload is not complete or verifiable.**

The wrapper framework is implemented, but the repository currently defines only 75 of the 137 tools declared by the root registry and the installer manifest contains zero downloadable packages. The hardened Phase B gate therefore prevents a release before any external-tool execution or installer build is attempted.

## Registry coverage

| Registry | Discovered | Status |
|---|---:|---|
| `app/tools/config/recon_passive.json` | 25 | Present |
| `app/tools/config/recon_active.json` | 20 | Present |
| `app/tools/config/web_vulns.json` | 30 | Present |
| `app/tools/config/mobile.json` | 0 | **MISSING** |
| `app/tools/config/web3.json` | 0 | **MISSING** |
| `app/tools/config/secrets.json` | 0 | **MISSING** |
| `app/tools/config/network.json` | 0 | **MISSING** |
| `app/tools/config/utilities.json` | 0 | **MISSING** |
| **Actual definitions** | **75** | — |
| **Root declared count** | **137** | **FAIL: mismatch by 62** |

All 75 definitions that exist contain the common execution metadata required by the wrapper factory: binary, category, arguments, timeout, retries, rate limit and `requires_scope=true`. That validates schema shape only; it does not prove that the exact CLI contract is valid on a clean Windows release.

## Installer coverage

`installer/tools-manifest.json` still contains an empty `tools` array. The installer therefore cannot currently prove or provide:

- pinned tool versions;
- redistribution/license review;
- immutable HTTPS distribution sources;
- SHA-256 verification;
- Windows destination/shim mapping;
- archive member mapping;
- registry `provides` coverage;
- non-invasive liveness probes;
- semantic compatibility between wrapper arguments and the pinned executable.

`installer/setup_tools.ps1` has now been changed to **fail on an empty manifest**. For each future manifest package it also requires safe paths, a version, license metadata, HTTPS source, 64-hex SHA-256, `provides`, probe arguments and a successful bounded probe. Direct files and ZIP archive members are supported.

## Dead / deprecated / suspect definitions requiring resolution

| Entry | Classification | Release action |
|---|---|---|
| `aquatone` | Deprecated/archived upstream | Do not ship as an unqualified current default. Either replace it or mark a specifically reviewed legacy build in the manifest. |
| `jsparser` / `JSParser` | Legacy Python 2.7 contract | Do not claim compatibility with the bundled Python 3.11 runtime without an isolated, pinned runtime or replacement. |
| `sublist3r` | Legacy/high-maintenance risk | Requires a pinned Windows-tested distribution before it can be release-certified. |
| `waffw00f` | Duplicate/typo suspect | The registry also contains `wafw00f`; resolve to one canonical wrapper or explicitly map a reviewed alias. |
| `github_models` Brain provider | Retired compatibility path | Must not be advertised as a live built-in provider unless an explicitly compatible endpoint is configured. |
| mitmproxy runtime contract | Version/runtime mismatch risk | The release must pin a Windows-compatible runtime/artifact rather than relying on an ambient Python 3.11 resolution for a newer documented runtime. |

Phase B now fails any known legacy/deprecated blocker above unless the corresponding manifest entry explicitly carries `legacy_reviewed: true`; this makes legacy support an auditable release decision rather than an accidental dependency.

## Wrapper semantic risks still requiring executable-level probes

- `recon-ng -r {target}` appears to use a resource-script option rather than a direct target argument and must be validated against the pinned release.
- `puredns resolve {target}` may treat its positional input as a file path depending on version; the pinned binary must prove the intended contract.
- Python-oriented entry points such as `cloud_enum`, `theHarvester`, `dnsgen` and similar tools need deterministic Windows shims/interpreter handling.
- API-key-dependent tools must distinguish **installed/lively** from **configured/usable**; absent optional credentials are not the same as a broken binary.

## Release-ready acceptance criteria for every wrapper

A wrapper is release-ready only when all of these are true:

1. It exists exactly once in the registry, or an alias is explicitly documented.
2. Upstream lifecycle is reviewed; legacy support is explicitly marked.
3. A Windows-compatible version is pinned.
4. Distribution URL is HTTPS and version-specific.
5. SHA-256 is pinned and verified before staging.
6. Redistribution/license metadata is recorded.
7. Destination/shim matches the wrapper's `binary` resolution contract.
8. A safe `--version`, `-h` or equivalent probe succeeds within 15 seconds.
9. Wrapper arguments are tested against that exact pinned version.
10. Scope, rate, timeout, cancellation and credential handling remain fail-closed.

## Current result

**FAIL.** No production release should claim “137 integrated tools” or “single installer contains everything” until the five missing registries and the complete reviewed installer manifest are present and G11b passes all safe probes on the Windows runner.
