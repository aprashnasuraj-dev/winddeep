# Windeep Phase B — Tool Liveness & Packaging Audit

Audit date: 2026-09-15  
QA branch: `release/qa-gate-v0.1.0`

## Decision

**FAIL — 0/137 declared tools have a complete installer/liveness contract.**

This is not a claim that every upstream project is dead. It means the current repository cannot prove that every declared wrapper is installable and runnable on a clean Windows 10/11 machine because the installer manifest is empty and five declared registry files are absent.

## Registry coverage

| Registry | Declared / discovered | Status |
|---|---:|---|
| `app/tools/config/recon_passive.json` | 25 | Present |
| `app/tools/config/recon_active.json` | 20 | Present |
| `app/tools/config/web_vulns.json` | 30 | Present |
| `app/tools/config/mobile.json` | missing | **FAIL** |
| `app/tools/config/web3.json` | missing | **FAIL** |
| `app/tools/config/secrets.json` | missing | **FAIL** |
| `app/tools/config/network.json` | missing | **FAIL** |
| `app/tools/config/utilities.json` | missing | **FAIL** |
| **Actual definitions** | **75** | — |
| **Root declared count** | **137** | **FAIL: mismatch by 62** |

All 75 definitions that do exist contain the common wrapper metadata (`binary`, `category`, `args`, `timeout`, `retries`, `rate_limit`, `requires_scope`). That validates schema shape, not executable availability or semantic correctness of every CLI argument.

## Installer coverage

`installer/tools-manifest.json` currently contains an empty `tools` array. Consequently:

- no portable executable has a pinned version;
- no external tool has a reviewed HTTPS distribution URL;
- no external tool has a SHA-256 value in the release manifest;
- no archive extraction mapping exists;
- no Python/script shim mapping exists;
- no safe liveness probe can be executed after `setup_tools.ps1`;
- no registry-to-installer coverage can be proven.

The QA branch Phase B script rejects the release unless every registered wrapper is covered by a manifest `provides` mapping and every manifest entry has a URL, SHA-256 and non-invasive liveness probe.

## Dead / deprecated / suspect entries found

| Entry | Classification | Finding / release action |
|---|---|---|
| `aquatone` | **Deprecated upstream** | Upstream `michenriksen/aquatone` is archived/read-only. Do not present it as a current default dependency. Remove, replace, or explicitly pin/label it as legacy. |
| `jsparser` / JSParser | **Legacy / incompatible** | Upstream describes JSParser as Python 2.7. It is incompatible with Windeep's Python 3.11 embedded runtime unless isolated in a separate legacy runtime. Prefer removal/replacement. |
| `sublist3r` | **Legacy / high-maintenance risk** | Upstream remains visible but its long-standing Python compatibility history makes it unsuitable for an unqualified clean-Windows guarantee without a pinned tested build. |
| `waffw00f` + `wafw00f` | **Duplicate/typo suspect** | `web_vulns.json` defines both spellings. The established project/CLI is WAFW00F (`wafw00f`). Resolve the duplicate before release. |
| `github_models` Brain provider | **Retired service compatibility key** | `llm_client.py` itself records that GitHub Models inference was retired on 2026-07-30; it only works with an explicitly supplied compatible endpoint. Not a tool-binary blocker, but it must not be advertised as a live built-in provider. |
| mitmproxy pip/runtime contract | **Version mismatch** | Current mitmproxy 12.x requires Python >=3.12. Windeep's Python-3.11 dependency range can resolve 11.0.x, while `mitm_addon.py` documents 12.x. For the Windows release, use the current standalone Windows binary as a separately pinned/hash-verified tool. |

## Wrapper semantic-risk examples requiring real Windows probes

The audit does not certify a wrapper merely because its JSON parses. Several configurations need executable-level verification, for example:

- `recon-ng -r {target}` appears to use a resource-script option rather than a direct target argument and therefore needs correction or a generated resource file.
- `puredns resolve {target}` may interpret the positional value as an input file depending on the pinned version; its actual invocation contract must be tested.
- Python-entrypoint tools (`cloud_enum`, `theHarvester`, `dnsgen`, and similar) need deterministic Windows `.cmd`/`.exe` shims or explicit interpreter handling; directly resolving a `.py` file is not enough for a portable Windows guarantee.
- API-key-dependent tools must be distinguished between **installed/lively** and **configured/usable**; missing optional credentials must not be reported as a broken binary.

## Phase B acceptance criteria

A tool is release-ready only when all of the following are true:

1. It exists in exactly one registry definition (aliases explicitly mapped).
2. Its upstream is active or it is explicitly classified as supported legacy.
3. A Windows-compatible artifact/runtime is pinned.
4. Distribution URL is HTTPS and immutable/versioned.
5. SHA-256 is pinned and verified by `setup_tools.ps1`.
6. The installed path or shim matches the wrapper's `binary` value.
7. `--version`, `-h`, or another non-invasive probe succeeds on Windows.
8. The wrapper's configured arguments are tested against the pinned version.
9. Scope/rate/timeout/cancellation behavior is preserved.
10. License redistribution terms permit bundling in the Windeep installer.

## Current result

**FAIL.** Until the manifest and five missing registries are completed, a “137 integrated tools / single installer contains everything” release claim is not verifiable.
