# Windeep

Windeep is a Windows-focused bug-bounty command center for **authorized security testing**. v0.1.0 ships a local-only desktop dashboard, guarded scan/runtime orchestration, encrypted persistence, traffic capture, evidence-driven test packs, reporting, and a classified security-tool integration catalog.

> **Authorization required:** Use Windeep only on systems you own or are explicitly authorized to test. Signed consent, scope enforcement, local-only binding, and rate controls are safety layers; they do not replace the tester's obligation to follow program rules and applicable law.

## v0.1.0 release scope

- Local dashboard and API on `127.0.0.1:7331`, with session authentication, CSRF validation, restrictive browser security headers, and SSE event streaming.
- Signed authorization consent and explicit allow/deny scope enforcement before guarded execution.
- Event-driven scheduler/runtime with SQLite persistence for targets, scans, findings, flows, hypotheses, chains, reports, and submission tracking.
- Encryption at rest for sensitive finding and captured-flow fields.
- **137 classified tool integrations** in the release registry. Every integration is explicitly classified as bundled/runtime/internal/system/unsupported/deprecated/legacy rather than silently assumed available.
- Six checksum-pinned portable command-line tools bundled by the Windows installer: `subfinder`, `dnsx`, `httpx`, `naabu`, `katana`, and `nuclei`.
- **160 evidence-driven tests** across eight packs. These inspect captured/imported evidence and explicit analyst signals; they do not independently generate exploit traffic.
- Browser-fidelity marker checks through a local capture proxy with scope interception.
- Isolated Python 3.12 capture runtime with pinned `mitmproxy==12.2.3`; the main application runtime remains Python 3.11.
- Markdown report generation, HackerOne/Bugcrowd-style submission tracking primitives, earnings aggregation, and Kanban state tracking.
- Windows packaging with PyInstaller + Inno Setup, clean-install verification, dependency audit, SBOM, SHA-256 checksums, and GitHub build provenance attestations.

## Architecture

```text
Browser dashboard (localhost:7331)
        |
        v
 Authenticated API / SSE
        |
        +----> Signed consent + scope + rate pre-flight
        |
        v
 Event Bus <----> Hypotheses / Chains / Memory
    |
    v
 Scheduler ----> Tool Wrappers ----> Findings ----> Encrypted SQLite
    |
    +----> Browser automation ----> Local capture proxy
                              |
                              v
                   Isolated Python 3.12 + mitmproxy
```

## Install

### Windows release

Download the verified v0.1.0 assets from [GitHub Releases](https://github.com/aprashnasuraj-dev/winddeep/releases/latest).

Release assets include:

- `Windeep-Setup.exe` — Windows installer
- `Windeep-Portable.zip` — portable application directory
- `windeep-source-v0.1.0.zip` — source snapshot from the tagged commit
- `SHA256SUMS.txt` — SHA-256 hashes for published release evidence/assets
- `RELEASE-NOTES.md`
- `SBOM.json` — CycloneDX software bill of materials
- release-gate evidence under `reports/`

Verify downloaded files against `SHA256SUMS.txt`. GitHub build-provenance attestations can also be verified with GitHub CLI, for example:

```powershell
gh attestation verify Windeep-Setup.exe --repo aprashnasuraj-dev/winddeep
```

### Developer setup

```powershell
git clone https://github.com/aprashnasuraj-dev/winddeep.git
cd winddeep
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
python launcher.py
```

The browser automation runtime additionally needs Chromium when running from a developer checkout:

```powershell
python -m playwright install chromium
```

## Reproducing the Windows build

```powershell
pip install -r requirements.txt -r requirements-dev.txt
powershell -ExecutionPolicy Bypass -File installer/setup_tools.ps1
powershell -ExecutionPolicy Bypass -File installer/install_python.ps1
powershell -ExecutionPolicy Bypass -File installer/install_capture_runtime.ps1
pyinstaller --clean --noconfirm Windeep.spec
ISCC.exe installer/BugBountyInstaller.iss
```

The release workflow repeats the static/product-contract audit, dependency audit, test/coverage gate, local end-to-end gate, pinned tool download/liveness validation, dual-runtime build, clean Windows installer/portable audit, SBOM/checksum generation, and provenance attestation before publishing.

## Integration support policy

The 137-entry registry is an integration catalog, not a claim that 137 third-party binaries are redistributed. Redistribution and Windows support are reviewed explicitly in `app/tools/release-policy.json`. Unsupported, commercial, platform-specific, legacy, and deprecated integrations remain visible with a reason and, where applicable, a replacement. This prevents a dashboard entry from being mistaken for a verified executable dependency.

## Test packs

The eight v0.1.0 packs are Browser Fidelity, Human Multi-Stage, Auth & Session, IDOR/BOLA, Business Logic, Mobile Deep Dive, AI Automation, and Wild Cards. Pack execution is evidence-driven and fail-closed when required prerequisites (such as authenticated evidence, two explicitly authorized accounts, or a mobile artifact) are missing.

## Security model

Windeep treats authorization and target scope as executable data:

- dashboard access is loopback-only;
- mutation routes require authenticated session + CSRF validation;
- consent records are signed and bound to the explicit scope rules;
- deny rules override allow rules;
- scans/tools/browser checks pass a pre-flight authorization gate;
- request rates are bounded;
- sensitive findings/flows are encrypted at rest;
- the capture process authenticates callbacks to the main application using a per-process token.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and safe-use guidance.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should include appropriate tests and must pass the repository release gates.

## License

MIT. See [LICENSE](LICENSE).
