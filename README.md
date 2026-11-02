# Windeep

Windeep is a local-first bug-bounty and security-assessment workspace for **authorized security testing**. Windeep v4 keeps the complete 137-integration catalog while resolving execution per host through native binaries, Windeep-managed provisioning, containers, WSL, authenticated remote workers, and pure-Python builtin fallbacks.

> **Authorization required:** Use Windeep only on systems you own or are explicitly authorized to test. Scope boundaries and program rules always take precedence over automation.

## Windeep v4 runtime model

A catalog entry being registered no longer means Windeep pretends that it is executable on every machine. The resolver reports the achieved runtime tier for each tool:

- `native` — already available as a host binary.
- `provisioned` — installed into Windeep-managed tool storage with a content-addressed cache.
- `container` — executed through the pinned `winddeep/tools:v3` OCI image.
- `wsl` — executed in a compatible Windows Subsystem for Linux distro.
- `remote` — executed by an authenticated Windeep worker on an appropriate Linux/macOS/device host.
- `builtin-fallback` — implemented by a maintained Python adapter when an external CLI is unnecessary or obsolete.
- `unavailable` — no currently enabled backend can satisfy the tool on this host.

All scan modes schedule only resolver-ready and target-compatible integrations. An unavailable dependency is a setup state, not a planned mid-scan `FileNotFoundError`.

## Catalog counts

`tools_config.json` distinguishes static catalog facts from dynamic host facts:

<!-- v4-runtime-counts:start -->
- **137 registered integrations** are retained for historical scan/template compatibility.
- **109 active v4.1 launch integrations** have a supported route, maintained fallback, host contract, or explicit external-service workflow.
- **28 dead/deprecated/catalog-only integrations** are excluded from the active launch surface instead of appearing as runnable tools.
<!-- v4-runtime-counts:end -->
- **Host-runnable counts are dynamic** and are reported by `winddeep doctor`, `/api/v2/tools`, and `/api/v2/status`.

CI verifies the static counts with `scripts/generate_v4_metadata.py --check` and aggregates doctor evidence across supported runtime environments before release.

## Architecture

```text
Dashboard (localhost:7331)
        |
        v
 API / SSE layer
        |
        v
 Target-aware planner
        |
        v
 ToolWrapperBase
        |
        v
 ExecutionResolver
   | native
   | provisioned
   | container
   | WSL
   | remote worker
   ` builtin fallback
        |
        v
 Findings + backend evidence ----> encrypted SQLite state
```

The wider product includes 160 assessment checks, findings/proof workflows, local SSE updates, scope/consent controls, reports, and Windows packaging through PyInstaller + Inno Setup.

Windeep is **not only a scanner**. Its program workspace is intended to support the full authorized research loop: program/scope understanding, rules-of-engagement enforcement, manual test planning, target-aware automation where permitted, evidence custody, deduplication/ranking, hypotheses, verification, reporting, submission tracking, and earnings history. Program rules can disable scanners or other target-facing automation without disabling the local reasoning/reporting workspace.

## Install

### Release build

When a v4 release is published, download its Windows installer or portable archive from [GitHub Releases](https://github.com/aprashnasuraj-dev/winddeep/releases/latest).

### Developer setup

```powershell
git clone https://github.com/aprashnasuraj-dev/winddeep.git
cd winddeep
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
pytest
python launcher.py
```

## Runtime doctor and healing

Inspect backend availability without changing the machine:

```text
python launcher.py doctor --backends
python launcher.py doctor --json
```

Provision declared dependencies, prepare WSL/container routes where applicable, then re-probe the catalog:

```text
python launcher.py doctor --heal
```

Healing requires an explicit confirmation. For non-interactive CI or an already-approved automation context:

```text
python launcher.py doctor --heal --yes --json
```

Provisioning is never triggered merely by viewing the catalog or resolving a backend.

## Provisioning and cache

V4 recipes support Go, Cargo/Rust, pipx/Python, npm, and OS package managers. Windeep-managed binaries are cached under `tools/.cache` using their SHA-256 content digest so an already-provisioned artifact can be restored without repeating the package-manager install.

On Windows, `doctor --heal` can also provision compatible declared recipes inside WSL. WSL healing is consented and installs command entry points into `/usr/local/bin` so execution does not depend on an interactive shell profile.

## Container backend

Heavy, driver-sensitive, or Windows-hostile integrations can use the pinned shared image:

```text
docker build -f docker/tools.Dockerfile -t winddeep/tools:v3 .
```

The resolver uses Docker or Podman only when the engine/socket is reachable and the configured image exists. CI probes every tool that declares the shared image rather than maintaining a partial hand-written probe list.

## Remote worker

Host-locked tools can run on a compatible authorized machine while preserving the same wrapper/argv contract. Configure the controller with:

```text
WINDEEP_REMOTE_WORKER_URL=https://worker.example:9443
WINDEEP_REMOTE_WORKER_TOKEN=<strong-random-token>
```

The worker requires bearer authentication. Non-loopback workers require TLS; loopback HTTP is permitted for local development. Start the worker using the v4 CLI command exposed by `launcher.py`.

## Offline / air-gapped runtime bundle

Export resolved tool storage plus the configured OCI image into one verified archive:

```text
python launcher.py bundle export --output windeep-runtime.tar.zst
```

Restore it on an offline machine:

```text
python launcher.py bundle import windeep-runtime.tar.zst
```

The bundle manifest hashes every staged file and import rejects path traversal, links, and checksum mismatches before restoring the runtime.

## Windows build

```powershell
pip install -r requirements.txt
pip install pyinstaller
powershell -ExecutionPolicy Bypass -File installer/setup_tools.ps1
pyinstaller --clean --noconfirm Windeep.spec
ISCC.exe installer/BugBountyInstaller.iss
```

The release workflow must test the exact candidate commit/artifact before publication. The v4 runtime gate separately verifies resolver contracts, Windows/Linux behavior, WSL presence, the shared container image, full-catalog doctor reports, and cross-platform route coverage.

## Security model

Windeep treats target scope as data, not as a comment. Scan contexts carry in-scope and out-of-scope rules, and execution remains bound to scope, consent, authentication and rate controls. No automated safeguard replaces the tester's obligation to follow the target program's authorization and rate limits.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and safe-use guidance.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should include tests and must pass the repository CI checks. A new catalog tool must declare at least one executable v4 route (provisioning, container, builtin fallback, alias, host-specific remote route, or certified bundled path).

## License

MIT. See [LICENSE](LICENSE).
