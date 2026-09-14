# Windeep

Windeep is a Windows-focused bug-bounty command center for **authorized security testing**. The project is designed around an event-driven Python 3.11+ core, a local web dashboard, SQLite persistence, pluggable security-tool wrappers, test packs, traffic capture, and optional AI-assisted triage/reporting.

> **Authorization required:** Use Windeep only on systems you own or are explicitly authorized to test. Scope boundaries and program rules always take precedence over automation.

## Status

Windeep is under active development. The repository is being built in phases from the project master blueprint. Current work includes the production repository/CI scaffold and the event-driven engine.

## Architecture

```text
Dashboard (localhost:7331)
        |
        v
 API / SSE layer
        |
        v
 Event Bus <----> AI Brain
    |               |
    v               v
 Scheduler ----> Hypotheses / Chains
    |
    v
 Tool Wrappers ----> Findings ----> SQLite
    |
    +----> Capture / Replay Engine
```

The planned product includes:

- 130+ integrated security tools grouped across recon, web, mobile, Web3, secrets, network, and utilities.
- 160 manual/semi-automated tests organized into eight test packs.
- AI-assisted hypothesis generation, finding chaining, self-critique, and report drafting.
- Local HTTP/HTTPS capture and replay using mitmproxy.
- A 16-section dashboard with real-time SSE updates.
- SQLite persistence and Windows packaging through PyInstaller + Inno Setup.

## Install

### Release build

When releases are available, download the Windows installer or portable archive from:

[GitHub Releases](https://github.com/aprashnasuraj-dev/winddeep/releases/latest)

Release artifacts are planned to include:

- `Windeep-Setup.exe`
- `Windeep-Portable.zip`
- `SHA256SUMS.txt`
- release notes generated from `CHANGELOG.md` and Git history

### Developer setup

```powershell
git clone https://github.com/aprashnasuraj-dev/winddeep.git
cd winddeep
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pytest
python launcher.py
```

## Windows build

```powershell
pip install -r requirements.txt
pip install pyinstaller
powershell -ExecutionPolicy Bypass -File installer/setup_tools.ps1
pyinstaller --clean --noconfirm Windeep.spec
ISCC.exe installer/BugBountyInstaller.iss
```

The GitHub Actions workflow performs the same build on `windows-latest` and uploads the installer as an artifact. Tagging a commit `vX.Y.Z` creates a GitHub Release when the tag matches `VERSION`.

## Screenshots

Dashboard screenshots will be added as the UI migration reaches the 16-section layout.

- `docs/screenshots/dashboard.png`
- `docs/screenshots/live-traffic.png`
- `docs/screenshots/brain-console.png`

## Security model

Windeep treats target scope as data, not as a comment. Scan contexts carry in-scope and out-of-scope rules, and later execution layers build on those constraints. No automated safeguard replaces the tester's obligation to follow the target program's authorization and rate limits.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and safe-use guidance.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should include tests and must pass the repository CI checks.

## License

MIT. See [LICENSE](LICENSE).
