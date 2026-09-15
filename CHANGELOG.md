# Changelog

All notable changes to Windeep are documented here. This project follows Semantic Versioning.

## [Unreleased]

No unreleased changes yet.

## [0.1.0] - 2026-09-15

### Added
- Local-only authenticated Windows dashboard and Flask API with CSRF protection, restrictive browser security headers, and SSE event streaming.
- Signed authorization consent, explicit allow/deny scope enforcement, pre-flight authorization, and bounded rate governance.
- Event-driven runtime with asynchronous scheduling, tool wrappers, normalized findings, scan status/logging, and cancellation handling.
- SQLite-backed targets, scans, findings, captured flows, hypotheses, chains, reports, learnings, tool runs, and submission tracking.
- Encryption at rest for sensitive finding content and captured request/response data.
- 137-entry integration catalog with explicit release-support classifications instead of implicit availability claims.
- Checksum-pinned Windows bundles for subfinder, dnsx, httpx, naabu, katana, and nuclei, with installer-time liveness validation.
- Eight evidence-driven test packs exposing exactly 160 tests with fail-closed prerequisites and analyst-signal support.
- Browser-fidelity inert marker checks with scope interception through the local capture proxy.
- Isolated Python 3.12 capture runtime pinned to mitmproxy 12.2.3, separate from the Python 3.11 main runtime.
- Hypothesis generation, chain rebuilding, local memory primitives, report generation, and submission/earnings/Kanban tracking.
- PyInstaller onedir build, Inno Setup installer, portable archive, source snapshot, clean Windows install audit, CycloneDX SBOM, SHA-256 checksums, and GitHub build-provenance attestations.
- Release candidate and tagged-release gates covering static/product contracts, dependency vulnerabilities, unit/integration behavior, local end-to-end checks, coverage, packaging, and installer verification.

### Security
- Bound explicit-scope consent signatures to the complete allow/deny authorization rules so an authorized wildcard scope can safely cover allowed subdomains while target-only consent remains exact.
- Hardened runtime dependency floors after dependency audit and removed an unused runtime dependency.
- Capture callbacks require a per-process token and unresolved traffic is never persisted as authorized target evidence.

### Changed
- Deprecated/legacy/platform-specific/commercial integrations are retained in the catalog only with an explicit reason and replacement where applicable.
- Release documentation now distinguishes the 137 classified integrations from the six third-party portable binaries redistributed in v0.1.0.
