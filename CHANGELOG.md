# Changelog

All notable changes to Windeep are documented here. This project follows Semantic Versioning.

## [Unreleased]

## [2.1.0] - 2026-09-15

### Added
- P0 scheduler-driven v2 scan pipeline with explicit passive-recon dependencies, bounded task retries, per-tool concurrency caps, per-host rate governance, and one asyncio event loop per registered scan runtime.
- Encrypted, versioned, monotonic scan event log supporting replayable `finding`, `progress`, `log`, `evidence`, `chain`, and `ranked` SSE events.
- Additive `scan_events`, `scan_findings`, and `scan_authorizations` migration for gap-free event replay and idempotent `(scan_id, tool_run_id, finding_fingerprint)` persistence.
- Deterministic post-processing order: fingerprint deduplication, chain correlation, finding ranking, then evidence-grounded heuristic hypotheses.
- Tests for concurrency, preflight non-execution on denial, batch idempotency, stable serialization, SSE replay/redaction, and persisted finding IDs in attack-chain correlation.
- Repository bootstrap, Windows CI/release pipeline, issue templates, security policy, and contribution guide.
- Event-driven engine primitives: async event bus, DAG scheduler, dynamic tool wrapper factory, and scan context.
- Fail-closed release audits for module completeness, registry/installer coverage, dependency health, local guardrails, coverage, tag/version consistency, and clean Windows packaging.
- Clean Windows installer/portable audit covering embedded Python, Playwright browser payload, manifest-declared tool probes, loopback binding, version identity, and silent uninstall.
- Deterministic portable-tool staging with pinned HTTPS assets, SHA-256 verification, archive-member extraction, path-safety checks, licensing metadata, and non-invasive liveness probes.
- CycloneDX SBOM generation plus GitHub build-provenance/SBOM attestations for release artifacts.

### Changed
- V2 scan execution no longer calls `asyncio.run()` once per integration; scans are registered and executed through the existing `TaskScheduler` on a single loop.
- Independent task failures no longer abort unrelated branches; dependent tasks fail closed and the scan finishes as `completed_with_errors` when independent work can still be retained.
- Preflight denials are first-class audit events; a denial that cannot be written to the audit sink fails closed.
- V2 report generation, report export, scan-event replay, scan cancellation, and intelligence reads now require live preflight authorization derived from the encrypted scan authorization reference.
- Existing global finding deduplication remains intact for compatibility; P0 adds encrypted per-tool-run `scan_findings` records rather than rewriting the evidence-bearing `findings` table.
- Refreshed release workflow action majors while preserving the G1-G21 tag-release sequence.
- Release tooling now rejects an empty tool manifest instead of silently producing an incomplete installer.

### Security
- SSE export payloads receive a deterministic P0 secret-safety pass before persistence/broadcast. The deeper reproducible redaction-map design remains scoped to P1.
- Post-execution chain/hypothesis stages use rule-based fallback only in P0 (`LLMClient([])`), so captured target content is not sent to an external model during this phase.

## [0.1.0] - 2026-09-15

### Added
- Initial public project scaffold based on the Windeep master blueprint.
