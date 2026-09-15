# Changelog

All notable changes to Windeep are documented here. This project follows Semantic Versioning.

## [Unreleased]

## [2.1.0] - 2026-09-15

### Added
- Repository bootstrap, Windows CI/release pipeline, issue templates, security policy, and contribution guide.
- Event-driven engine primitives: async event bus, DAG scheduler, dynamic tool wrapper factory, and scan context.
- Fail-closed release audits for module completeness, registry/installer coverage, dependency health, local guardrails, coverage, tag/version consistency, and clean Windows packaging.
- Clean Windows installer/portable audit covering embedded Python, Playwright browser payload, manifest-declared tool probes, loopback binding, version identity, and silent uninstall.
- Deterministic portable-tool staging with pinned HTTPS assets, SHA-256 verification, archive-member extraction, path-safety checks, licensing metadata, and non-invasive liveness probes.
- CycloneDX SBOM generation plus GitHub build-provenance/SBOM attestations for release artifacts.
- P0 v3 scheduler node contract with explicit task IDs, kinds, dependencies, resource classes, timeouts, bounded deterministic-jitter retries, and cancellation metadata.
- Scheduler-owned per-tool concurrency plus layered per-host rate governance and per-attempt fail-closed tool reauthorization.
- Additive `scan_events` and `tool_finding_refs` schema for monotonic replayable SSE and idempotent `(scan_id, tool_run_id, finding_fingerprint)` occurrence persistence.
- Encrypted transactional P0 pipeline store that batches each tool run into one SQLite transaction and keeps occurrence snapshots addressable without rewriting legacy evidence tables.
- Deterministic post-execution pipeline using fingerprint deduplication, `chain_builder`, `finding_ranker`, and evidence-grounded heuristic hypotheses.
- Registered background scan runtime so Flask scan workers are owned and leak-detectable rather than ad-hoc threads.
- Versioned per-scan SSE events with `Last-Event-ID` replay, sequence-gap repair, and metadata-only finding/evidence notifications.
- Platform threat model covering malicious target content, compromised tools, SSRF, prompt injection, evidence integrity, migration safety, redaction DoS, and P0 concurrency/replay risks.

### Changed
- Refreshed release workflow action majors while preserving the G1-G21 tag-release sequence.
- Release tooling now rejects an empty tool manifest instead of silently producing an incomplete installer.
- The v2 scan surface now delegates execution to one shared asyncio event loop and `TaskScheduler` instead of running `asyncio.run` once per tool.
- Passive recon branches fan out in parallel; active/web work declares recon dependencies; failed branches block only their dependents while independent work drains to `completed_with_errors`.
- Finding SSE payloads no longer export raw evidence, requests, responses, or proof narrative fields while the full P1 deterministic redaction-map layer is being built.

### Security
- Preflight denial paths now fail closed and attempt to append first-class denial audit events; guardrail denials are never retried as transient tool failures.
- Tool attempts re-check scope, consent, crypto health, and audit health immediately before invocation and consume both tool and host rate capacity.
- P0 persistence is additive only; no evidence-bearing table is dropped or rewritten.

## [0.1.0] - 2026-09-15

### Added
- Initial public project scaffold based on the Windeep master blueprint.
