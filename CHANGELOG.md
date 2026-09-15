# Changelog

All notable changes to Windeep are documented here. This project follows Semantic Versioning.

## [Unreleased]

Post-freeze changes to the public v3 contracts are released as `3.0.x` patches unless they require a new major/minor compatibility window.

## [3.0.0] - 2026-09-15

### Phase map
- **P0 → Scheduler:** single-loop DAG scheduling, fail-closed preflight, partial-failure isolation, monotonic replayable SSE, deterministic post-processing.
- **P1 → Forensic capture:** encrypted content-addressed raw artifacts, exact HTTP evidence, custody metadata, replay inputs, redaction and Merkle/integrity support.
- **P2 → Evidence bundles:** deterministic self-proving evidence bundles, flow/artifact/provenance binding, completeness gates, `observed | needs-human-review` exploitability.
- **P3 → Reporting:** evidence-only deterministic Markdown/HTML, CVSS v3.1, chain narratives, redacted HAR/attachments, audited submission lifecycle.
- **P4 → LLM assist:** prompt-guarded, evidence-grounded hard-middle analysis with structured validation and no direct model-to-tool authority.
- **P5 → Web3:** read-only multi-chain source/bytecode resolution, Slither+Aderyn corroboration, bounded Mythril, immutable engine/detector/SWC provenance.
- **P6 → Operations:** restart-safe checkpoints, per-scan/per-tool budgets, encrypted structured logs, durable-first backpressure, active cleanup.
- **P7 → Self-threat-model:** release-blocking threat/mitigation/test/residual-risk mapping across the complete platform attack surface.
- **P8 → Schema:** current+previous readers, current-only writers, explicit API deprecation policy, evidence-preserving rollback discipline.

### Added
- v3 contract-freeze manifest covering `windeep.sse.v1`, `windeep.har-extension.v1`, `windeep.evidence-bundle.v1`, `windeep.artifact.v1`, `windeep.report.v1`, and the new `windeep.verification.v1` verification record.
- Single evidence-preserving Python release migration `0030_v3_release.py` for v3 release wiring, verification, target-class, handling-policy, and triage metadata tables.
- Unified v3 stage coordinator: scope+consent → recon → engines → dedup → chain → rank → hypothesis → handling → bundle close → verification → report → export/submission, with resumable encrypted checkpoints and audited transitions.
- R5 hash-addressed per-claim verification records stored as P1 artifacts before report generation.
- Completed P1 forensic capture/custody convergence so P2 evidence bundles and P3 reports consume real encrypted raw artifacts, captured flows, deterministic redaction data, replay/custody metadata, and integrity roots.
- P4 hard-middle intelligence with guarded JavaScript harvesting, two-session authorization-diff evidence, prompt-guarded LLM narrative assistance, schema validation, and scheduler/preflight-controlled action planning.
- Expanded P5 multi-chain static web3 analysis with audited Sourcify → Etherscan → Blockscout → Routescout resolution, verified compiler/ABI provenance, encrypted bytecode/disassembly artifacts, Slither + Aderyn corroboration, bounded Mythril analysis, SWC mapping, immutable engine/finding provenance, read-only RPC enforcement, and deterministic web3 report sections.
- P6 restart-safe operational runtime with encrypted committed stage boundaries, per-scan and per-tool budgets, redaction-aware structured logs, durable-first backpressure fanout, and active temp/process/orphan-chunk cleanup.
- P7 release-blocking platform threat model covering prompt injection, artifact traversal, loopback SSRF, compromised tools, key leakage, redaction DoS, authorization-diff misuse, web3 write escalation, crash/resume confusion, slow clients, and cleanup leakage with explicit mitigation/test/residual-risk mappings.
- P8 versioned schema envelopes, persisted schema/API compatibility metadata, current+previous readers, current-only writers, and an evidence-preserving paired down-migration mechanism with mandatory backup and destructive-SQL rejection.

### Breaking changes
- `3.0.0` freezes the P0–P8 public wire contracts listed above. Any incompatible post-freeze change requires an explicit compatibility/migration note; patch-level changes may only extend these contracts compatibly.
- New v3 reports require a closed evidence bundle and a hash-addressed verification record for every rendered claim. A missing verification record now fails report generation rather than degrading silently.
- v3 release metadata is installed by `0030_v3_release.py`; its down path is intentionally evidence-preserving and does not remove historical v3 evidence tables/records.
- New writes use the current v2 API/schema contract; v1 remains readable only during its documented deprecation window.

### Changed
- Release version advanced to `3.0.0`; the pre-v3 SQL migration chain remains intact while `0030_v3_release.py` owns all new v3 tables.
- The threat model reflects P1 forensic capture as landed and treats uncovered attack surfaces as release blockers.
- Web3 High/Critical confidence is driven by inspectable source evidence and/or independent engine corroboration; bytecode-only or exploitation-required cases remain `needs-human-review`.
- Migration rollback is no longer an implicit/destructive operation: only paired safe rollback contracts may execute, and historical evidence is retained.

### Security
- Existing C1–C7 constraints remain unchanged: no new v3 path bypasses preflight, scope, consent, rate governance, encryption, audit, or scheduler ownership.
- No P5 path sends transactions, forks/deploys contracts, signs data, or performs state-changing RPC.
- P6 durable persistence occurs before bounded UI fanout, so a slow client cannot cause evidence loss; cleanup actively removes registered temp artifacts/processes and fails closed if residue remains.
- R5 verification records are immutable encrypted P1 artifacts; report claims resolve to those records instead of relying on narrative trust.

## [2.3.0] - 2026-09-15

### Added
- P3 deterministic evidence-only finding and chain reports generated exclusively from normalized findings plus closed, hash-valid P2 evidence bundles.
- Canonical Markdown and self-contained inline-CSS HTML with stable ordering, evidence-derived timestamps, explicit CVSS v3.1 vectors/scores, captured-flow replay handles, detector provenance, duplicate context, impact, remediation, and observation-only reproduction.
- Deterministic redaction views for captured request/response headers, bodies, URLs, and raw detector-output slices without mutating encrypted source evidence.
- Redacted HAR export, redacted screenshot-only export, SHA-256 attachment manifests, and platform payloads for HackerOne, Jira, and GitHub without performing remote side effects.
- Strict encrypted P3 report-submission lifecycle `draft → queued → submitted → acknowledged → closed`, with every state transition hash-chained through the audit log and persisted in append-only history.
- P3 acceptance tests covering CVSS metric options, byte-identical renders, secret-free exports with real captured-flow references, chain narratives/severity, bundle-integrity refusal, and non-regressing audited submission state.

### Changed
- P3 report generation fails closed when a P2 evidence bundle is missing, incomplete, or fails flow/artifact integrity revalidation; it does not fall back to model-authored claims.
- Browser-observed evidence is exportable only when an explicit redacted screenshot artifact exists. Raw encrypted screenshots remain non-exportable.
- Existing legacy bounty `SubmissionTracker` remains compatible; the narrower P3 delivery lifecycle is implemented separately rather than rewriting historical submission semantics.

### Security
- P3 report/HTML/export surfaces contain only deterministic redacted views. Authorization headers, cookies, tokens, passwords, API keys, credentials, and secret-shaped fields are removed from exported evidence views.
- HTML reports make no external network fetches, and P3 output contains no render-time wall clock, avoiding nondeterministic content and external asset leakage.
- At the time of the 2.3.0 phase snapshot, missing P1 prerequisites were handled fail-closed; v3.0.0 subsequently lands the P1 forensic-capture convergence.

## [2.2.0] - 2026-09-15

### Added
- P2 deterministic `windeep.evidence-bundle.v1` records binding findings to persisted flow IDs plus content hashes, raw artifact SHA-256 plus validated line ranges, detector provenance graphs, calibrated confidence, exploitability state, and observation-only reproduction handles.
- Encrypted content-addressed `evidence_blobs` storage as the minimum immutable artifact primitive required for P2 integrity checks.
- Append-only evidence-bundle history with stable canonical JSON, SHA-256 bundle identity, explicit supersession, completeness scoring, and corruption revalidation on bundle resolution.
- Reflection/browser-specific evidence slots for inert reflected-marker observations, screenshot artifact hashes, final URL/status, and viewport metadata.
- P2 acceptance tests for byte-stable bundle generation, flow/artifact corruption failure, High/Critical completeness closure, closed exploitability values, and append-only supersession.

### Changed
- Evidence-bundle closure is fail-closed: missing captured flow, raw tool slice, provenance, replay handle, or required specialized evidence leaves the bundle incomplete instead of fabricating proof.
- Exploitability is intentionally limited to `observed` and `needs-human-review`; evidence that would require exploit execution cannot be promoted to a synthetic `confirmed` state.

### Security
- P2 performs no exploit execution. It binds and validates persisted evidence, and bundle/artifact payloads remain encrypted at rest with context-specific AAD.

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
- V2 report generation, report export, scan-event replay, scan cancellation, and intelligence reads require live preflight authorization derived from the encrypted scan authorization reference.
- Existing global finding deduplication remains intact for compatibility; P0 adds encrypted per-tool-run `scan_findings` records rather than rewriting the evidence-bearing `findings` table.
- Refreshed release workflow action majors while preserving the G1-G21 tag-release sequence.
- Release tooling rejects an empty tool manifest instead of silently producing an incomplete installer.

### Security
- SSE export payloads receive a deterministic secret-safety pass before persistence/broadcast.
- Post-execution chain/hypothesis stages use rule-based fallback where no guarded model provider is configured.

## [0.1.0] - 2026-09-15

### Added
- Initial public project scaffold based on the Windeep master blueprint.
