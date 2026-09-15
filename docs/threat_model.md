# Windeep threat model

This document tracks threats to the Windeep platform itself. It is a release requirement: changes that add an attack surface must add a mitigation, a test, and a residual-risk statement here.

## Trust boundaries

Windeep is a loopback-only authorized-security-testing application. Targets, captured HTTP content, tool output, contract source, JavaScript, and model-visible evidence are untrusted. The local operator is authenticated but is not permitted to bypass scope, consent, rate, crypto, or audit controls. Tool wrappers are the only permitted subprocess/network execution boundary for in-scope scanning. Sensitive findings and scan-event payloads are encrypted at rest.

## P0 scheduler and event pipeline

### Guardrail bypass through alternate execution paths

**Threat.** A new scheduler path could invoke a wrapper, socket, subprocess, post-processing stage, report/export path, or evidence read without the canonical preflight checks.

**Mitigation.** `TaskScheduler` has no runnable mode without a `PreFlightGuard`. P0 authorizes the scan before runtime registration, at scheduler entry, immediately before each tool invocation, and before every post-processing stage. V2 cancellation, event replay, report generation/export, and intelligence reads recover the encrypted scan authorization reference and re-run preflight. Tool execution remains inside the existing wrapper catalog. There is no test/debug/replay bypass.

**Tests.** `tests/test_p0_pipeline.py::test_preflight_denial_never_reaches_runner` spies on the runner; existing preflight tests cover live consent and out-of-scope denial. P0 adds an assertion that scope denial is itself an audit event.

**Residual risk.** Legacy non-v2 endpoints predate this P0 wiring and are not refactored in the same phase, per the phase-isolation rule. They remain subject to their existing guards. A later dedicated hardening PR should consolidate read-side authorization without mixing that refactor into P0.

### Dependency confusion and partial-failure propagation

**Threat.** A failed passive-recon branch could feed invalid data to an active dependent, or one failed independent tool could destroy unrelated evidence.

**Mitigation.** Passive recon is declared explicitly as a dependency for active/web/network tasks. Dependents reject exception-valued dependency results. Independent task failures remain isolated; committed successful branches are retained and the scan closes as `completed_with_errors`. Post-processing consumes committed `scan_findings`, not transient task-local state.

**Tests.** P0 DAG tests assert explicit passive dependencies and overlapping independent work under the scheduler cap.

**Residual risk.** P0 declares dependencies by catalog category, not semantic dataflow inferred from tool output. A misclassified catalog entry can therefore be over- or under-constrained; catalog review remains required.

### SSE replay leakage or reordering

**Threat.** Reconnects could miss events, duplicate ordering, expose secrets, or allow a slow client to stall a scan.

**Mitigation.** Events receive a per-scan monotonically increasing sequence in an encrypted `scan_events` table. Replay is ordered by `(scan_id, seq)` and rejects gaps. The export payload is sanitized before encrypted persistence and broadcast. SSE reads the committed log and therefore cannot backpressure the scheduler itself.

**Tests.** P0 tests assert sequence `1,2,3`, replay from `Last-Event-ID`, gap-free ordering, schema versioning, and removal of known authorization/API-key values.

**Residual risk.** P0 uses a conservative deterministic masking pass, not the P1 versioned redaction-map system. P1 must add reproducible per-occurrence maps and broader secret-pattern coverage before evidence exports are considered final.

## Malicious target content

### Prompt injection from HTML, JavaScript, tool output, or contract source

**Threat.** Captured content may contain text such as “ignore previous instructions” intended to cause model-directed tool execution or fabricated conclusions.

**Mitigation.** P0 post-processing constructs `LLMClient([])`, forcing deterministic rule-based fallback; target content is not sent to an external model. `HypothesisEngine` additionally wraps untrusted context with `PromptGuard`. No model output can directly invoke a tool. P4 must preserve this boundary when external model providers are introduced for hard-middle analysis.

**Tests.** Existing prompt-guard tests cover instruction-like untrusted text. P4 will add explicit adversarial model-output tests.

**Residual risk.** `ChainBuilder` still builds an in-memory prompt string before the local heuristic fallback. Because there are no enabled providers in P0, that string leaves no trust boundary; enabling a provider here without adding the P4 prompt guard would be unsafe.

### Path traversal into artifact/state storage

**Threat.** Target-controlled filenames or URLs could attempt `../` traversal or write outside encrypted state.

**Mitigation.** P0 adds no target-derived filesystem write path. New P0 evidence is stored in SQLite through parameterized statements. Tool execution remains inside the wrapper layer. Existing capture/artifact path controls remain unchanged.

**Tests.** Existing capture and release guardrail tests cover allowed storage paths; P1 will extend artifact-store path tests.

**Residual risk.** External tools may report attacker-controlled path strings in stdout; these remain data, not paths consumed by P0.

### SSRF against Windeep loopback endpoints

**Threat.** A malicious target response could direct a scanner or browser toward Windeep’s own `127.0.0.1` control plane.

**Mitigation.** Scope enforcement is canonical and fail-closed. P0 does not add a direct HTTP client or socket path; all target traffic remains in existing wrappers/capture components, and the dashboard remains loopback-only.

**Tests.** Existing scope-enforcer and secure-server tests cover target authorization and remote dashboard rejection.

**Residual risk.** Individual third-party engines have their own redirect behavior; wrapper/capture policy must continue to enforce the final destination in later capture work.

## Compromised tool binary

### argv injection, environment leakage, and stdout spoofing

**Threat.** A compromised or replaced tool may interpret arguments unexpectedly, exfiltrate environment secrets, or emit crafted output that attempts to corrupt parsers/reports.

**Mitigation.** P0 introduces no direct `subprocess` or shell call and constructs no shell command strings. Execution remains in the catalog wrapper. Exported command metadata uses `<scope-bound target>`. Parser output is treated as untrusted structured data and serialized deterministically. Environment values are not placed in SSE events.

**Tests.** Existing tool-wrapper tests and release audits cover wrapper execution contracts; P0 tests cover export masking.

**Residual risk.** P0 does not yet record binary-path hashes or environment allowlist hashes. Those are P1 custody requirements.

## Master-key compromise

**Threat.** Theft of the master key could expose encrypted findings, scan events, settings, and authorization references.

**Mitigation.** Existing crypto remains the only encryption boundary; P0 does not introduce plaintext evidence files. Scan-event and scan-finding payloads are encrypted with context-specific AAD.

**Tests.** Existing crypto and secure-database tests verify encrypted sensitive fields and key handling.

**Residual risk.** P0 still relies on the current store key hierarchy. Per-scan DEKs, rotation, evidence Merkle roots, and limited-scope key destruction are P1 work and are necessary to reduce blast radius after a master-key leak.

## Malicious operator-supplied redaction term

**Threat.** A pathological regular expression could create CPU denial of service during export.

**Mitigation.** P0 does not accept operator-provided regular expressions. Its masking expressions are fixed, compiled application constants. P1 operator terms must use a bounded regex engine/time budget and versioned rules.

**Tests.** P0 export-redaction tests use fixed patterns; P1 will add regex-DoS fixtures before accepting custom terms.

**Residual risk.** Fixed P0 patterns are intentionally narrow and may miss novel secret formats; this is a leakage-coverage risk, not a regex-DoS risk.

## Evidence persistence compatibility

### Canonical finding dedup versus per-run custody

**Threat.** Rewriting the existing `findings` table to change uniqueness semantics could destroy historical evidence or break encrypted-store compatibility.

**Mitigation.** P0 leaves the existing table and index untouched. It adds encrypted `scan_findings` keyed by `(scan_id, tool_run_id, finding_fingerprint)` and batch-upserts those rows in one transaction. The existing canonical finding ID is referenced rather than rewritten.

**Tests.** P0 persists the same tool finding twice and asserts one `scan_findings` row for the tuple.

**Residual risk.** The canonical `findings` row still reflects the repository’s pre-P0 global fingerprint contract. Full immutable raw-output/flow custody is intentionally deferred to P1 rather than forced into a destructive P0 schema change.
