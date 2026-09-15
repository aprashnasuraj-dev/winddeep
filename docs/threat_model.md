# Windeep threat model

This document is the release-blocking threat model for Windeep v3. Every attack surface introduced by P0-P6 must have a concrete threat, mitigation, regression test, and residual-risk statement. **A phase cannot close while an uncovered threat remains.** New attack surfaces must extend this document and add a test before release.

## Trust boundaries and security invariants

Windeep is a loopback-only authorized-security-testing application. Targets, HTTP flows, JavaScript, smart-contract source, deployed bytecode, third-party tool output, LLM-visible text, imported program scope, and exported report fields are untrusted input. The authenticated local operator may select targets and tools but cannot bypass scope, consent, rate, crypto, audit, evidence integrity, or scheduler controls.

P0 owns scheduler/preflight/event ordering. **P1 forensic capture** owns encrypted raw artifacts, custody metadata, hashes, redaction maps, and replay inputs. P2 binds normalized findings to immutable evidence. P3 renders evidence-only reports/exports. P4 handles guarded hard-middle/LLM assistance. P5 adds static/read-only web3 analysis. P6 adds restart recovery, budgets, structured observability, backpressure, and cleanup.

Tool subprocesses are permitted only through the guarded wrapper/scheduler path. Target HTTP is permitted only through the capture/interceptor path. Web3 chain access is read-only. Exploitation-required conclusions remain `needs-human-review`; Windeep does not autonomously exploit, transact, fork, deploy, sign, or mutate a target.

## P7 platform closeout

### Prompt injection from malicious target content

**Threat.** HTML, JavaScript, HTTP bodies, detector output, repository text, verified contract source, or bytecode-derived strings can contain instruction-like content intended to override system intent, cause a model to invoke tools, fabricate evidence, escape scope, or promote a hypothesis to a finding.

**Mitigation.** P4 treats all target-derived content as untrusted data, bounds and labels it before model use, routes model interaction only through the existing `llm_client`/`prompt_guard` boundary, validates structured model output, and drops plus audits invalid output. The model cannot invoke tools directly: any proposed action must become a scheduler plan and pass live `PreFlightGuard`. P0-P3 evidence/report stages remain deterministic and do not depend on model-authored proof.

**Tests.** `tests/test_p4_hard_middle.py` exercises adversarial instruction text, schema rejection, evidence attribution, and non-tool-invoking model behavior. P0 preflight-spy tests additionally prove that a denied scheduler action never reaches a runner.

**Residual risk.** A future model/provider change can alter narrative quality or discover new prompt-injection patterns. Structured validation constrains authority, but reviewers must still treat LLM narrative as assistance rather than evidence and keep provider/version changes behind regression tests.

### Artifact path traversal

**Threat.** Target-controlled filenames, URLs, archive members, source-tree paths, detector labels, or export names could attempt `../` traversal, absolute-path writes, symlink escape, or plaintext writes outside Windeep's encrypted state/temp boundaries.

**Mitigation.** P1 forensic capture stores evidence through the encrypted, content-addressed artifact layer instead of using target-derived filesystem paths. Temporary files are restricted to the encrypted-temp namespace and P6 `CleanupSweeper.register_temp()` refuses paths outside that root. Release/tool staging retains archive-member path-safety checks. P5 source, bytecode, disassembly, and engine output reuse P1 artifact references rather than direct filesystem writes.

**Tests.** `tests/test_p1_forensic_capture.py` covers encrypted artifact custody and safe storage behavior. `tests/test_p6_operational.py` and `tests/test_p6_operational_depth.py` cover encrypted-temp cleanup and rejection of outside paths. Existing release staging tests cover unsafe archive paths.

**Residual risk.** Third-party tools can emit path-looking strings into stdout or source maps; they are preserved as data. Any future feature that materializes those strings as paths must add canonicalization/symlink tests before the phase can close.

### SSRF against the loopback control plane

**Threat.** Redirects, imported URLs, browser navigation, replay inputs, or malicious target content could attempt to make a target-facing component request Windeep's own `127.0.0.1`/`::1` control plane or another out-of-scope host.

**Mitigation.** Scope and consent are fail-closed and revalidated immediately before target-facing actions. P1 capture/replay retains canonical target identity and evidence provenance; P4 auth-diff uses already authorized captured flows rather than arbitrary URLs; P5 chain resolution accepts a scoped contract address and exposes only read RPC methods. The dashboard itself remains loopback-only, while target traffic stays in the guarded capture/wrapper boundary.

**Tests.** P0 scope/preflight tests assert out-of-scope denial. `tests/test_p1_forensic_capture.py` covers captured-flow/replay custody. `tests/test_p4_hard_middle.py` covers bounded authorization-diff inputs. P5 tests assert the read-only RPC surface.

**Residual risk.** Third-party scanners and browsers implement their own redirect stacks. Redirect-final-destination enforcement therefore remains a boundary that must be retested whenever a wrapper/browser engine is upgraded.

### Compromised tool binary

**Threat.** A replaced or compromised Slither, Aderyn, Mythril, recon utility, browser binary, or other catalog executable could reinterpret argv, read unexpected environment values, emit malicious parser input, or produce misleading findings.

**Mitigation.** Process creation remains in the catalog/tool-wrapper boundary; shell interpolation is prohibited. P1 forensic capture records command/argv identity, tool version, binary provenance/hash where available, bounded environment metadata, exit status, and raw output artifacts. P2/P5 provenance binds normalized findings back to engine/version/detector and immutable raw artifacts. P5 cross-engine corroboration records independent engine agreement instead of silently treating one tool as authoritative.

**Tests.** `tests/test_p1_forensic_capture.py` covers raw invocation/evidence custody. Existing tool-wrapper tests cover argv/process contracts. `tests/test_p5_web3_depth.py` and `tests/test_p5_web3_validation.py` verify engine provenance, SWC mapping, corroboration, and immutable raw-output references.

**Residual risk.** A compromised binary can still emit internally consistent but false output. Hash/provenance makes the event attributable; independent-engine corroboration and human review reduce, but do not eliminate, this supply-chain risk.

### Leaked master key

**Threat.** Theft of the local master key can expose encrypted artifacts, flows, findings, scan authorization references, structured logs, and web3 source/bytecode evidence.

**Mitigation.** P1 forensic capture separates evidence into encrypted, content-addressed records with context-specific AAD and scan custody metadata; P0/P2/P3/P5/P6 continue using encrypted database/artifact paths rather than introducing plaintext evidence stores. Scan evidence can be independently integrity-checked by content digests/custody roots, limiting silent tampering even if confidentiality is lost.

**Tests.** `tests/test_p1_forensic_capture.py` validates encrypted artifact payloads, hashing/custody, and no plaintext source evidence. Existing crypto/secure-database tests validate authenticated decryption failure and encrypted sensitive fields.

**Residual risk.** A live compromise with access to the active key and process memory can decrypt data available to that process. Key rotation/per-scan destruction limits historical blast radius but cannot protect evidence while legitimately open in the compromised process.

### Operator-supplied redaction regex DoS

**Threat.** A pathological user-provided regular expression can cause catastrophic backtracking and CPU denial of service during report/HAR/artifact export; overly broad patterns can also destroy triage value.

**Mitigation.** Core P1/P3 redaction uses versioned, deterministic bounded rules and fixed secret semantics rather than executing arbitrary operator regexes in the hot export path. Stable placeholders and redaction metadata make repeated exports reproducible. If operator-defined patterns are accepted by a future adapter, they must be length/complexity bounded and time-limited before becoming active.

**Tests.** `tests/test_p1_forensic_capture.py` covers deterministic redaction/custody behavior and `tests/test_p3_reporting.py` verifies that secrets are absent from Markdown, HTML, HAR, and attachment manifests while evidence references remain stable.

**Residual risk.** Fixed/bounded detectors can miss novel secret shapes or over-redact benign values. Operators must inspect redacted exports before submission, and any future arbitrary-regex feature requires dedicated worst-case CPU tests.

### Authorization-diff session misuse

**Threat.** A user or model could misuse P4 authorization-diff analysis by inventing credentials, swapping sessions outside operator intent, comparing unrelated principals, or replaying state-changing requests in an attempt to confirm an authorization flaw.

**Mitigation.** P4 accepts two operator-supplied authorized sessions and uses captured, in-scope, read-only flows. It produces a byte-level comparison artifact and `needs-human-review` evidence where stronger confirmation would require exploitation. It does not guess credentials, mint sessions, mutate request bodies into exploit payloads, or bypass replay/preflight policy.

**Tests.** `tests/test_p4_hard_middle.py` covers two-session attribution, bounded diff artifacts, prompt injection resistance, and refusal to elevate unsupported conclusions. P1 replay tests protect exact captured-request provenance.

**Residual risk.** Two valid sessions can still represent roles whose business semantics are unknown to Windeep. A response difference is therefore evidence for triage, not proof that the authorization policy is wrong.

### Web3 write-RPC escalation

**Threat.** A web3 adapter, symbolic engine integration, resolver, or later model plan could escalate from static/read-only inspection into `eth_sendTransaction`, `eth_sendRawTransaction`, signing, deployment, fork mutation, or other state-changing behavior.

**Mitigation.** P5 exposes a positive read-only RPC allowlist through `ReadOnlyRPC`; source resolution uses only chain id, pinned-block lookup, deployed bytecode, and other explicitly read-only methods. Verified-source resolution is audited in the fixed Sourcify → Etherscan → Blockscout → Routescout order. Static engines consume encrypted cached artifacts. Mythril execution is bounded and used for static/symbolic inspection only. No fork, transaction, signing, deployment, or executable calldata validation exists in the P5 path.

**Tests.** `tests/test_p5_web3_depth.py` spies on RPC calls and proves that write methods are absent, covers resolver fallback/compiler pinning/bytecode disassembly/corroboration, and verifies bytecode-only results remain `needs-human-review`. `tests/test_p5_web3_validation.py` additionally asserts direct write-RPC calls fail closed.

**Residual risk.** A third-party engine can contain unexpected behavior outside Windeep's RPC abstraction. Process/network sandboxing is not a substitute for supply-chain trust, so maintained engine pins and binary provenance remain required.

### Crash-resume state confusion

**Threat.** A process crash or restart can cause completed stages to rerun, skipped stages to be treated as committed, stale transient state to overwrite newer evidence, or a partially failed scan to be marked complete.

**Mitigation.** P6 persists encrypted stage checkpoints and resumes only from committed boundaries. `ScanResumeCoordinator.run_stage()` returns committed outputs without rerunning work and commits a new boundary only after the callback succeeds. P0/P2 evidence writes remain idempotent/append-oriented. P6 scan and per-tool budgets are persisted, and budget exhaustion moves the scan to `incomplete` rather than `complete`.

**Tests.** `tests/test_p6_operational.py` simulates a fresh coordinator reading prior committed boundaries. `tests/test_p6_operational_depth.py` proves committed work is skipped, a failing callback is not checkpointed, per-tool budget exhaustion is fail-closed, and only an active budget may transition to complete.

**Residual risk.** External tools may have performed non-Windeep-local work immediately before a host crash. Windeep can recover its committed evidence/stage state, but cannot roll back side effects of a misbehaving third-party tool; this is another reason state-changing tools are excluded.

### Slow-client backpressure

**Threat.** A slow or disconnected browser/SSE consumer can fill an event queue, block scheduler progress, or cause findings/evidence to be discarded when the UI cannot keep up.

**Mitigation.** Durable evidence/event persistence happens before UI fanout. P6 `BackpressureChannel` is bounded and non-blocking; once full, it records a dropped delivery attempt rather than blocking the producer. `DurableFanout` persists first and then attempts UI delivery, so a dropped UI event does not mean lost scan evidence.

**Tests.** `tests/test_p6_operational.py` proves bounded queue behavior. `tests/test_p6_operational_depth.py` verifies durable persistence of both events even when the second UI enqueue is dropped.

**Residual risk.** A client can miss live events and need persisted replay to catch up. Operators should treat the durable event/evidence store as authoritative and the live stream as a convenience view.

### Plaintext temp or orphan-process leakage

**Threat.** A crash/cancellation path can leave plaintext temporary files, child processes, browser/tool handles, or unreferenced artifact chunks behind after a scan ends.

**Mitigation.** Temporary evidence is restricted to the encrypted-temp namespace. P6 `CleanupSweeper` actively unlinks registered temp files, terminates then kills stubborn registered processes within a bounded timeout, invokes the orphan-chunk sweeper, and finally fails the cleanup invariant if any registered temp/process/chunk remains.

**Tests.** `tests/test_p6_operational.py` verifies that leaked files/running processes make `assert_clean()` fail. `tests/test_p6_operational_depth.py` verifies active deletion, normal termination, forced kill of a stubborn process, orphan-chunk sweeping, and rejection of temp registrations outside encrypted-temp.

**Residual risk.** A process unknown to the scheduler cannot be registered or cleaned by this mechanism. C7 therefore remains important: background processes/threads must be scheduler-owned and registered, otherwise the phase cannot close.

## Cross-phase evidence and reporting integrity

P1 forensic capture records immutable raw evidence. P2 validates hashes, provenance, and completeness. P3 refuses to render evidence-backed reports from missing or corrupt bundles and redacts before export. P4 adds narrative/analysis but not proof. P5 extends provenance to chain id, contract address, pinned block, resolver response hash, source/bytecode/disassembly artifacts, engine/version/detector/SWC, and cross-engine corroboration. P6 makes stage completion and budgets durable across restart.

Corrections append/supersede evidence; they do not rewrite historical evidence in place. `observed` and `needs-human-review` remain the only exploitability states. High/Critical closure requires the evidence depth defined by the phase that produced the finding.

## P7 closure rule

P7 is documentation backed by executable release tests, not a substitute for controls. When a new attack surface is introduced, the owning PR must add or update: (1) a named threat here, (2) its concrete mitigation, (3) an executable test reference, and (4) a non-empty residual-risk statement. **Any uncovered threat blocks phase and release closure.**
