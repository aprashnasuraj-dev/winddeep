# Windeep threat model

This document is the release-blocking threat model for Windeep v3. Every attack surface introduced by P0-P8 and the v3 release workstreams must have a concrete threat, mitigation, executable regression test, and residual-risk statement. **A phase cannot close while an uncovered threat remains.**

## Trust boundaries and security invariants

Windeep is a loopback-only authorized-security-testing application. Targets, HTTP flows, JavaScript, smart-contract source, deployed bytecode, third-party tool output, LLM-visible text, imported program scope, target-class declarations, handling policies, and report fields are untrusted input. The authenticated local operator may select targets and tools but cannot bypass scope, consent, rate, crypto, audit, evidence integrity, verification, or scheduler controls.

P0 owns scheduler/preflight/event ordering. **P1 forensic capture** owns encrypted raw artifacts, custody metadata, hashes, redaction maps, replay inputs, and raw HTTP evidence. P2 binds findings to immutable evidence. P3 renders deterministic evidence-only reports. P4 handles guarded hard-middle/LLM assistance. P5 adds static/read-only web3 analysis. P6 adds restart recovery, budgets, observability, backpressure, and cleanup. P7 makes this model release-blocking. P8 governs compatibility and evidence-preserving schema change. V3-A broadens target classes without broadening authority.

Tool subprocesses remain inside the guarded wrapper/scheduler boundary. Target HTTP remains inside the capture/interceptor boundary. Web3 access is read-only. Exploitation-required conclusions remain `needs-human-review`; Windeep does not autonomously exploit, transact, fork, deploy, sign, or mutate a target.

## P7 platform closeout

### Prompt injection from malicious target content

**Threat.** HTML, JavaScript, HTTP bodies, detector output, repository text, verified contract source, or bytecode-derived strings may contain instructions intended to make a model escape scope, invoke a tool, fabricate evidence, or promote an unsupported conclusion.

**Mitigation.** P4 labels/bounds target-derived text, uses the existing prompt guard and LLM client, validates structured output, audits invalid output, and gives the model no direct tool authority. Proposed actions must return to the scheduler and pass live preflight. Deterministic P0-P3 evidence never depends on model-authored proof.

**Tests.** `tests/test_p4_hard_middle.py` covers adversarial target instructions, schema rejection, evidence attribution, and non-tool-invoking model behavior. P0 scheduler/preflight tests prove denied actions never reach runners.

**Residual risk.** Model/provider changes can discover new injection patterns or change narrative quality. Model text therefore remains assistance, never evidence, and provider changes require regression testing.

### Artifact path traversal

**Threat.** Target-controlled paths, archive members, URLs, source-tree names, detector labels, or export names may attempt traversal, absolute writes, symlink escape, or plaintext writes outside encrypted state/temp storage.

**Mitigation.** P1 uses encrypted content-addressed artifact identities rather than target filenames. P6 restricts registered temp files to encrypted-temp and actively sweeps them. Release/tool staging retains archive path-safety checks; P5 web3 artifacts reuse P1 custody.

**Tests.** `tests/test_p1_forensic_capture.py`, `tests/test_p6_operational.py`, and `tests/test_p6_operational_depth.py` cover encrypted storage, outside-temp rejection, and cleanup. Release staging tests reject unsafe archive members.

**Residual risk.** Third-party tools can still emit path-looking strings as data. Any future feature that materializes those strings as paths must add canonicalization/symlink tests before release.

### SSRF against the loopback control plane

**Threat.** Redirects, imported URLs, replay inputs, browser navigation, or malicious target content may try to redirect target-facing traffic toward `127.0.0.1`, `::1`, or another unauthorized destination.

**Mitigation.** Scope/consent are fail-closed and revalidated before target-facing actions. P1 replay preserves captured identity, P4 auth-diff uses authorized captured flows, V3-A literal-IP replay pins the declared IP, and the dashboard remains loopback-only while target traffic remains in capture/wrapper code.

**Tests.** P0 scope/preflight tests, `tests/test_p1_forensic_capture.py`, `tests/test_p4_hard_middle.py`, and `tests/test_v3_target_classes.py` exercise authorization boundaries and pinned target identity.

**Residual risk.** Third-party scanners/browsers own redirect behavior. Final-destination enforcement must be retested whenever those components are upgraded.

### Compromised tool binary

**Threat.** A replaced Slither, Aderyn, Mythril, recon tool, browser, or catalog binary can reinterpret argv, inspect unexpected environment values, emit malicious parser input, or fabricate internally consistent results.

**Mitigation.** Process creation stays in the wrapper boundary; shell interpolation is prohibited. P1 records invocation/raw-output provenance. P2/P5 bind findings to engine/version/detector/upstream/raw artifacts, and P5 preserves independent-engine corroboration instead of treating one engine as authoritative.

**Tests.** `tests/test_p1_forensic_capture.py`, tool-wrapper tests, `tests/test_p5_web3_depth.py`, and `tests/test_p5_web3_validation.py` verify invocation custody, maintained-engine provenance, SWC/location mapping, and corroboration.

**Residual risk.** A compromised binary may still emit plausible false output. Provenance makes the event attributable; independent corroboration and human review reduce but cannot eliminate supply-chain risk.

### Leaked master key

**Threat.** Theft of the local master key can expose encrypted artifacts, flows, findings, authorization references, logs, target declarations, and web3 evidence.

**Mitigation.** P1 uses per-scan encrypted artifact custody and context-specific AAD; later phases reuse those stores rather than introducing plaintext evidence. Hash/custody roots detect silent mutation even if confidentiality is lost.

**Tests.** `tests/test_p1_forensic_capture.py` and crypto/secure-database tests validate encrypted payloads, authenticated decryption, hashing/custody, and absence of plaintext evidence.

**Residual risk.** A live compromise that controls the active process/key can read evidence legitimately opened by that process. Rotation/per-scan destruction limits historical blast radius but cannot prevent live-process disclosure.

### Operator-supplied redaction regex DoS

**Threat.** Pathological user regexes can cause catastrophic backtracking/CPU denial during export and overly broad rules can erase triage value.

**Mitigation.** P1/P3 use deterministic bounded secret semantics and versioned redaction behavior rather than arbitrary regex execution on the hot path. Stable placeholders/maps keep exports reproducible. Any future custom-regex adapter must be length/complexity/time bounded.

**Tests.** `tests/test_p1_forensic_capture.py` and `tests/test_p3_reporting.py` verify deterministic redaction and secret-free Markdown/HTML/HAR/attachments.

**Residual risk.** Bounded detectors can miss novel secret shapes or over-redact benign data; operators must inspect redacted exports before submission.

### Authorization-diff session misuse

**Threat.** A user/model may invent credentials, swap unrelated sessions, compare principals outside intent, or replay state-changing requests to try to confirm an authorization flaw.

**Mitigation.** P4 accepts two operator-supplied authorized sessions and captured in-scope read-only flows. It stores byte-level comparison evidence and uses `needs-human-review` where stronger confirmation would require exploitation. It never guesses credentials, mints sessions, or mutates a request into an exploit.

**Tests.** `tests/test_p4_hard_middle.py` covers two-session attribution, bounded diffs, injection resistance, and unsupported-conclusion refusal; P1 replay tests preserve captured-request provenance.

**Residual risk.** Two legitimate sessions can still represent business roles whose intended policy is unknown. A difference is evidence for review, not proof of authorization failure.

### Web3 write-RPC escalation

**Threat.** A chain adapter, symbolic engine, resolver, or later model plan may escalate static inspection into transaction sending, signing, deployment, fork mutation, or state change.

**Mitigation.** P5 exposes a positive read-only RPC allowlist, audited resolver ordering, cached encrypted source/bytecode/disassembly, bounded Mythril, and no fork/sign/deploy path.

**Tests.** `tests/test_p5_web3_depth.py` spies on RPC calls and verifies resolver/compiler/bytecode/corroboration behavior; `tests/test_p5_web3_validation.py` asserts write-RPC denial.

**Residual risk.** A compromised third-party binary may behave outside Windeep's RPC abstraction. Engine pins/binary provenance remain required.

### Crash-resume state confusion

**Threat.** A crash/restart may rerun completed work, skip incomplete work, overwrite newer evidence, or mark a partial scan complete.

**Mitigation.** P6 stores encrypted committed stage boundaries and only commits after success. V3 release wiring adds its own ordered release-stage checkpoints/transitions above P0-P8. Budgets persist and exhaustion marks work incomplete.

**Tests.** `tests/test_p6_operational.py`, `tests/test_p6_operational_depth.py`, and `tests/test_v3_release_wiring.py` prove restart resume, failed-stage non-commit, budget failure, and v3 transition replay.

**Residual risk.** Windeep cannot roll back side effects of a misbehaving third-party tool immediately before host failure; state-changing tools remain excluded.

### Slow-client backpressure

**Threat.** A slow/disconnected SSE/browser client can fill queues, block scan progress, or lose visible events.

**Mitigation.** Durable persistence precedes bounded non-blocking UI fanout. Dropped live delivery does not remove durable evidence; persisted replay is authoritative.

**Tests.** `tests/test_p6_operational.py` and `tests/test_p6_operational_depth.py` prove bounded queues and durable-first fanout.

**Residual risk.** A client may miss live display and need `Last-Event-ID` replay; the durable event/evidence store remains authoritative.

### Plaintext temp or orphan-process leakage

**Threat.** Crash/cancellation may leave plaintext temp files, subprocesses, browser/tool handles, or orphan artifact chunks after a scan.

**Mitigation.** Temps are restricted to encrypted-temp. P6 actively unlinks registered temps, terminates then kills stubborn registered processes, sweeps orphan chunks, and fails closed if residue remains.

**Tests.** `tests/test_p6_operational.py` and `tests/test_p6_operational_depth.py` verify leak detection, active deletion, graceful/forced process shutdown, orphan sweeping, and outside-temp rejection.

**Residual risk.** An unregistered process cannot be cleaned. C7 therefore requires background work to be scheduler-owned and registered.

## V3-A target-surface expansion

### IP/CIDR declaration used as a preflight bypass

**Threat.** Raw IPs, CIDRs, IP ranges, IP-addressed HTTPS, IPv6, or unusual ports could be treated as discovery output and tested without the same explicit authorization used for domain targets.

**Mitigation.** Every V3-A target is a persisted declaration containing class, value, explicit port set, consent token id, and justification. CIDR/IP-range declarations additionally require `max_hosts`. `TargetDeclarationStore.declare()` runs the same live `PreFlightGuard` before persistence; `authorize_route()` re-runs preflight immediately before a target send. CIDR planning re-authorizes the declared range before host selection. No reverse-DNS/certificate name expands scope.

**Tests.** `tests/test_v3_target_classes.py` declares every supported target class, requires consent/justification, verifies deterministic capped CIDR planning/rate acquisition/audit, and proves PTR output does not create a target.

**Residual risk.** A very broad authorized range can still create operational load. To preserve P6 resource budgets while auditing every candidate, one declaration is limited to 4096 auditable candidate hosts; larger ranges must be split into separately justified/consented declarations.

### Undeclared SNI, Host, or non-standard port injection

**Threat.** A scanner might connect to an authorized IP while silently substituting an undeclared SNI, HTTP `Host`/`:authority`, or port, effectively testing a different virtual service.

**Mitigation.** Ports, SNI values, and Host values are declaration fields, not discovery hints. `authorize_route()` rejects an undeclared value before the connector is invoked and records a denial audit event. The capture-layer connector never invents DNS names and keeps the socket destination literal.

**Tests.** `tests/test_v3_target_classes.py` injects undeclared SNI/Host/port values and asserts connector invocation count remains zero.

**Residual risk.** A permitted Host/SNI can still route within a multi-tenant service according to server configuration. Authorization therefore depends on the operator having explicitly declared that exact virtual-host value.

### Literal-IP TLS verification ambiguity

**Threat.** HTTPS by IP may fail normal certificate-name validation, omit SNI, expose a different default certificate, or tempt the scanner to treat certificate mismatch as a transport error and silently retry against a hostname/DNS address.

**Mitigation.** V3-A pins the literal IP. It records separate IP-SAN and SNI-less verification attempts as evidence, including peer/server IP, SNI/Host sent, TLS version/cipher, certificate fingerprint, best-available chain, and verification outcome. A validation failure may be observed read-only against the same already-authorized IP; it never changes the destination. IP replay remains pinned to the original literal IP.

**Tests.** `tests/test_v3_target_classes.py` verifies two cert-backed flows, additive HAR metadata, and IP-pinned replay. `tests/test_v3_ip_tls_connector.py` covers successful IP-SAN verification, captured certificate mismatch, SNI-less IPv4/IPv6 behavior, bounded response capture, transport preflight/rate recheck, and failure handling.

**Residual risk.** Python/OpenSSL may expose only the leaf certificate on some platforms. Windeep records `cert_chain_complete=false` rather than fabricating intermediates; operators requiring full chain custody should run on a transport/runtime that exposes the chain.

### IPv6 zone-id retargeting

**Threat.** A link-local IPv6 zone id such as `%eth0` is a host-local routing hint and can make the same textual target identify a different interface/context on another operator machine.

**Mitigation.** Zone/scope IDs are rejected at declaration/preflight. IPv6 services use portable `[address]:port` syntax and otherwise follow the same explicit ports, consent, rate, and evidence rules as IPv4.

**Tests.** `tests/test_v3_target_classes.py` asserts a zone-id declaration is refused before any target action.

**Residual risk.** Link-local addresses that legitimately require a zone cannot be tested by this portable v3 target class; operators must use a routable explicitly authorized address instead.

## Cross-phase evidence and reporting integrity

P1 forensic capture records immutable raw evidence. P2 validates hashes/provenance/completeness. P3 refuses corrupt or missing bundles and redacts before export. P4 adds guarded analysis but not proof. P5 extends provenance to chain/block/resolver/engine/detector/SWC. P6 makes completion and budgets durable. V3-A extends the frozen HAR `_winddeep` block additively and preserves literal-IP identity in replay.

Corrections append/supersede evidence; they do not rewrite historical evidence. `observed` and `needs-human-review` remain the only exploitability states. High/Critical closure requires the evidence depth defined by its producing phase.

## P7/v3 closure rule

Threat-model documentation is backed by executable release tests, not a substitute for controls. A new attack surface must add: (1) a named threat, (2) a concrete mitigation, (3) an executable test reference, and (4) a non-empty residual-risk statement. **Any uncovered threat blocks phase and release closure.**
