# Windeep v3 Threat Model

Status: release-blocking for v3.0.0. Scope: localhost Windeep application, scan scheduler, catalog tool wrappers, forensic evidence store, Brain/LLM narrative features, Web3 read-only audit path, exports, and offline packaging.

## Security invariants

1. No scan/tool/replay/evidence-export action bypasses live scope + consent preflight.
2. Target-controlled bytes are data, never instructions or executable configuration.
3. Subprocesses are launched with argv arrays and bounded environment; no shell interpolation and no `eval`/`exec` of parsed output.
4. Raw evidence is content-addressed, encrypted under per-scan DEKs, custody-logged, and sealed with a Merkle root.
5. Export surfaces redact secrets before bytes leave encrypted custody.
6. Web3 auditing is read-only: no signing, transaction submission, mining, account mutation, or state-changing RPC.
7. Schema/migration changes are additive and evidence-preserving.

## Threat register

| Threat | Attack surface | Mitigation | Release test/evidence | Residual risk |
|---|---|---|---|---|
| Prompt injection in HTTP/tool/JS content | Brain narrative and planning | `PromptGuard` marks target data `UNTRUSTED_TARGET_DATA`; P4 output schema contains narrative fields only; P7 model plans contain pre-approved task IDs only | `test_p4_hard_middle.py`, `test_p7_threat_controls.py` | A model can still produce misleading prose; evidence hashes and human review remain authoritative |
| Loopback/control-plane SSRF | URLs discovered in target content | `V3ThreatControls.assert_external_target` denies localhost, loopback, unspecified and link-local destinations; scan scope/preflight still applies | `test_target_ssrf_guard_blocks_loopback_and_local_control_plane` | DNS rebinding after validation requires resolver/connection-layer revalidation where network adapters resolve dynamically |
| Path traversal / unsafe artifact names | Export names, filenames, archive entries | Artifact labels must be basename-only, bounded, non-absolute and free of traversal/control characters | `test_artifact_label_rejects_path_traversal_and_absolute_paths` | Third-party unpackers may have independent archive bugs; Windeep must not trust extracted paths |
| Regex DoS through operator redaction terms | Export/redaction configuration | Operator terms are bounded literal strings, never compiled as supplied regex; count/length limits enforced | `test_redaction_terms_are_literal_bounded_and_cannot_be_regex_dos` | Built-in redaction regexes remain code and require normal review/fuzzing |
| Compromised or spoofed tool binary | Catalog process execution | Catalog allow-list, scope requirement, argv execution without shell, binary SHA-256 recorded in P1 custody, environment allow-list hash, bounded timeout/retry | P1 custody tests, P5 catalog contract, release audit | A legitimately installed malicious binary can lie in stdout; findings remain untrusted until evidence/provenance/human validation |
| Malicious tool stdout/JSON | Parsers, findings, Brain input | Parsed output is bounded data; schema normalization; no `eval`; P7 output depth/item/text budgets; Brain wraps evidence as untrusted | P4 prompt tests, P7 `validate_tool_output` tests | Parser logic can still contain implementation bugs; fuzz/property tests should grow over time |
| Leaked application master key | Encrypted database/evidence | P1 uses per-scan random DEKs wrapped by the application crypto layer; retention can destroy scan keys; evidence is content-addressed and Merkle sealed | `test_p1_raw_capture.py` key-destruction/Merkle tests | A live compromise with access to master key and wrapped scan DEKs can decrypt retained evidence; OS/account hardening remains required |
| Evidence tampering | DB/artifact chunks, reports | Chunk hashes + artifact SHA-256, flow hashes, bundle hashes, append-only audit chain, scan Merkle root, P3 revalidation before rendering | P1/P2/P3 convergence tests | Attackers controlling both storage and live application key material may forge new state; external notarization is outside v3 scope |
| Secret leakage through exports/logs | HAR, reports, SSE, structured logs | Deterministic redaction maps, export sanitization, structured logger secret-key redaction | P1 HAR tests, P3 report tests, P6 structured-log tests | Unknown secret formats may evade built-in rules; operator literal terms provide an additional bounded layer |
| Slow consumer / memory pressure | SSE/event streaming | Bounded backpressure buffer drops oldest events instead of blocking scan execution; replayable DB event log remains source of truth | P6 backpressure test | Excessive event generation can still increase DB size; scan budgets and retention apply |
| Crash/restart ambiguity | Scheduler and reports | Append-only committed stage checkpoints; resume derives next stage from DB/artifact store, never in-memory guesses | P6 checkpoint restart test | Non-idempotent external tools can still differ after restart; captured run IDs/provenance distinguish reruns |
| Disk exhaustion / residue | Artifact capture and temp files | Artifact-byte budget; scan-end sweeper flags plaintext temp residue and relational evidence orphans | P6 budget/sweeper tests | OS-level full-disk failure can interrupt cleanup; next startup/release diagnostics must rerun sweeper |
| Web3 state change | JSON-RPC, analysis engines | Strict read-only RPC allow-list; Slither/Mythril static/read-only inputs; Aderyn corroboration-only; no transaction/signing methods | P5 no-write spy and expanded Web3 tests | `eth_call` executes only simulated EVM state; node/provider trust remains external |
| Dependency/tool version drift | Reproducibility | P5 engine version pins, input/output SHA-256, compiler divergence recorded explicitly, release dependency audit/SBOM | P5 catalog/compile-divergence tests, release workflows | Remote providers can change responses; cached source/bytecode hashes preserve what was actually analyzed |

## Release closure rule

A phase cannot be marked complete when it introduces a threat without a documented mitigation, automated test or reproducible audit evidence, and a stated residual risk. Any exception must be recorded as a release-blocking limitation rather than silently waived.
