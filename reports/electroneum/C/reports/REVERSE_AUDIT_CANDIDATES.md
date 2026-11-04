# Independent Reverse Audit R — Evidence-Backed Candidate Ledger

This is an **unconfirmed candidate ledger**, not the confirmed-vulnerability report. This worker owns only new files under `reports/electroneum/C/reports/`, `reports/electroneum/C/reverse/`, and `.github/workflows/electroneum-reverse-independent-ci.yml`. All A–E existing reports, fixtures, workflows and automations are read-only.

## R-E-010 — Counterexample-first analysis of nil-header handling in transaction receipt RPC

**Status:** CONFIRMED TARGET-RUNTIME SOFTWARE DEFECT for a synthetically missing London header; **attacker-reachable security vulnerability remains OPEN/UNCONFIRMED**. Independent fail-closed oracle and scratch-only corrective mutation executed successfully. **Order:** Reverse pass #1, newest open E topic (followed by older E items, then D, C, B, A). **Threat:** untrusted or lower-privilege caller sends `eth_getTransactionReceipt` for an actual transaction; requires block header lookup to disappear while transaction index and receipts remain retrievable. No public node has been probed.

### 1. Vulnerability Detail with Proof of /electroneum-sc Git Codes/Sources

**Certified target:** Immutable Windeep source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, Git tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned Electroneum upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`. Historical archive SHA-256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` is provenance only.

- [`internal/ethapi/api.go:1571–1614`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1571-L1614) `PublicTransactionPoolAPI.GetTransactionReceipt`: transaction lookup → separate receipt lookup → London effective gas price path → `header,err:=HeaderByHash(ctx,blockHash)`. It checks `err` and immediately references `header.BaseFee` without testing `header != nil`.
- [`eth/api_backend.go:99–101`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L99-L101) `EthAPIBackend.HeaderByHash` returns `blockchain.GetHeaderByHash(hash),nil`; if no header exists, `(nil,nil)` is possible at this backend boundary.
- [`eth/api_backend.go:187–189,265–269`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L187-L269) `GetReceipts` and `GetTransaction` use distinct underlying data accesses. Separate reads permit a race *in principle*, but ordinary full-node canonicality and consistent DB writes may defeat it.
- Verified branch **counterexamples**: absent receipts cause early null return before header lookup; pre-London receipts compute effective gas price without retrieving the header; standard coherent London records return normal data. These are hypotheses to validate in the Go runtime, not assertions of production exposure.

### 2. Possible Impact

**Conditional** Go runtime panic in a JSON-RPC request handler if the missing-header precondition is reached, potentially interrupting a request or affecting availability depending on panic recovery. No demonstrated persistent node outage, transaction/receipt forgery, exchange miscredit, monetary loss, or unauthenticated ability to force an inconsistent full-node state.

**Strongest defeating control:** normal full-node storage semantics may never deliver a receipt and an inaccessible block header for the same hash simultaneously; the application RPC server may recover an individual request panic. A valid RPC input alone does not prove an attack-controlled missing header. This counterexample is the reverse worker's main falsification target.

### 3. Proof of Concept

**Synthetic, local only.** Independent worker file [`reverse_e_rpc_header_test.go`](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reverse/reverse_e_rpc_header_test.go) calls the **real** certified `PublicTransactionPoolAPI.GetTransactionReceipt` with a controlled backend and five cases: coherent London receipt; no receipt; pre-London nil header; London nil header; and mismatched receipt identity.

**Executed CI:** [run 41742642862](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41742642862), isolated class R workflow `.github/workflows/electroneum-reverse-independent-ci.yml`. Run 41742642862, job 126287716651, completed SUCCESS; the certificate/bootstrap step, all five Go defense-matrix subtests, negative fail-closed oracle sensitivity and scratch-only guard recovery succeeded. Bootstrap/check source identities, clone certified bytes into private `$RUNNER_TEMP/worker-r-scratch`, run:
```bash
go test -count=1 -timeout=10m -run '^TestReverseEReceiptDefenseMatrix$' -v ./internal/ethapi
```
Then run strict independent fail-closed oracle expected to fail on actual source **only when a named mismatch assertion fires**, patch a *scratch-only* missing-header guard, and require the same oracle to pass; verify immutable certified source unchanged. Do not count a pre-execution YAML/Go compile error as a vulnerability.

**Decisive actual logs (certified Go runtime):**
- `REVERSE_E_VALID_LONDON_CONTROL_PASS`, `REVERSE_E_NO_RECEIPT_DEFENSE_PASS`, `REVERSE_E_PRE_LONDON_COUNTEREXAMPLE_PASS` — controls passed.
- `REVERSE_E_RUNTIME_NIL_HEADER_PANIC_OBSERVED type=runtime.errorString value=runtime error: invalid memory address or nil pointer dereference` — runtime defect reproduced by actual exported receipt handler using synthetic Backend.
- `REVERSE_E_SYNTHETIC_RECEIPT_MISMATCH` — separate source-level observation, not real full-node proof.
- `TestReverseEFailClosedOracle` **intentionally failed** with `REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH`, exit code **1**. Workflow verified the exact marker; an unrelated Go compilation or runner failure would not qualify.
- Scratch-only `reverse_e_guard_patch.py` inserted a defensive missing-header error into `internal/ethapi/api.go`; rerunning the same strict oracle and defense matrix **PASSED**, including `REVERSE_E_FAIL_CLOSED_ORACLE_PASS`. `sha256sum --check` validated the read-only certified file remained unchanged. Complete Actions run status SUCCESS, not a claim of production exploitation.
- The Go runtime result is a **conditional nil-header panic**. Real full-node race/pruning preconditions, RPC panic-recovery behavior and ability of an untrusted caller to force those conditions remain **UNTESTED**; no transaction loss or node outage demonstrated.

### 4. Recommendation

1. In the RPC receipt path, check `header != nil` and (for London) `header.BaseFee != nil` before dereferencing; return a consistent retriable error instead of propagating a panic.
2. Revalidate receipt hash/transaction index binding and canonicality before advertising an externally relied-upon receipt; avoid conflating an injected inconsistent backend with shipped full-node behavior.
3. Test staged chain reorg/pruning/db fault with a **real** `EthAPIBackend` and synthetic local chain to establish whether the missing-header state can be attacker-induced.
4. Keep RPC panic-recovery boundaries enabled as defense in depth; never rely on recovery to replace field validation.
5. Before publishing a confirmed security vulnerability, reproduce a realistically attacker-reachable path and concrete availability or asset-impact violation.

**Promotion gate:** SOURCE-LEVEL DEFECT and synthetic runtime divergence are insufficient for confirmed remote security risk; additional production-path reachability, impact and counterexample falsification are mandatory.


## R-E-008 — Silent partial-success eth_getLogs result on missing intermediate canonical header

**Classification:** CONDITIONALLY REPRODUCED **TARGET SOFTWARE DEFECT** in certified Go runtime; **attacker-reachable security impact NOT CONFIRMED**. Reverse order #2. All tests were read-only or synthetic and any defensive modification affected only a disposable scratch copy.

### 1. Vulnerability Detail with Proof of /electroneum-sc Git Codes/Sources

- [`eth/filters/api.go:365–396`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/filters/api.go#L365-L396), `PublicFilterAPI.GetLogs`, constructs a range filter and returns `returnLogs(logs),err`; if `Filter.Logs` returns partial logs with a nil error, the RPC adapter has no signal of incompleteness.
- [`eth/filters/filter.go:122–171,224–238`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/filters/filter.go#L122-L238) `Filter.Logs` → `unindexedLogs` loops through numbered headers. When `HeaderByNumber` returns `(nil,nil)` for the middle of a range, the code `if header == nil || err != nil { return logs, err }` returns the prefix and **nil error**, silently presenting an incomplete result as success. An equivalent early-return pattern exists at `indexedLogs` lines 206–210; the present tests cover **only unindexed** range scanning.
- [`eth/api_backend.go:70–82`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L70-L82) `EthAPIBackend.HeaderByNumber` delegates to `blockchain.GetHeaderByNumber(...),nil`; therefore a missing header is representable by `(nil,nil)`.
- Certified immutable source ID is Windeep `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`.

### 2. Possible Impact

A querying wallet, explorer or exchange could receive an incomplete log range **without a JSON-RPC error** if a needed intermediate header is absent while preceding headers are available. It might mistake missing events for an honest empty or complete range; the harm depends on the caller's independent confirmation/canonicality rules. **No actual exchange miscredit, payment loss, transaction rewriting, or network-wide denial of service demonstrated.**

**Strongest counterexample:** a coherent shipped full node normally has contiguous canonical headers for any admitted range. An adversary selecting `fromBlock` and `toBlock` cannot automatically delete or conceal a middle canonical header. Production race/prune/corruption reachability and indexed path still require testing. The negative control with an explicitly returned backend error correctly propagates a nonnil error, so this is specifically a `nil,nil` omission.

### 3. Proof of Concept

- Independent R fixture: [`C/reports/fixtures/reverse_e_log_range_test.go`](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reports/fixtures/reverse_e_log_range_test.go), installed under `eth/filters` in a certified Go scratch copy. Real `Filter.Logs` executed with range [1,3], synthetic `Backend` returns headers 1/3 and `(nil,nil)` at 2. Source-backed test family: valid 3-log range, missing middle, missing first, explicit error, range cap, and independent strict fail-closed oracle.
- [GitHub Actions 41743587384](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41743587384), job `126290902950`, **COMPLETED/SUCCESS** after correcting a preceding YAML-only failure [41743525868](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41743525868) that ran no tests.
- Actual certified test outputs: `REVERSE_E_LOG_COMPLETE_RANGE_PASS count=3`; `REVERSE_E_LOG_MISSING_MIDDLE_SILENT_PARTIAL_OBSERVED count=1 requested=3`; `REVERSE_E_LOG_MISSING_FIRST_SILENT_EMPTY_OBSERVED`; `REVERSE_E_LOG_EXPLICIT_ERROR_CONTROL_PASS`; `REVERSE_E_LOG_RANGE_CAP_CONTROL_PASS`.
- Independent oracle on unmodified target source: `REVERSE_E_LOG_FAIL_CLOSED_ORACLE_MISMATCH: query [1..3] returned 1 logs with nil error and missing block 2`. Intentional Go test **exit 1**, caught and validated by the R CI; unrelated compile failures would be rejected.
- A nil-header guard added **only to scratch `eth/filters/filter.go`** yielded `REVERSE_E_LOG_FAIL_CLOSED_ORACLE_PASS err=missing block header 2 while scanning logs returned_prefix=1`. The immutable certified source hash verification passed. No patched source committed into vendor or upstream.

### 4. Recommendation

1. In both `unindexedLogs` and `indexedLogs`, handle `err != nil` independently, then treat `header == nil` as an explicit missing-header/incomplete-range error. Do not silently return logs as a successful full-range response.
2. At the RPC adapter boundary, surface incomplete-range errors and decline to produce a success response with a truncated event set; ensure consumer retry semantics are documented.
3. Reproduce the anomaly using a real in-process `EthAPIBackend` and locally fault-injected/pruned header storage; test indexed and unindexed paths, reorg/restart, missing first/middle/last, cancellation and range limits.
4. Require exchange/deposit monitors to verify block hash/canonicality and confirmations independently; never equate an empty or partial `eth_getLogs` success response with proof of no matching transaction.
5. Do not promote this to a remotely exploitable vulnerability unless legitimate lower-trust input can create the missing-header precondition and a concrete security/financial consequence is reproducible.
