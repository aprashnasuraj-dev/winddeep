# Reverse Audit Worker R — Latest Independent Run

## 2026-11-04 05:39 NPT — Reverse pass 1 of 14: E-RPC-010 verified runtime error-handling defect

**Owner R (independent of A–E).** Start at newest open E item, traverse older E items, then D → C → B → A in descending item chronology. Existing A–E files, workflows, automations, schedules and ongoing CI are **READ-ONLY** for R. All R write paths: `reports/electroneum/C/reports/REVERSE_AUDIT_*`, `reports/electroneum/C/reverse/`, and `.github/workflows/electroneum-reverse-independent-ci.yml`. Never overwrite the existing C report or C/LATEST.md. Findings use existing four-section security report headings **only in candidate analysis** unless reproducible lower-trust security impact is confirmed.

### Executive forensic result

**Confirmed software defect under a conditional state; security risk still open.** Electroneum's actual `PublicTransactionPoolAPI.GetTransactionReceipt` panics when the synthetically supplied backend gives `(nil,nil)` for a London-era block header while a validly shaped receipt and transaction index remain available. The independent fail-closed oracle rejected the original source. A defensive missing-header guard applied **only to a disposable scratch copy** made that exact oracle pass. Runtime results were obtained from the certified Go source. There is **no proof** that an untrusted JSON-RPC caller can produce the missing-header precondition on a coherent live full node, that the RPC panic escapes server recovery, or that assets/history/finality are affected.

### Exact source and attacker path

- Source: [`internal/ethapi/api.go:1571–1614`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1571-L1614) `GetTransactionReceipt`; separate transaction/receipt lookups, `HeaderByHash` and unchecked `header.BaseFee`.
- Production backend: [`eth/api_backend.go:99–101`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L99-L101) returns `GetHeaderByHash(hash),nil`, potentially `(nil,nil)`.
- Attacker-controlled request: transaction hash query (when public `eth` RPC module exposed). **Unproven trust crossing:** can that query cause a transaction+receipt to exist while its header becomes inaccessible during concurrent reorg/pruning/db failure? An ordinary full node may preserve coherent hash-indexed data, defeating the attack.

### Certified execution and decisive log

| Gate | Evidence and status |
|---|---|
| G1 source certification | **PASS in CI** via `source tools/electroneum_target_bootstrap.sh`, four identity assertions; immutable source path `/home/runner/work/_temp/windeep-electroneum-tree.ANMK50FT/source`. Windeep commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, source tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Local checkout unavailable (GitHub DNS exit 128); no false local execution claimed |
| G2 attacker path | **PARTIAL** actual exported `eth_getTransactionReceipt` adapter and backend source traced. Real full-node lost-header precondition / remote attacker control unproved |
| G3 target runtime | **PASS**, five real adapter cases on certified synthetic backend: coherent London receipt; no-receipt early null; pre-London missing-header bypass; London missing-header panic; injected receipt.TxHash disagreement. Four counterexample/behavior variations + baseline |
| G4 independent oracle/sensitivity | **PASS for tested nil-header condition**: independent structured-error oracle intentionally failed on original source (exit 1, named mismatch marker) and passed after defensive guard injection on R's **scratch-only** copy. No source or other worker file mutation |
| G5 commands/logs | **PASS**: `go test -count=1 -timeout=10m -run '^TestReverseEReceiptDefenseMatrix$' -v ./internal/ethapi` exit 0. `go test -count=1 -timeout=10m -run '^TestReverseEFailClosedOracle$' -v ./internal/ethapi` original exit **1 expected** with `REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH`; after injecting scratch guard both `TestReverseE*` cases PASS, and immutable-source SHA check PASS |
| G6 new path | **YES**: independently challenged original E source hypothesis by validating no-receipt/pre-London controls and a reversible fail-closed oracle. This is new R evidence, independent of E's job |
| G7 committed report | **YES** once this R-only checkpoint and state ledger commit. Confirmed-vulnerability report deliberately untouched |

**CI run:** [41742642862](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41742642862), job `126287716651`, trigger SHA `9cd0963117ee3fd93990a999cafa009eed836f5b`, **COMPLETED/SUCCESS**. Exact observed job output:

```text
REVERSE_E_VALID_LONDON_CONTROL_PASS
REVERSE_E_NO_RECEIPT_DEFENSE_PASS
REVERSE_E_PRE_LONDON_COUNTEREXAMPLE_PASS
REVERSE_E_RUNTIME_NIL_HEADER_PANIC_OBSERVED type=runtime.errorString value=runtime error: invalid memory address or nil pointer dereference
REVERSE_E_SYNTHETIC_RECEIPT_MISMATCH: public adapter emits requested hash; real backend consistency unproven
REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH: header=nil yielded panic type=runtime.errorString
REVERSE_R_ORIGINAL_SOURCE_ORACLE_REJECTED exit=1
REVERSE_E_SCRATCH_GUARD_INJECTED
REVERSE_E_FAIL_CLOSED_ORACLE_PASS
REVERSE_R_E_GUARD_SENSITIVITY_AND_CERTIFIED_SOURCE_INTACT_PASS
```

The `##[error]` prefix on successful `sha256sum --check` output is a GitHub log presentation artifact; the verification exited successfully and the job was SUCCESS. No benchmark fuzz counts claimed: this campaign is a targeted bounded deterministic oracle, not a sustained fuzz job; elapsed test runtime on log output is ~0.03s for Go test bodies after compilation.

### Reverse-order queue and next action

**First analyzed:** E-RPC-010 (software defect **VERIFIED**, production exploitability **OPEN**, no remote-impact claim). **Second item:** E-RPC-008, partial-success `eth_getLogs` with a nil intermediate header; validate both missing-first and missing-middle counterexamples, and run the independent fail-closed oracle on actual `eth/filters` source before any promotion. Then move to E-RPC-004 receipt canonicality, E-RPC-002 fee serialization, D newest-to-oldest, C, B, and A. Disproven claims are skipped; unresolved reachability remains in the backlog rather than marked fixed. If a class R CI is RUNNING/QUEUED, do not dispatch overlap; pursue independent certified source falsification.

### Recommended engineering fix, NOT applied to upstream

After `HeaderByHash`, reject `header == nil` with a structured error; on London forks also check `header.BaseFee` is present; add a race/reorg regression with a real in-process `EthAPIBackend`. Treat the already executed scratch guard as **sensitivity proof**, not a production patch. Correctness and severity must be established on a full-node interface before reporting a remotely exploitable vulnerability.

### Preservation and handoffs

- New class R-only path: [reverse CI](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/.github/workflows/electroneum-reverse-independent-ci.yml), [E fixture](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reverse/reverse_e_rpc_header_test.go), scratch defensive guard script, [candidate ledger](REVERSE_AUDIT_CANDIDATES.md), [state ledger](REVERSE_AUDIT_STATE.json).
- No changes to A–E's original `LATEST.md`, fixture files, workflows, branch ownership, active CI, or scheduled automations.
- Findings report for confirmed security vulnerabilities stays blank/uncreated until reachable impact proof. This latest and candidate report are process/candidate evidence, not a disclosure.
