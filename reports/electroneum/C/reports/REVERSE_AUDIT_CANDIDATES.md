# Independent Reverse Audit R — Evidence-Backed Candidate Ledger

This is an **unconfirmed candidate ledger**, not the confirmed-vulnerability report. This worker owns only new files under `reports/electroneum/C/reports/`, `reports/electroneum/C/reverse/`, and `.github/workflows/electroneum-reverse-independent-ci.yml`. All A–E existing reports, fixtures, workflows and automations are read-only.

## R-E-010 — Counterexample-first analysis of nil-header handling in transaction receipt RPC

**Status:** SOURCE-SUPPORTED, independent actual Go runtime **RUNNING/WAITING_CI** at initial report time. **Security exploitability:** NOT CONFIRMED. **Order:** Reverse pass #1, newest open E topic (followed by older E items, then D, C, B, A). **Threat:** untrusted or lower-privilege caller sends `eth_getTransactionReceipt` for an actual transaction; requires block header lookup to disappear while transaction index and receipts remain retrievable. No public node has been probed.

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

**Executable CI:** [run 41742642862](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41742642862), isolated class R workflow `.github/workflows/electroneum-reverse-independent-ci.yml`. First run was IN_PROGRESS at report creation. Bootstrap/check source identities, clone certified bytes into private `$RUNNER_TEMP/worker-r-scratch`, run:
```bash
go test -count=1 -timeout=10m -run '^TestReverseEReceiptDefenseMatrix$' -v ./internal/ethapi
```
Then run strict independent fail-closed oracle expected to fail on actual source **only when a named mismatch assertion fires**, patch a *scratch-only* missing-header guard, and require the same oracle to pass; verify immutable certified source unchanged. Do not count a pre-execution YAML/Go compile error as a vulnerability.

**Expected behavior, not observed at this checkpoint:** synthetic London missing-header path likely panics. The counterexamples and patch sensitivity must be certified by completed CI step/log outcomes. Exact target-runtime outputs and exit codes are **PENDING**, not invented.

### 4. Recommendation

1. In the RPC receipt path, check `header != nil` and (for London) `header.BaseFee != nil` before dereferencing; return a consistent retriable error instead of propagating a panic.
2. Revalidate receipt hash/transaction index binding and canonicality before advertising an externally relied-upon receipt; avoid conflating an injected inconsistent backend with shipped full-node behavior.
3. Test staged chain reorg/pruning/db fault with a **real** `EthAPIBackend` and synthetic local chain to establish whether the missing-header state can be attacker-induced.
4. Keep RPC panic-recovery boundaries enabled as defense in depth; never rely on recovery to replace field validation.
5. Before publishing a confirmed security vulnerability, reproduce a realistically attacker-reachable path and concrete availability or asset-impact violation.

**Promotion gate:** SOURCE-LEVEL DEFECT and synthetic runtime divergence are insufficient for confirmed remote security risk; additional production-path reachability, impact and counterexample falsification are mandatory.
