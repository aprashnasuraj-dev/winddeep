# Worker R: local canonical-receipt TOCTOU reproducibility

**Status:** Reproduced in the certified Electroneum code under a deterministic in-process reorganization. **Not a claim of demonstrated external exploitability.** The failure was already characterized in the preceding reverse audit, so this fuzz result is independent reproduction of the same mechanism, not a new separate CVE or finding count.

## Source-level mechanism

`internal/ethapi/api.go`, `PublicTransactionPoolAPI.GetTransactionReceipt`, lines ~1571–1630 of the certified source:

1. `s.b.GetTransaction(ctx, hash)` identifies a transaction and block hash.
2. `s.b.GetReceipts(ctx, blockHash)` separately retrieves receipts.
3. The source constructs a success response with the originally captured block hash. It has **no end-of-query canonicality recheck** before returning fields.

A synthetic, rawdb-backed backend changes `rawdb.ReadCanonicalHash(db, 1)` between steps 1 and 2 and removes the orphaned transaction lookup. The RPC adapter still produces the old block's receipt successfully. The exact claim is: a response can already be stale at the moment it is constructed after a concurrent canonical-chain change in the instrumented source-backed adapter.

## Independent controls and reproduction

- Coherent canonical transaction receipt: succeeds.
- Completed reorganization: orphan excluded; replacement receipt succeeds.
- Rollback and replay through rawdb lookup: coherent results.
- Mid-read reorganization: strict oracle reports `R_REORG_TOCTOU_ORACLE_FAIL` with the original block hash in a successful receipt.
- Coverage-guided run: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41754226567
- Minimal reproducer produced by Go fuzz: `testdata/fuzz/FuzzRReorgStateMachine/2fde656d41007dc7`; execution log includes `go test -run=FuzzRReorgStateMachine/2fde656d41007dc7`.
- In contrast, full chain reorganization, EIP-155 transition and transaction-index integration tests pass: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41754322942

## Interpretation and risk boundaries

**Verified:** The implementation lacks an explicit final canonicality check; the timed rawdb adapter reproduces a successful stale receipt; earlier completed-reorg controls reject an orphan.

**Not yet demonstrated:** Attacker influence over timing, realistic peer-driven reorganization frequency, reliability on a production Electroneum node, wallet theft, consensus divergence, actual monetary harm, or finality violation. Calling this an exploitable remote security flaw without those demonstrations overstates the evidence.

**Remediation direction:** Provide transaction lookup and receipt data from a consistent chain view or revalidate the canonical hash at the queried height after assembling the result and retry or fail closed when it differs. A simple final check reduces the tested race but cannot guarantee a stable external answer after response transmission; document eventual-consistency behavior on chain switches. Add end-to-end tests with live chain head changes to validate the protection.

**Test-harness requirement:** Do not turn an expected panic or a fixture initialization failure into an arbitrary passing “security test.” Preserve the exact failure marker, positive controls and immutable source identity. Fuzz artifacts expire after the configured 14-day retention; promote the reduced regression seed to version control before expiry if additional validation confirms it.
