# Worker R: coverage-guided stateful cross-component audit

Target: certified Electroneum source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`. Four independent workflows run only against isolated scratch copies (not main). Trigger SHA is pinned. Real HTTP RPC handlers are exercised *in-process*, with synthetic wallets and no remote network.

## Four tracks and source-level oracles

1. **01-rpc-wallet:** Real `rpc.Server.ServeHTTP` → registered `PrivateAccountAPI` → `accounts.Manager` → synthetic wallet. Mutated sequences of initialize/open/list/unknown URI. Enforces ID correlation, result/error separation, no fake passphrase exposure, and wallet-opening counts. Forced personal registration is intentionally a reachability test; it **does not** establish default HTTP exposure.
2. **02-reorg-transactions:** Signed transactions → `rawdb` canonical index and receipt storage → `PublicTransactionPoolAPI.GetTransactionReceipt`. Stateful forward/rollback/replacement plus TOCTOU reorg. Strict invariant rejects successful orphan receipts after canonical switch. A failure from this oracle matches the previously observed reorg flaw unless a distinct mechanism is shown.
3. **03-downloader-cancel:** Real receipt queue + synthetic headers / RLP + peer reassignment. Mutated revoke/expire/corrupt commitment/corrupt wire data/cancel-reset/valid-retry sequences. Checks stale peer exclusion, no lost pending task, and eventual valid recovery. Baseline runs with the Go race detector.
4. **04-parser-exhaustion:** Grammar-aware ABI offset and dynamic length mutation, arbitrary RLP differential reencoding, and byte-limited RLP stream decoder. Rejects out-of-bounds resource demands without unbounded allocation. Fuzz input is capped at 2 KiB; `GOMEMLIMIT=768MiB` and parallelism 2.

Each track runs deterministic positive/adversarial baseline tests, followed by Go's native coverage-guided `-fuzz` engine for 40 seconds, one track per GitHub Actions run. Each run writes baseline/fuzz logs, source provenance, and minimized reproducers to a downloadable Actions artifact (14-day retention). A **fuzzed assertion failure** is an untriaged finding, not proof of impact. False assumptions in fixtures and oracle design must be tested first.

The audit tests **behavior**, not exposure, exploitation or a production deployment. Previously found TOCTOU receipt consistency problems remain separate from new findings. There is no external fuzz traffic.
