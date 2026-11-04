# E-RPC-004 — Receipt Canonicality TOCTOU Across Concurrent Reorganization

**Disposition (4 November 2026): CONFIRMED SOURCE-LEVEL DEFECT — VERIFICATION CLOSED.** The certified Electroneum receipt adapter can return a successful receipt for an orphaned transaction after a synthetic reorganization changes canonical state during its read. **Production exploitability, adversary control and financial impact remain unproven.** This report closes verification of source behavior, not remediation. Repeated fuzz reproductions refer to the same finding, not separate new vulnerabilities.

**Finding family:** RPC state-consistency; non-atomic transaction-to-receipt read. **Severity:** deployment/impact dependent, not assigned a remotely exploitable security severity without lower-trust reachability proof. **Target:** certified Windeep commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0, vendor tree de7f3c75a2db7e87a89918f1257820703d5b731e, pinned Electroneum upstream 3aeb14db0d6384243302f3a025bdff904dc28bf6.

## 1. Vulnerability Detail with Electroneum Git Source Proof

1. [internal/ethapi/api.go lines 1570–1588](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1570-L1588): PublicTransactionPoolAPI.GetTransactionReceipt first calls Backend.GetTransaction for transaction, block hash, height and index, then separately calls Backend.GetReceipts for that block hash.
2. [internal/ethapi/api.go lines 1590–1630](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1590-L1630): constructs a successful response from the captured block hash and receipts, without checking whether the captured block is still canonical at response time.
3. [eth/api_backend.go GetTransaction](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L265-L269) and [core/rawdb/accessors_indexes.go](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/core/rawdb/accessors_indexes.go#L94-L120): a canonical body check prevents ordinary completed-reorg stale-index results. The subsequent chain switch, after this check but before receipt acquisition, defeats that earlier guarantee.

**Controlled state transition:** synthetic block A is canonical at height 1 with signed transaction and receipts stored in real in-memory rawdb. The RPC adapter resolves A. A deterministic backend hook changes canonical height 1 to block B and removes A's lookup *before* providing the receipt. Historical A receipt remains addressable by block hash. The adapter returns success for A even though canonical state now points to B.

**Counterexamples verified:** stable A receipt succeeds, completed-reorg A is excluded even with a stale lookup, canonical B receipt succeeds, missing receipt returns null. These reject the false claim that any old receipt or old index alone is a vulnerability.

## 2. Possible Impact and Reachability

**Demonstrated:** RPC read-consistency breach: a stale successful receipt can be assembled during a concurrent canonical switch. A downstream client that treats one receipt as irrevocably canonical might act on a block already displaced. This does not directly demonstrate consensus failure.

**Required preconditions:** old transaction lookup resolves just before a concurrent reorganization; old receipts are still present; a caller queries within this window. The test sets these conditions by local hook. A deployed EthAPIBackend and live consensus chain are **not** exercised in the decisive synthetic reproduction.

**Not demonstrated:** attacker-triggered/controlled QBFT reorg, bypassed finality, guaranteed race timing, default remote denial-of-service, exchange credit error, unauthorized ETN transfer, wallet theft or realized financial loss. No severity score based on imagined exploitation.

**Defeating counterexample:** a consumer that rechecks canonical block identity, waits for confirmations and handles eventual consistency may not suffer an integrity violation. Even a final server-side check cannot prevent a chain change *after* response publication.

## 3. Proof of Concept and Reproduction

**Source-backed fixture:** [reverse_e_rawdb_reorg_test.go](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reverse/reverse_e_rawdb_reorg_test.go); uses real rawdb.ReadTransaction, rawdb.ReadReceipts, canonical mapping writes and real PublicTransactionPoolAPI, but a synthetic injected backend rather than a full node.

**Independent reverse CI [41744841662](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41744841662):** coherent/negative controls pass. The original certified source fails the strict TestReverseECanonicalTOCTOUOracle with named REVERSE_E_CANONICAL_TOCTOU_ORACLE_MISMATCH, intentionally yielding exit 1. A scratch-only post-read canonicality guard causes the strict oracle to pass; immutable-source checksum remains valid. An overall green CI wrapper is **not** a claim that the original source passed this strict oracle.

**Coverage-guided reproduction CI [41754226567](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41754226567):** deterministic stateful baseline passes. Native Go coverage-guided fuzzing then minimizes a sequence whose mid-RPC switch yields a successful A receipt after B becomes canonical; exact marker R_REORG_TOCTOU_ORACLE_FAIL. Fuzz reproducer recorded at testdata/fuzz/FuzzRReorgStateMachine/2fde656d41007dc7 inside disposable scratch. A path in runner scratch is not itself a durable attached artifact; the deterministic fixture above is the durable source repro.

**Full-chain counterexample CI [41754322942](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41754322942):** TestReorgLongBlocks, TestReorgShortBlocks, TestChainTxReorgs, TestEIP155Transition, TestTransactionIndices all passed. These do not exercise the narrow mid-receipt-read timing.

**Source identity:** certified Windeep source tree de7f3c75a2db7e87a89918f1257820703d5b731e; all tested mutations occurred in disposable scratch. No public nodes, funds or credentials.

## 4. Recommendation and Closure Decision

1. Tie transaction lookup, canonical block identity and receipt reads to a consistent chain view. At minimum, revalidate canonical block identity at the returned height after receipt/header construction and retry or return a controlled not-current error when it differs.
2. Avoid introducing nil dereferences: check absent tx, receipt, header and post-London BaseFee before use. Maintain explicit negative controls and error semantics.
3. Add permanent full-backend tests: stable A, completed A→B, A→B between lookup and receipt, repeated A↔B transitions, missing data, context cancellation, and JSON-RPC transport response consistency.
4. Prove real production reachability separately: use an in-process full Ethereum/Electroneum blockchain backend and actual head changes, quantify window width and frequency, and test downstream consumer behavior. Do not promote severity based solely on synthetic control of chain switching.
5. Scratch-only canonical recheck was an **oracle-sensitivity control**, not an upstream patch; review remediation and retain the certified source baseline.

**Final verification disposition:** E-RPC-004 = CONFIRMED_SOURCE_DEFECT / REPRODUCTION_CLOSED / REMEDIATION_OPEN / PRODUCTION_EXPLOITABILITY_OPEN. Close the report's reproducibility investigation; do not mark production remediation completed or create a duplicate CVE from the same source behavior.
