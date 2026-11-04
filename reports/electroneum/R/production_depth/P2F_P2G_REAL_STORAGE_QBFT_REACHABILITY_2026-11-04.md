# Worker R P2f/P2g — Real OS write refusal, QBFT, ETH/66 reachability, RPC effects

**Evidence date:** 2026-11-04 UTC. **Branch:** `audit/r-production-depth-20261104-16-fsize-qbft-reachability`. **Status:** reproducible local fault / public API consistency condition; NOT a proven unprivileged remote exploit or financial loss.

## Executive findings

1. **Real syscall error established:** Linux `RLIMIT_FSIZE` on a genuine goleveldb write-ahead log (WAL) produces an OS `EFBIG` failure, an unmodified `ethdb.Batch.Write` error, and the shipped `log.Crit` process exit code 1. This is an operating-system file-growth refusal, **not** an `ENOSPC` disk-volume exhaustion test, physical power loss, or arbitrary error returned after a successful commit.
2. **Real error can expose the claimed inconsistency:** A 25-offset WAL growth sweep across a genesis-only LevelDB and two generated blocks passed all 25 crash/restart/resync cases. Ten limits (WAL growth allowances 1120 through 1408 bytes in steps of 32) left the block-1 canonical mapping, transaction index, receipt, header/fast heads present, but recovered **executed full head 0**. All 25 later imported to head 2 and restarted coherently. [CI 41794543204](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41794543204).
3. **Shipped QBFT verifier accepts the same real-fault outcome:** Four test validators, **3-of-4 distinct committed seals**, default Istanbul/QBFT backend (no widened future-block window in the tested receiver). Invalid **2-of-4** committed seals were rejected. A dedicated independent LevelDB calibration found first-block WAL growth of **1615 bytes**. Setting the real Linux file-size limit just after that measured growth caused an actual `Batch.Write` error while importing a second quorum-committed block. After restart, real `eth_getBlockByNumber("latest",false)` returned `0x0` but real `eth_getTransactionReceipt(txHash)` returned a **block-1** receipt. [CI 41794995232](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41794995232); unchanged-error observer [CI 41795447879](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41795447879). No synthetic error adapter was installed in this successful `os_fsize_late` case.
4. **Real ETH/66 delivery / local availability:** A separate real loopback TCP/RLPx/ETH66 downloader path received a validator-quorum-valid block body from a peer. With receiver WAL growth capped to 64 additional bytes, the production downloader's block import caused a genuine LevelDB write error and **the node process exited with status 1**. On restart, full head remained genesis and no phantom receipt was visible; after restoring write capacity and importing the exact quorum-signed block, full head advanced to 1 with a successful receipt. [CI 41794152912](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41794152912); passive LevelDB error confirmation and restored-capacity replay [CI 41795447879](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41795447879).
5. **Unprivileged exploit NOT established:** The *peer* can deliver already quorum-valid public blocks across the protocol, but the user/tester imposed the local file limit. An ordinary peer was **not** shown to create disk exhaustion, bypass quorum, influence LevelDB's error return, force a different finalized block, or harm a deployed exchange. ETH/66 delivery is an exposure path under a **preexisting local storage-capacity failure**, not proof of attacker-controlled causation.

## Exact controlled test surface

| Gate / experiment | Strict expected oracle | Verified |
|---|---|---|
| Linux direct OS journal write | File-size cap, `SIGXFSZ` ignored, independent `EFBIG` probe, native DB error | PASS |
| `Batch.Write` provenance | Passive adapter logs original `Batch.Write` error unchanged; no error fabrication | PASS |
| OS WAL boundary matrix | 25 levels, full-state safety checks, import two blocks, second restart | 25/25 PASS |
| QBFT seal positive control | 3/4 signatures verified by shipped backend | PASS |
| QBFT seal negative control | 2/4 signatures rejected | PASS |
| Public receipt/latest on `os_fsize_late` | Same restarted DB and in-process JSON-RPC dispatcher | latest 0, receipt 1 |
| Early real OS error | No canonical height-1 or receipt visibility | PASS |
| ETH66 peer against limited disk | Handshake + block-body response + actual local DB error + process exit | PASS, exit 1 |
| Restore-capacity counterexample | Restart at full 0, no receipt; valid reimport to full 1, receipt 1 | PASS |
| Lower-authority 2/4 ETH66 path | Downloader refuses invalid committed seals | PASS, 73 receipt checks / 0 stale in CI 41794995232 |
| Real unprivileged fault induction | Remote actor forces underlying local capacity limit or bypasses consensus | NOT DEMONSTRATED |
| Third-party material loss | Actual exchange/indexer miscredits, fund transfer, or mainnet outage | NOT DEMONSTRATED |

## Why the consistency condition arises

Source-level references from certified Electroneum:

- `vendor/electroneum-sc/ethdb/leveldb/leveldb.go`: the production batch calls `db.db.Write(b.b,nil)`; `Put` and `Delete` also use nil options. The pinned goleveldb dependency is `github.com/syndtr/goleveldb` revision `2ae1ddf74ef7`. That revision's `db_write.go` writes/flushes the journal, returns write errors before applying the batch to memdb, and does not fsync ordinary nil-option writes.
- `vendor/electroneum-sc/core/blockchain.go` `writeBlockWithState`: data (header/body/receipt) and state trie are handled separately from the later `writeHeadBlock` batch of canonical/transaction indexes and head markers. Failed writes invoke `log.Crit` (`os.Exit(1)`).
- On restart the same `blockchain.go` checks for missing state at the persisted full head and repairs/rewinds executed state where needed. In these fixtures it rewinds the executed full head to genesis while leaving an indexed block-1 receipt accessible.
- `vendor/electroneum-sc/eth/api_backend.go`: `GetTransaction` delegates to `rawdb.ReadTransaction`, `GetReceipts` delegates to `BlockChain.GetReceiptsByHash`, while `BlockByNumber(latest)` returns `CurrentBlock()`.
- `vendor/electroneum-sc/internal/ethapi/api.go` `GetTransactionReceipt` uses those index/receipt lookups without enforcing that the indexed receipt height is at or below the recovered current *executed* head. Its normal JSON-RPC dispatch is exercised by the new test.

The result is **not the same as invalid QBFT finality**. Block 1 is genuinely signed by the configured test quorum; the gap concerns durable index visibility versus locally recoverable executed state. Applying a simplistic receipt-height guard to all full/fast-sync nodes may break valid sync behavior. A production change requires an explicit semantic contract and regression testing before patching.

## Threat/impact analysis

- **Attacker-controlled entry:** ordinary ETH/66 peers may carry already valid quorum-signed blocks. An actual 2/4 subquorum block is rejected before canonical acceptance. No path was found for a lower-trust peer to cause the local OS file limit in these experiments.
- **Environment precondition:** near-exhausted local WAL/file growth capacity or comparable local storage write refusal; a configured OS per-file limit is not itself an external vulnerability. Full-volume ENOSPC, hardware EIO, torn writes, true power loss and journal fsync errors were **not** tested here.
- **Reproduced node availability impact:** one import process exits status 1. Service remains unavailable while that process is stopped; restart and quorum-valid reimport were demonstrated with capacity restored. No estimate of mainnet outage duration, scope, or probability.
- **Reproduced data/API consistency impact:** a read-only RPC consumer can observe a real block-1 receipt while `latest` reports block 0, under the controlled genuine local write refusal. The data are indexed to a *quorum-valid* test block, not proven fraudulent.
- **Consumer counterexample:** current official explorer `electroneum/electroneum-sc-block-explorer` source returns `{:error, :non_consensus}` for non-consensus blocks when computing confirmations, clears reorged transaction receipt fields, and includes reorg mismatch handling. Therefore **official explorer false credit was not reproduced**; no deployed wallet/exchange credit path was demonstrated. Do not equate a receipt-only toy consumer with a real exchange.
- **Exploit classification:** conditional **integrity/consistency availability finding** under host storage failure. Remote actor control (G6) and realized third-party financial harm (G7) remain OPEN; do not assign an unsupported CVSS or submit a bounty claim as if funds were stolen.

## Evidence hygiene and prior CI failures

- The prior PR #44 `head_after` scenario intentionally returned a synthetic error after a successful LevelDB batch write. This is useful as a test oracle but was not proof of a naturally returned post-commit error. The new `os_fsize_late` case removes that artifact.
- Early Worker R branch-16 run [41792959257](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41792959257) and subsequent [41793392768](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41793392768), [41794108355](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41794108355) had unused Go test imports, corrected immediately; these are compilation/harness errors, **not target faults**.
- A passing run after the complete local error instrumentation is [41795447879](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41795447879). The original certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, remains unchanged.

## Next security gates

**G6:** Verify a lower-trust actor can create or exploit the storage condition without validator quorum or host privileges, using explicit operational assumptions (disk allocation, rate, quotas, sync catch-up). Merely delivering a valid block after somebody else has exhausted storage proves protocol delivery, not attacker-owned failure causation.

**G7:** Verify an actual third-party integration accepts receipt visibility as paid/final when `latest` is lower, despite its canonical-hash, indexing, sync-state and reorg protections. No such deployment has been shown; do not invent economic loss.

**Durability:** A real VM/block-device power-failure experiment (including actual `ENOSPC`/`EIO` or fsync-boundary failures) would be different from `RLIMIT_FSIZE`. If authorized, construct one only in an isolated disposable environment, not on live validators.

**Disposition:** retain isolated **draft** PR; no certified-source modification, merge, release, remote probe of real validators, or third-party claim.
