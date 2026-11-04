# Worker R P2i — Real ETH66 persistent disk-growth oracle

**Evidence timestamp:** 2026-11-04 UTC  
**Passed production-depth run:** https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41808840938  
**Passed workflow syntax guard:** https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41808840894  
**Runtime job:** 126502583425  
**Evidence artifact:** https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41808840938/artifacts/13311141796  
**Event commit:** `68c647d63333eb6c9af16c85f5b614782c541d9e`  
**Certified Electroneum source:** `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`  
**Certified vendor tree:** `de7f3c75a2db7e87a89918f1257820703d5b731e`  
**Disposition:** **NO NEW VULNERABILITY; peer-controlled disk amplification not observed in the two bounded canonical-block cases.**

## Purpose and actor model

P2h ([41806392322](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41806392322)) showed a lower-trust ETH66 peer could tip a **pre-existing near-full ext4** receiver into native LevelDB ENOSPC and fatal exit by serving an already-valid QBFT block. It did **not** prove that the peer could create the near-full condition.

P2i tests that missing G6 link: does the real TCP/RLPx/ETH66/downloader path write substantially more persistent data than the **same quorum-valid block** imported directly into an equivalent local canonical chain? Does replaying the same block body create additional database growth without canonical progress?

The peer can choose delivery and repeat requested existing data, but cannot forge a 3-of-4 QBFT quorum, choose local disk quotas, or write host files. Tests run on disposable local ext4 loopback storage; no public network is touched.

## Measurements, source and controls

The deterministic reproducer is `reports/electroneum/R/production_depth/qbft_peer_disk_growth_oracle_test.go`. The production-depth workflow copies it and its helper fixtures into disposable certified source; `vendor/electroneum-sc` remains untouched.

Both profiles use an independent remote QBFT chain, a real signed transaction, successful 3-of-4 QBFT verification, real TCP/RLPx/ETH66 handshake and downloader `LegacySync`. The direct control imports the identical block into a separate persistent LevelDB-backed chain with `core.BlockChain.InsertChain`. Both chains must advance to the block and expose successful matching receipts. Allocation is measured using filesystem `stat(2)` allocated 512-byte block counts for LevelDB regular files, not apparent file sizes.

| Metric | Small valid block | Valid block with 256 KiB transaction payload |
|---|---:|---:|
| Encoded block bytes | 953 | 263,105 |
| ETH66 receiver physical DB allocation delta | 4,096 B | 266,240 B |
| Independent direct-import physical DB allocation delta | 4,096 B | 266,240 B |
| Peer-to-direct delta ratio | **1.000x** | **1.000x** |
| Receiver allocation / encoded-block bytes | 4.298x | 1.012x |
| Repeated `LegacySync` calls | 3 | 3 |
| Additional ETH66 block-body responses during repeats | 3 | 3 |
| Additional persistent DB bytes after repeats | **0 B** | **0 B** |
| Successful replay `LegacySync` calls | 3 | 3 |

Verified log markers: `R_G6_DISK_GROWTH_PROFILE` (both cases), `R_G6_DISK_GROWTH_BASELINE_PASS`, successful receipt/chain tests, and unchanged source. Go runtime test completed successfully.

The ~4.3x ratio for the tiny 953-byte block is a **4 KiB filesystem allocation quantum** and also appears identically in the direct baseline; it is not evidence of malicious amplification. The large payload profile shows ~1.2% physical overhead above its encoded block size.

## Evidence gates

- **G1 — PASS:** certified source commit/tree and immutable vendor source.
- **G2 — PASS:** real loopback TCP/RLPx/ETH66 valid block and matching canonical receipt.
- **G3 — PASS as measurement oracle:** physical receiver allocation compared with direct canonical import of the *same* block; no vulnerability asserted merely because an allocation ratio is nonzero.
- **G4 — PASS:** committed source test, workflow, CI logs and artifact.
- **G5 — PASS as bounded negative control:** small/large blocks, independent direct import, three extra body responses with zero observed further DB growth.
- **G6 — NOT ESTABLISHED for attacker-driven disk exhaustion:** an ordinary peer did not create additional persistent growth beyond canonical-chain import in this scope.
- **G7 — NOT ESTABLISHED:** no remote exhaustion from a healthy reserve, third-party outage, chain integrity break or financial impact.

## Scope limitations / decisive counterexamples

1. Two one-block scenarios are insufficient for long-chain LSM compaction, retained stale forks, headers-only storms, or multi-height reorganization storage growth.
2. Physical per-directory file allocation is a point-in-time measurement; concurrent compaction and dirty-page flush can change it. Run-to-run comparisons should capture quiescent checkpoints, filesystem available bytes, block-body bytes on the wire and compaction counters.
3. The fixture supplies preconstructed **valid 3-of-4** consensus data, not forged blocks or a demonstrated ordinary-peer ability to produce competing finalized blocks.
4. Three body responses with zero durable growth are strong evidence against simple duplicate-body replay in this fixture, not proof against every replay or cache-edge sequence.
5. A node already running out of disk can still fail as P2h demonstrated; this P2i result says nothing about generic disk-full availability or safe production free-space reserve policies.

## Highest-value next nonredundant gate (P2j)

Use a **bounded, multi-height** valid QBFT history delivered by a real TCP/RLPx/ETH66 peer, with independent direct-import baseline and no-peer idle control at a healthy fixed free-space reserve. Collect (a) wire response bytes, (b) physical and logical DB growth after WAL flush/compaction, (c) canonical block/receipt counts, and (d) requested/returned block bodies. Separate new-canonical-block growth from replay and abandoned-branch growth, including restart/recovery checkpoints.

Only promote a remote-disk-exhaustion finding if lower-authority peer choices alone cause reproducible incremental persistent growth materially above unavoidable canonical progress, without supplying a full-disk precondition or a consensus-quorum signing adversary. If growth remains proportional to legitimate chain data, classify as ordinary operational capacity behavior, not a protocol exploit.
