# Electroneum Worker R — P2m Snap state-sync persisted-input audit (2026-11-04)

**Disposition: VERIFIED NEGATIVE RESULT. No bounty-ready finding; no healthy-disk exhaustion established.**

- **Certified unmodified Electroneum source:** commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`.
- **Branch:** `audit/r-production-depth-20261104-22-snap-state-persistence`
- **Passing production CI:** [#41815620101](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41815620101), Go test commit `5ff9acd498bfe4d5edd45ad0d4b12305d88adb04`.
- **Passing YAML/syntax CI:** [#41815620196](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41815620196).
- **Run evidence ZIP:** [artifact 13313809957](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41815620101/artifacts/13313809957) (expires 2026-11-18).
- **Reproducer:** `reports/electroneum/R/production_depth/qbft_snap_sync_real_persistence_test.go`.
- **Workflow selector:** `22-snap-state-persistence` in `.github/workflows/electroneum-r-production-depth.yml`.

## Production ingestion mechanism verified

`eth/downloader/statesync.go` invokes **`SnapSyncer.Sync(root,cancel)`**. The shipped `eth/protocols/snap/sync.go` requests account ranges and bytecode from a Snap `SyncPeer`, enforces outstanding request IDs, checks **`trie.VerifyRangeProof`** against a fixed state root, checks bytecode's Keccak hash against requested code hashes, and writes accepted state/trie to LevelDB using production batches. This is the **real state persistence pipeline**, unlike P2l's diagnostic ETH66 NodeData response sink.

**Important boundary:** The peer transport in P2m is the certified source's **in-process `SyncPeer` test adapter**, not live snap/1 TCP/RLPx. The root is fixed by a 96-account test fixture, *not* derived in this test from a finalized QBFT header. The adversarial provider controls only returned account/code values, proof witness repetition and response IDs; it possesses no validator signing keys and cannot alter the trusted state root. Real network reachability remains **unproven**.

Each scenario starts with an independent, empty **on-disk LevelDB** on an isolated **256 MiB ext4** filesystem. Read actual physical allocations via Linux `st_blocks*512`; call the shipped syncer; commit accepted account snapshots and trie state; compact, close, reopen; verify the state root and persisted account count.

## Passing CI measurements

| Response mode | Account/code requests | Account snapshots after restart | Allocated LevelDB bytes after compaction+restart |
|---|---:|---:|---:|
| Honest source, fixed 96-account root | 1 / 2 | **96** | **32,768 B** |
| Same valid state, 24 repeated proof witnesses | 1 / 2 | **96** | **32,768 B** |
| Four unsolicited request IDs then legitimate ID | 1 / 2 | **96** | **32,768 B** |
| Modified account leaf, unchanged root and proof | 2 / 0 (includes cancelled retry) | **0** | 20,480 B |
| Incorrect requested contract bytecode | 1 / 2 | **0** | 20,480 B |

The 96-account root was `0x7b6fe80212471b30567143206ce2b40d349b13186100eba9965e15ae3d4a50a1`.

The duplicate-proof response provided **6,682 B of proof** versus **850 B** in the honest response (**+5,832 B inbound proof data**). Persisted state still matched the honest root and **0 B excess durable disk allocation**. Four unsolicited IDs were ignored; a later properly requested response reconstructed the same root, again **0 B excess allocation**.

The mutated account proof triggered an actual validation error, `invalid proof, want hash …, got …`. The wrong bytecode triggered `unexpected bytecode`. Both tests observed a genuine rejection and **zero account snapshots** after restart. The aborted databases occupied 20,480 B from LevelDB initialization/progress; that is not evidence of malicious state being committed. A subsequent cancelled/stale callback can return `nil` without processing its payload; the final test differentiates this from a successful proof validation.

Initial filesystem available space: **229,072,896 B**; final available: **228,913,152 B**, including all five databases. No disk exhaustion, node crash or chain-head corruption occurred. The physical **+28,672 B** during each valid sync became **32,768 B** after compaction+reopen, identical in all three legitimate-equivalent cases.

## Limits and interpretation

**Established:** production `SnapSyncer.Sync` ran end-to-end, validated source-root proofs and code hashes, made real state/trie writes, persisted/reopened identical complete roots in positive controls, rejected two malicious payload categories without account snapshots, and did not persist redundant proof witnesses or unsolicited-ID replies.

**Not established:** actual snap/1 RLPx network delivery, a root anchored to fixture-finalized QBFT headers, malicious node-healing `OnTrieNodes` packet persistence, snapshot/storage-range attack paths, sustained adversarial peer throughput, resource consumption at scale, or remote exhaustion of a healthy disk reserve.

**Source-review caveat:** `trie.Sync.Process` assumes its caller correctly binds data to hashes; the Snap `OnTrieNodes` callback hashes returned node bytes before passing them to the trie-healing scheduler. That exact healing packet path was **not** dynamically exercised here. The account-range code contains a post-proof RLP decoding panic intended for trusted proof-validated account data, but P2m did not remotely trigger it; a peer cannot simply mint a different root trusted by consensus.

**CI harness corrections:** initial workflow YAML syntax failure; then missing test-mode copy produced `no tests to run`; the first actual runtime identified a stale/cancelled response returning `nil` as a false-positive harness assertion. The final passing test requires actual proof/code rejection and checks on-disk state; these were harness issues, not proven vulnerabilities.

## G1–G7 gate classification

| Gate | Status |
|---|---|
| Exact immutable source and test isolation | PASS |
| Actual production SnapSyncer and LevelDB persistent write/reopen | PASS |
| Unprivileged response data with trusted fixed root | PASS — adapter model |
| Merkle proof, requested bytecode hash and request-ID controls | PASS |
| Identical legitimate root after witness replay and unsolicited IDs | PASS |
| Durable attacker-only amplification over legitimate state | **0 B observed** |
| Live unprivileged snap/1 path to excessive disk growth/validator crash | **NOT PROVEN** |

**Next qualified work:** P2n should reproduce the same controls over a live localhost snap/1 RLPx connection, use a state root anchored to a fixture-finalized QBFT block, exercise `AccountRange`, `StorageRanges`, `ByteCodes` and `TrieNodes` healing, and measure per-peer write keys, compaction/restart and disk reserve against a byte-identical honest peer. An unprivileged actor must demonstrably create **extra durable storage beyond legitimate canonical state** (or a healthy-reserve liveness fault) before promoting a bounty finding. No production validator should be targeted.
