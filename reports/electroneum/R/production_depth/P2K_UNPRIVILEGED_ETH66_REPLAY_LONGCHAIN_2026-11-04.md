# Worker R P2k — Unprivileged ETH66 response replay and eight-block durable storage oracle

**UTC date:** 2026-11-04  
**Repository:** `aprashnasuraj-dev/winddeep`  
**Branch:** `audit/r-production-depth-20261104-20-untrusted-eth66-replay`  
**First full passing execution:** [GitHub Actions #41811712141](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41811712141)  
**Run artifact:** [r-production-depth-41811712141-1](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41811712141/artifacts/13312821372) (expires 2026-11-18)  
**Certified source commit:** `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`  
**Certified source tree:** `de7f3c75a2db7e87a89918f1257820703d5b731e`  
**Reproducer:** `reports/electroneum/R/production_depth/qbft_eth66_unprivileged_replay_longchain_test.go`  
**Workflow:** `.github/workflows/electroneum-r-production-depth.yml` with selector `20-untrusted-eth66-replay`

## Disposition

**NO NEW VULNERABILITY ESTABLISHED.**

A non-validator Ethereum/66 (ETH66) peer synced eight fixture-provided quorum-valid QBFT blocks to an isolated persistent LevelDB node over real TCP/RLPx. The peer then (a) retransmitted a previously consumed block-body reply using its original request ID and (b) established a separate P2P identity to transmit the same historical body with a fabricated, unsolicited request ID. Both message injections were accepted by the network writer, each peer subsequently disconnected, and **neither yielded additional physical LevelDB allocation**. No canonical head or receipt changed. Four duplicate legitimate synchronization calls did elicit four further body responses but also yielded **0 B** additional persistent allocation.

The ETH66 path incurred **exactly the same** allocated physical disk growth as an independent byte-identical `BlockChain.InsertChain` direct-import control. After explicit full compaction, complete shutdown and reopen, both databases occupied **1,085,440 bytes** (ETH66/direct = **1.000x**). The healthy reserve remained healthy.

These are bounded observed results, not a proof that all possible ETH66 messages are safe, or that an arbitrary hostile peer can never use storage resources. P2h's fatal ENOSPC on an already-nearly-full disk remains a distinct **local available-capacity precondition**, not evidence the peer fills a healthy disk.

## Threat model and controls

The **unprivileged attacker** is a standard remote ETH66-capable peer with its own generated network identity. The attacker can supply already-valid chain data over the wire, repeat old replies, manipulate a response's *transport-level RequestId*, disconnect, and reconnect under a fresh peer identity. It cannot generate or modify QBFT commitment seals, create finalized headers, alter the receiver's LevelDB directly, or forge higher-consensus authority.

For the *positive control only*, four fixture keys sign all eight linked QBFT blocks with **3-of-4** committed seals. Each includes a distinct **128 KiB** noncompressible-ish transaction payload, for at least **1,048,576 bytes** of data in the eight transaction payloads. All block generation is completed by the trusted local fixture *before* network transport. The receiver uses production-default QBFT future-time validation; testing waits until the tip falls within the shipped five-second future window.

The receiver and direct control each start from the exact same committed genesis on an independent LevelDB directory, on the **same isolated 256 MiB ext4 loopback mount**. Record physical allocated bytes via Linux `st_blocks * 512`, not application payload or nominal file lengths. The same canonical head and successful transaction receipt are checked after each attack and after restart.

The test has no remote public nodes and does not change certified Electroneum source code.

## Observations from the passing run

| Stage | Real measured evidence | Finding significance |
|---|---|---|
| Fixture build | 8 blocks, 3-of-4 QBFT seals, >=1,048,576 B signed transaction payload, attacker peer keys=0 | No validator-equivalent attacker privilege |
| Legitimate eight-block import | ETH66 **+1,060,864 B**, direct control **+1,060,864 B**, ratio **1.000x**; 2 ETH66 body messages, 1,049,570 message bytes | Transport induced no excess persistent data |
| Four repeat downloader syncs | 4 additional legitimate block-body response messages, **0 B** physical growth | Valid-body replay under legitimate requests did not amplify storage |
| Malicious reuse of consumed ID | 131,209 B ETH66 BlockBodies response sent, peer disconnected, **0 B** physical growth, head remains 8 | No durable amplification from old request-ID replay |
| Malicious unrelated request ID | 131,209 B ETH66 BlockBodies response sent by a new P2P identity, peer disconnected, **0 B** physical growth, head remains 8 | No durable amplification from unsolicited response |
| Compaction control | Both DBs **1,077,248 B** before; **2,134,016 B** just after explicit compact | Nearly 2x temporary LSM allocated footprint, **not peer-specific** |
| Restart control | Both DBs **1,085,440 B** after clean close and reopen, ratio **1.000x** | No durable peer-only excess or lost canonical data |
| Healthy-space control | Available before **229,072,896 B**; after **226,893,824 B** | No induced disk exhaustion, including both DBs' legitimate allocation |

A transient **1,056,768-byte** allocation increase occurred on *both* databases during compaction (2,134,016 − 1,077,248 B). A LevelDB compaction stress could matter operationally, but the exact equality with the direct-import control defeats any claim in this experiment that it is **unprivileged peer-induced disk amplification**.

The test failed fast if storage after shutdown exceeded the direct-import control by more than 64 KiB or if free space fell below 100 MiB. Actual equality is stronger than the configured excess bound.

## Security mechanism corroboration

Certified `eth/protocols/eth/handlers.go` decodes an ETH66 response envelope into `RequestId` and `Payload`, but forwards its payload to request-aware decoding only through `peer.dispatchResponse`. Certified `eth/protocols/eth/dispatcher.go` uses the matching request ID and requested message type; an unsolicited, unknown response ID maps to `errDanglingResponse` and is treated as a protocol violation. A cancelled request can instead be silently discarded as a stale reply. The run demonstrates disconnection for both injected packets but **does not independently trace the precise internal disconnect error**, so report this source mechanism separately from measured disconnection.

The replay payload is real, previously observed RLP-encoded BlockBodiesPacket66 data. For the unrelated-ID test, only its request ID is mutated. It is not a fabricated or validator-signed block.

## Evidence markers

`R_P2K_VALID_QUORUM_FIXTURE_PASS`  
`R_P2K_LONGCHAIN_BASELINE`  
`R_P2K_DUPLICATE_DOWNLOADER_RESULT`  
`R_P2K_STALE_ID_REPLAY_RESULT`  
`R_P2K_UNKNOWN_ID_REPLAY_RESULT`  
`R_P2K_COMPACTION_CONTROL`  
`R_P2K_RESTART_DISK_ORACLE_PASS`  
`R_P2K_P2K_VALIDATED`

The test runner and workflow enforce the markers and preserve the complete GitHub job log/evidence artifact. The workflow syntax guard also passed on test commit `8a5b93dcf413c6e9c276dd2c4007dd1930b7e5cc`.

**Harness-only failure before the successful run:** [#41811578838](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41811578838) hit an unused `rawdb` import at Go compilation; no security conclusion was drawn. The import was removed before the passing execution.

## Acceptance gates

| Gate | Result |
|---|---|
| G1 certified source and unmodified production client | PASS |
| G2 actual ETH66 transport with independently QBFT-valid long chain | PASS |
| G3 explicit zero-attacker-validator-key model | PASS |
| G4 real replay of already-used body reply | PASS; 0 durable amplification, peer disconnected |
| G5 unsolicited, unrelated request ID from fresh network identity | PASS; 0 durable amplification, peer disconnected |
| G6 physical-disk comparison, compaction, restart, receipts | PASS; equality with direct control |
| G7 evidence of loss of healthy reserve, remote liveness fault or financially meaningful compromise | **NOT ESTABLISHED** |

**Classification:** NEGATIVE REPRODUCTION / SECURITY CONTROL, **not bounty-ready**.

## Limits, counterexamples and next escalation criterion

1. **Eight blocks** are larger than P2j's initial three- and four-block samples but remain a short synthetic history; this does not measure months of chain churn.
2. Only two unsolicited transport frames were tested (one old-ID and one unrelated-ID), each separately in a live connection; peers disconnected promptly. It does **not** establish an unbounded replay flooding throughput or connection-churn cost.
3. The test counts transmitted bytes, but does not benchmark CPU consumption, memory allocations, rate-limit fairness, packet ingress bandwidth, or network reputation systems. **Those are distinct resource dimensions**, not established permanent disk exhaustion.
4. The direct-import control contains **legitimate** accepted canonical data, not attacker-minted unauthorized history. The peer is allowed to relay existing finalized blocks; doing so consumes ordinary chain storage.
5. Need a genuinely **lower-authority control path** to cause durable storage outside the canonical baseline and persist across compaction and restart, starting with more than 100 MiB of free disk, before classifying the P2h ENOSPC threshold as remotely exploitable from a healthy node.

**Next hypothesis (P2l)**: iterate bounded resync/disconnection and genuinely lower-authority noncanonical block-body or node-data responses under receiver-verified request-ID constraints. Instrument per-peer ingress bytes, any persistently allocated key ranges, and process resource usage. Do not promote a claim without a concrete unprivileged actor script, independent control, production-path reproduction and actual durable growth beyond legitimate canonical history. Do not run on production or third-party validators.
