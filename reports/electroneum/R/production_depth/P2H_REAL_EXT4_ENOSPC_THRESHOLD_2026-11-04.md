# Worker R P2h — Real ext4 ENOSPC threshold over ETH/66

**Evidence date:** 2026-11-04 UTC  
**Branch:** `audit/r-production-depth-20261104-17-enospc-peer-threshold`  
**Certified production-depth run:** https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41806126281 — PASS  
**Workflow syntax guard:** https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41805341732 — PASS  
**Certified Electroneum source:** `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` / tree `de7f3c75a2db7e87a89918f1257820703d5b731e` — unchanged.

## Executive result

P2h moves the prior storage-failure model from a per-file `RLIMIT_FSIZE/EFBIG` condition to a **real ext4 filesystem-space exhaustion condition**.

A receiver on a disposable 128 MiB ext4 loopback filesystem was filled to a controlled remaining-space margin. An independent loopback peer then delivered an **already-valid 3-of-4 QBFT-committed block** over the real TCP/RLPx/ETH66/downloader path. The block carried one valid signed transaction with a 256 KiB non-zero payload to force meaningful database growth.

The seven tested requested free-space margins produced:

| Requested free space before sync | Result |
|---:|---|
| 8 MiB | Import success |
| 2 MiB | Import success |
| 512 KiB | Import success |
| 128 KiB | Native LevelDB ENOSPC; fatal exit 1 |
| 32 KiB | Native LevelDB ENOSPC; fatal exit 1 |
| 8 KiB | Native LevelDB ENOSPC; fatal exit 1 |
| 4 KiB | Native LevelDB ENOSPC; fatal exit 1 |

The fill routine targets each requested margin to within one 4 KiB filesystem block. Therefore, for this exact block, filesystem image, LevelDB state and runner, the observed transition is bracketed between approximately **128 KiB and 512 KiB available**. This is a measured fixture boundary, not a universal production threshold.

## Evidence gates

- **G1 source identity — PASS.** Exact event SHA and certified source/tree were recorded; certified source remained unchanged.
- **G2 positive control — PASS.** The same real TCP/RLPx/ETH66 path imported the quorum-valid block and exposed its successful receipt when sufficient filesystem space remained.
- **G3 strict oracle — PASS.** Failure cases required all of: successful ETH66 block-body response, the unmodified LevelDB batch-write error, native Linux `no space left on device`, and process exit code 1.
- **G4 durable reproducer — PASS.** `reports/electroneum/R/production_depth/qbft_real_enospc_peer_threshold_test.go`.
- **G5 sensitivity/counterexample — PASS.** 8 MiB / 2 MiB / 512 KiB controls succeed, while 128 KiB / 32 KiB / 8 KiB / 4 KiB fail. The prior small-block sweep also succeeded at all seven margins, showing that free-space level alone is insufficient; valid write amplification materially changes the result.
- **G6 lower-trust trigger — PARTIAL.** Once a node is already near full, the network peer can time delivery of an ordinary already-valid quorum block and tip the receiver into the real ENOSPC fatal-write path. The peer did **not** create the initial near-full filesystem state and did not bypass QBFT.
- **G7 concrete impact — PARTIAL / local availability only.** The reproduced consequence is receiver process termination on the native database write failure. No deployed third-party false credit, financial loss, authorization bypass, validator-key compromise or chain-finality break was demonstrated.

## Actor boundary

The peer's capability in P2h is deliberately limited: it serves a block that is already valid under the configured QBFT validator set. It does not own 3-of-4 validator keys in the receiver threat model, forge committed seals, mutate local filesystem quotas, or write arbitrary host files.

This matters because the successful causal statement is:

> **pre-existing near-full storage + valid network synchronization traffic -> native ENOSPC -> shipped fatal database-write path**

The stronger statement:

> **unprivileged peer alone -> fills healthy node storage -> fatal exit**

is **not established**.

## Counterexamples and rejected interpretations

1. A tiny valid block imported successfully even with the filesystem filled to the same requested 4 KiB margin in the preceding bounded run. This disproves treating “low free space” by itself as the complete trigger.
2. 512 KiB free was sufficient for the amplified 256 KiB-transaction block in the certified run, so the node is not shown to crash merely because it crosses a broad “below 1 MiB” threshold.
3. Existing Worker R QBFT controls reject the tested 2-of-4 lower-authority block. P2h does not weaken that result.
4. Forcing an artificial zero-byte filesystem before the peer acts was rejected as the primary experiment because it would prove local exhaustion, not peer-triggered incremental failure.

## Security classification

**Verified fact:** a real protocol delivery can be the final operation that crosses a real ext4 ENOSPC boundary and reaches the shipped fatal LevelDB-write handling when the receiver is already very near capacity.

**Inference:** nodes operating inside a similarly narrow free-space window could have availability coupled to normal catch-up traffic volume. The exact margin depends on block size, LevelDB/WAL state, filesystem behavior, compaction, and sync phase.

**Not established:** remote creation of the disk-pressure precondition, repeatable exhaustion from a healthy production storage reserve, deployed-network outage, financial loss, or a standalone bounty-ready remote DoS.

## Next nonredundant gate

Advance G6 from **PARTIAL_TRIGGER_ONLY** only by starting from a receiver with a quantified *healthy* free-space reserve and showing that protocol-valid lower-trust sync traffic can consume that reserve at an attacker-influenced rate materially above unavoidable canonical-chain growth. The next experiment should therefore measure **bytes written per delivered valid block / per MiB of block body**, include a no-peer/canonical-baseline control, and calculate the traffic-to-disk amplification ratio.

A useful promotion threshold is evidence of attacker-controlled amplification rather than a one-for-one consequence of legitimate chain growth. If storage consumption is approximately proportional to canonical data received, classify the condition as operational capacity exhaustion rather than a protocol vulnerability.

## Superseded harness runs

The following are not source findings:

- 41805223935 / 41805226068: malformed first workflow insertion; workflow/syntax failure.
- 41805341821: first real ext4 sweep reached the target but all seven tiny-block cases succeeded; useful negative boundary.
- 41805702666 / 41805929493: compile-only logging-format errors while adding the amplified block fixture.

Only the passing, source-certified run 41806126281 is used for the P2h threshold classification above.
