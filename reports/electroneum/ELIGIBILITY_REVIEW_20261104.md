# Electroneum A-E bounty eligibility strengthening — 4 November 2026

## Executive conclusion

A certified source-backed verification campaign has now succeeded end-to-end: [GitHub Actions 41775518831](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41775518831), job 126394841186. It established a stronger E-RPC-004 outcome in a simulated third-party recipient and rechecked defenses for all seven defect families. No external attacker-controlled A-E bounty outcome is yet proven.

Test branch: audit/eligibility-20261104; exact source Electroneum upstream 3aeb14db0d6384243302f3a025bdff904dc28bf6, pinned source tree de7f3c75a2db7e87a89918f1257820703d5b731e. All tests run on temporary certified copies, not real public infrastructure.

## E-RPC-004 — strongest Category E candidate

Real, in-process downloader LegacySync fed a validated competing fork into core.BlockChain while PublicTransactionPoolAPI.GetTransactionReceipt was suspended between its canonical transaction lookup and independent receipt lookup. The old successful transaction was returned after the new fork became canonical.

Deterministic result:
- Original transaction at block 1; initial head 4, positive control showed 4 confirmations.
- After downloader switch head=5, old block 1 is noncanonical. The API still returned its successful receipt, making 5 apparent confirmations.
- A modeled third-party deposit-monitor rule accepting status+numeric-confirmations>=3 returned naive_credit=true.
- A properly canonical-aware consumer returned canonical_aware_credit=false.
- Fresh receipt request *after* the reorg returned nil. The problem is the mid-query consistency window, not generic stale indexing.
- CI marker: ELIGIBILITY_E004_UNSAFE_CONSUMER_FALSE_CREDIT_SIMULATED naive_credit=true canonical_aware_credit=false min_confirmations=3.
- CI markers: ELIGIBILITY_E004_DOWNLOADER_STALE_RECEIPT_CONFIRMED and ELIGIBILITY_E004_COMPLETED_REORG_NEGATIVE_CONTROL_PASS.
- Reproducer: reports/electroneum/eligibility/e004_e008_production_controls_test.go. It uses existing R production-depth full-backend and downloader helper tests.

This is evidence of a plausible third-party false-credit mechanism, NOT evidence that a real exchange uses that rule, or that a below-threshold adversary can trigger this chain change under real QBFT finality. Synthetic peer is in-process and the test genesis uses a fake Ethash engine; it does not exercise TCP/RLPx/devp2p or public Electroneum validators.

Next decision: strengthen through genuine QBFT finality and authenticated peer control before treating it as unambiguously bounty-eligible. Even if a server adds a final recheck, clients still need canonical confirmation logic for chain changes after a response.

## E-RPC-008 — silent partial logs

The controlled missing-header case still returned only 1 of 3 logs without error; however the newly executed real EthAPIBackend test verified contiguous headers on both sides of an ordinarily validated competing-chain import.

Markers: ELIGIBILITY_E008_COHERENT_FULL_BACKEND_HEADER_RANGE_PASS and REVERSE_E_LOG_MISSING_MIDDLE_SILENT_PARTIAL_OBSERVED count=1 requested=3.

The defect exists under artificial missing headers; attacker-induced gaps on coherent production nodes are unproven. Category E remains conditional.

## E-RPC-002 — full-width gas price display

Earlier signed synthetic tests demonstrated a price 2^64+12345 rendered as 12345 in receipt fields. New runtime checked the actual default checkTxFee admission boundary: a 21,000-gas transaction with that price is rejected under a 100,000-unit RPC cap. Disabling the cap passes this *single check*, not full execution or block inclusion. CI: ELIGIBILITY_E002_DEFAULT_RPC_CAP_REJECTS_HIGH_FEE_PASS; amount 387381625547900843181000 base units.

Therefore display truncation is real but Category E external exploit is NOT established. Need a valid signed and included high-price transaction, not a mock backend alone.

## B — QBFT round-width anomalies

The signed seal-domain 0/2^32 collision and 2^63/2^64 arithmetic issues reproduced. The actual authenticated admission handler still rejected F+1 high-round attempts; MaxFutureRoundGap=15. No effect on finalized blocks, issuance or liveness established. Markers: REVERSE_B32_SIGNED_SEAL_DOMAIN_ALIAS_CONFIRMED, REVERSE_B32_FPLUS1_IMMEDIATE_ADMISSION_BLOCKED_PASS.

Category B submission remains unsupported. Prioritize authenticated future-sequence backlog revalidation and a realistic latency/throughput or finality oracle instead of another numeric collision-only fuzz pass.

## D — local finalized-marker inconsistency

Local administrative SetFinalized(7) followed by SetHead(4) retained in-memory finalized height 7. Marker: REVERSE_D_STALE_FINALIZED_POINTER_OBSERVED finalized=7 current=4. No external altered-history acceptance or real QBFT validator path was tested. Category D not met.

## C-002 — encrypted-keystore panic

Exported KeyStore.Import still panicked on missing or numeric KDF salt and invalid AES-CTR IV. Valid input and structured-error controls passed. No unauthorized wallet access, private-key disclosure or default encrypted-keyfile remote RPC route was demonstrated. Category C not met; ordinary process crashes are excluded unless a qualifying funds/consensus consequence is shown.

## E-RPC-010 — missing receipt header

Real receipt adapter panics under synthetic nil London header. Marker REVERSE_E_RUNTIME_NIL_HEADER_PANIC_OBSERVED. No qualifying A-E consequence or attacker ability to cause the required state. Ordinary DoS is excluded. Do not submit as Category E solely for the panic.

## Submission-readiness matrix

| Family | Bug verified? | A-E outcome proven? | Action |
| --- | --- | --- | --- |
| E004 race and simulated false credit | Yes | Simulated only, not real exchange/QBFT | Highest-priority conditional Category E |
| E008 incomplete log range | Yes under injected gap | No | Investigate realistic header loss |
| E002 fee width truncation | Yes under high-price fixture | No | Test real inclusion and valid funds |
| B QBFT width | Yes | No, handler blocks test rounds | Test reachable signed state transition |
| D finalized marker | Yes under admin rewind | No | Demonstrate lower-trust historical acceptance |
| C002 keystore import | Yes | No key theft/disclosure | Keep engineering-only |
| E010 nil header | Yes | No | Keep engineering-only |

All test jobs completed SUCCESS. Certified source and worker-owned paths were not modified; previous A-E scheduled audits remain separate.

CI: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41775518831
