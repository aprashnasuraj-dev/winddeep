# Worker R production-depth finding gate

This phase does **not** promote a red CI job, panic, timeout, or fuzz assertion directly into a security finding.

## Mandatory evidence gates

| Gate | Required evidence | Failure classification |
|---|---|---|
| G1 Source identity | exact event SHA plus certified Electroneum commit/tree, source unchanged after test | infrastructure/test invalid |
| G2 Positive control | coherent valid case reaches the intended production code path and succeeds | harness invalid |
| G3 Named strict oracle | one exact invariant marker identifies the target mismatch; generic panic/compile/timeout is rejected | harness/infrastructure failure |
| G4 Durable reproducer | committed deterministic test or minimized corpus plus exact command | candidate only |
| G5 Counterexample/sensitivity | nearby valid/invalid states prove the oracle is discriminating; defensive scratch change or independent cross-layer control when appropriate | candidate only |
| G6 Production reachability | demonstrate a shipped lower-trust input/path can create the precondition without privileged test hooks | source defect only if absent |
| G7 Concrete impact | reproduce specific integrity/availability/authorization consequence; no inferred theft/finality claims | no security severity if absent |

**Promotion rule:** SECURITY_FINDING_CONFIRMED requires G1-G7. G1-G5 can close a source-level defect. G1-G4 without counterexample/sensitivity remains UNTRIAGED_CANDIDATE.

## Current campaigns

- P1 full backend reorg: real BlockChain + EthAPIBackend; deterministic scheduling sensitivity plus unmodified concurrent InsertChain stress. InsertChain is peer-equivalent validated import, **not** a devp2p transport reproduction.
- P1b downloader-fed reorg: actual downloader `Peer` registration, ETH66 service-query handlers, `LegacySync`, validated competing-fork import, and concurrent real `EthAPIBackend` receipt reads. The peer is **synthetic and in-process**; no TCP, RLPx handshake, externally controlled devp2p peer or QBFT validator adversary was tested. Certified campaign: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41764867034 (success). Observed 36 straddled stale-receipt responses in 814,710 calls across 32 bounded trials.
- P1c loopback devp2p reorg: two real `p2p.Server` instances negotiated TCP/RLPx + ETH66, registered the remote protocol peer through `runEthPeer` into the real downloader and synchronized the competing chain. Certified campaign: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41767213441 (success). Across 12 trials: 3,041,785 receipt calls, 2,142,752 old-receipt responses, 48 post-response stale receipts, 29 requests straddling the canonical flip, maximum measured flip-to-return interval 12,931,088 ns (~12.93 ms). This establishes the race survives the real devp2p transport stack on controlled loopback. It does **not** establish that an ordinary peer can create a QBFT-valid competing fork, and G7 remains OPEN.
- P1d QBFT authority gate: certified campaign https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41768312671 (success) exercised the real backend verifier and `BlockChain.InsertChain`. Exact quorum imported for N=1/4/7 at 1/3/5 unique seals respectively; N=4 with 2 seals and N=7 with 4 seals were rejected; duplicate-validator and outsider-signature quorum-shaped inputs were rejected. The shipped threshold is `ceil(2N/3)` unique validator committed seals. Therefore an ordinary external peer without validator authority cannot manufacture the competing finalized block precondition through the consensus verifier.
- P1e quorum-authorized end-to-end path: certified campaign https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41769370716 (success) built competing QBFT branches using 3-of-4 unique validator committed seals, waited until each remote tip was inside the shipped 5-second future-block window, connected real TCP/RLPx/ETH66 peers, synchronized the branch through the downloader, and reproduced the stale-receipt race. Four trials produced 1,509,994 receipt calls, 1,345,307 old-receipt responses, 16 post-response stale receipts, 7 canonical-flip-straddling stale responses, max measured flip-to-return 4,780,307 ns (~4.78 ms). This establishes conditional G6 reachability for a validator-quorum actor; it does not change the ordinary-peer rejection boundary.
- P2 crash/persist replay: LevelDB reopen after explicit sync-stage interruptions; unclean-shutdown marker, body/receipt/index/head commitment matrix and corruption control.
- P3 realistic parser budgets: ~4.7 MiB HTTP body, ~4 MiB nested ABI, ~2 MiB raw transaction and receipt/log data. CI enforces 512 MiB Go memory limit, CPU/wall clocks and records /usr/bin/time -v.
- P4 priority consensus integration: real priority block execution across registry/future-signature transition, same txpool admission boundary, then actual chain reorg/pool state. Exact parity marker: R_PRIORITY_POOL_EXECUTION_PARITY_MISMATCH.

Every candidate artifact must state production_reachability=ESTABLISHED|OPEN|DISPROVEN, never leave it implicit.

## 2026-11-04 R integration CI classification and next evidence gate

- Integration push https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41765115057 (`f16fd831f6e71887c041199deac36a01f3052eb7`) reports `conclusion=failure` with **zero jobs and zero artifacts**. This is `WORKFLOW_NOT_STARTED/CI_CONFIGURATION`, **not a test failure and not a finding**. Do not infer which workflow-config mechanism failed without a GitHub validation annotation. A retry of the same workflow configuration alone does not strengthen a security claim.
- The R production-depth workflow is branch-scoped to `audit/r-production-depth-20261104-*` (excluding seed). The R stateful seed branch is **not an eligible production-depth CI run target**. Only cite successful runs on the matching dedicated campaign branches when claiming execution.
- `P1b` CI evidence exists and is independently green: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41764867034. `P2` abrupt process-restart evidence also passed: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41764251176.
- The real loopback TCP/RLPx/devp2p gate is now **PASS** in run 41767213441. Transport reachability is no longer the principal open question. Preserve the counterexample: a consumer verifying canonical block hash after receiving the receipt rejects stale results.
- The QBFT authority gate is now **PASS as a boundary test** in run 41768312671: exact quorum is accepted/imported and sub-quorum, duplicate, and outsider signatures are rejected. For the ordinary external-peer actor, the required competing-finalized-block precondition is **NOT REACHABLE without validator authority**.
- Conditional G6 for the stronger validator-quorum actor is now **ESTABLISHED** end-to-end by run 41769370716: quorum-authorized QBFT branch → real TCP/RLPx/ETH66 → downloader → canonical replacement → stale-receipt window. Ordinary external-peer G6 remains **DISPROVEN** by the quorum gate.
- Do not collapse these actor models: the reproducer explicitly possesses 3-of-4 validator keys. It demonstrates behavior after consensus authority is already sufficient to finalize the conflicting branch, not a method for an unauthenticated peer to obtain that authority.
- Remaining G7 work is to identify a concrete downstream consumer whose normal confirmation/canonicality controls still make an incorrect security or financial decision. Confirmation-only consumers are insufficient evidence if a canonical block-hash recheck would reject the stale receipt.
- Next consensus reachability experiment must demonstrate the permitted QBFT fork/reorg preconditions, with explicit validator authority and finality assumptions. If the necessary adversarial control exceeds the intended threat model, classify G6 as `NOT_ESTABLISHED` for that actor rather than calling it exploitable.
- Next G7 experiment must define one named downstream consumer and assert a concrete incorrect security/financial decision **despite its ordinary confirmation and canonicality checks**. Without such an impact demonstration, retain `SOURCE_DEFECT_REPRODUCED` and `SECURITY_FINDING_NOT_PROMOTED`.
- A failed/timeout/compile-invalid harness must be corrected and rerun on an eligible branch before evaluating any source oracle. Preserve provenance for individual trials and report counts separately from estimated exploit probability.
