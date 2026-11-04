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
- P1b downloader-fed reorg: actual downloader `Peer` registration, ETH66 service-query handlers, `LegacySync`, validated competing-fork import, and concurrent real `EthAPIBackend` receipt reads. The peer is **synthetic and in-process**; no TCP, RLPx handshake, externally controlled devp2p peer or QBFT validator adversary was tested. Certified campaign: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41764867034 (success). Observed 36 straddled stale-receipt responses in 814,710 calls across 32 bounded trials. This supports G6=PARTIAL, not G6=ESTABLISHED; G7 remains OPEN.
- P2 crash/persist replay: LevelDB reopen after explicit sync-stage interruptions; unclean-shutdown marker, body/receipt/index/head commitment matrix and corruption control.
- P3 realistic parser budgets: ~4.7 MiB HTTP body, ~4 MiB nested ABI, ~2 MiB raw transaction and receipt/log data. CI enforces 512 MiB Go memory limit, CPU/wall clocks and records /usr/bin/time -v.
- P4 priority consensus integration: real priority block execution across registry/future-signature transition, same txpool admission boundary, then actual chain reorg/pool state. Exact parity marker: R_PRIORITY_POOL_EXECUTION_PARITY_MISMATCH.

Every candidate artifact must state production_reachability=ESTABLISHED|OPEN|DISPROVEN, never leave it implicit.

## 2026-11-04 R integration CI classification and next evidence gate

- Integration push https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41765115057 (`f16fd831f6e71887c041199deac36a01f3052eb7`) reports `conclusion=failure` with **zero jobs and zero artifacts**. This is `WORKFLOW_NOT_STARTED/CI_CONFIGURATION`, **not a test failure and not a finding**. Do not infer which workflow-config mechanism failed without a GitHub validation annotation. A retry of the same workflow configuration alone does not strengthen a security claim.
- The R production-depth workflow is branch-scoped to `audit/r-production-depth-20261104-*` (excluding seed). The R stateful seed branch is **not an eligible production-depth CI run target**. Only cite successful runs on the matching dedicated campaign branches when claiming execution.
- `P1b` CI evidence exists and is independently green: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41764867034. `P2` abrupt process-restart evidence also passed: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41764251176.
- Next G6 experiment must use a **real loopback TCP/RLPx/devp2p handshake**, real protocol peer registration and downloader import, and instrument the exact fork/receipt ordering. Keep source immutable and isolate scratch chain/state. Compare against a counterexample: a consumer verifying canonical block hash after receiving the receipt rejects stale results. Do not claim attacker control of a QBFT-valid competing fork from transport alone.
- Next consensus reachability experiment must demonstrate the permitted QBFT fork/reorg preconditions, with explicit validator authority and finality assumptions. If the necessary adversarial control exceeds the intended threat model, classify G6 as `NOT_ESTABLISHED` for that actor rather than calling it exploitable.
- Next G7 experiment must define one named downstream consumer and assert a concrete incorrect security/financial decision **despite its ordinary confirmation and canonicality checks**. Without such an impact demonstration, retain `SOURCE_DEFECT_REPRODUCED` and `SECURITY_FINDING_NOT_PROMOTED`.
- A failed/timeout/compile-invalid harness must be corrected and rerun on an eligible branch before evaluating any source oracle. Preserve provenance for individual trials and report counts separately from estimated exploit probability.
