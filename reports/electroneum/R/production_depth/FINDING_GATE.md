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
- P2 crash/persist replay: LevelDB reopen after explicit sync-stage interruptions; unclean-shutdown marker, body/receipt/index/head commitment matrix and corruption control.
- P3 realistic parser budgets: ~4.7 MiB HTTP body, ~4 MiB nested ABI, ~2 MiB raw transaction and receipt/log data. CI enforces 512 MiB Go memory limit, CPU/wall clocks and records /usr/bin/time -v.
- P4 priority consensus integration: real priority block execution across registry/future-signature transition, same txpool admission boundary, then actual chain reorg/pool state. Exact parity marker: R_PRIORITY_POOL_EXECUTION_PARITY_MISMATCH.

Every candidate artifact must state production_reachability=ESTABLISHED|OPEN|DISPROVEN, never leave it implicit.
