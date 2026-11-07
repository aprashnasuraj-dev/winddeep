# D — root-guard fixture execution and pivot decision (2026-11-07 NPT)

## Exact evidence
- Audit branch HEAD observed before this assessment: `a1c493e50be5068e7244980e3d38d036802d8429` (Class A change). Not the Class D test trigger.
- Matching historical Class D run: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/42345353600 ; head SHA `05920a20c3af77e5431cca5c6e8944b65aed9b83`; job `128321811643`, completed SUCCESS.
- Retrieved **actual job log** through GitHub connector. Its runner recorded `FRESH_MATRIX_ATTEMPT 1/3 class=D probes=3 PASS_REGRESSION_ONLY` at 06:05:01Z, attempt 2 at 06:05:18Z, attempt 3 at 06:05:35Z, and `FRESH_MATRIX_FINAL class=D status=PASSED_INDEPENDENT_REGRESSIONS_NOT_FINDINGS`.
- This log does **not** expose the individual Go probe output/markers, fixture seeds, or the artifact's per-probe hashes. Those must be checked before claiming each root-control assertion independently executed. No new Go test was run in this assessment.

## Discriminating conclusion
- The previous duplicate-test compilation blocker was repaired and the three-process matrix completed for the corrected registration. This is **harness success**, not a vulnerability or QBFT finality evidence.
- `D-short-sibling-restart` and `D-invalid-sibling-root-restart` remain fake-PoW import/persistence regressions. They do not prove peer ingress, signed validator quorum, finality violation, or current deployed-version exposure. Retire further malformed-root variants absent a newly demonstrated bypass.
- The strongest counterexample is ordinary import-root validation combined with consensus signature/quorum verification before canonical insertion; a valid pre-finality reorg is not an attack.
- **G0** not established; **G1** partial source grounding; **G2** historical harness execution only (per-probe raw outputs not independently reviewed); **G3/G4** unmet. **Verdict: NO CONFIRMED FINDING.**

## One next executable discriminator
- In a class-owned Go test copied to the certified source's `consensus/istanbul/backend` package, use upstream `backend/engine_test.go` helpers `testutils.GenesisAndKeys`, `newBlockchainFromConfig`, `makeBlockWithoutSeal`, and `Backend.VerifyHeader`. Build two conflicting **properly signed** QBFT branches with distinct synthetic validators; test insufficient committed seals vs a quorum-valid branch, then verify finalized canonical/receipt indices after DB reopen against an independent oracle. First establish how to produce valid committed seals and that peer-delivered headers actually reach this verifier. Do not count unsealed/fake-PoW fixtures as finalized blocks.
