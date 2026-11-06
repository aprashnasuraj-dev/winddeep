# B-MINER-DIRECT-WRITE — 2026-11-06 18:23 NPT

**Decision: SUSPECTED (E1 source only), NOT REPORTABLE.** Hypothetical P1 only if an attacker with <=1 Byzantine validator can cause canonical invalid finalization. No CVSS, no confirmed breach.

## New evidence this invocation
Immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` was retrieved through GitHub connector; fresh certified runtime bootstrap was not possible (local `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` failed exit 128: DNS). Source identities are documentary only: tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.

1. `consensus/istanbul/backend/backend.go:202-245`: `Backend.Commit` attaches seals, invokes `verifyCommitted`, then sends proposer-matching block to `commitCh`.
2. `backend/backend.go:262-275`: preliminary `verifyCommitted` returns nil if `sb.chain == nil` or parent snapshot retrieval fails; otherwise invokes committed-seal verifier.
3. `consensus/istanbul/backend/engine.go:239-247`: `Seal` forwards matching `commitCh` block into mining result channel.
4. **NEW:** `miner/worker.go:703-768`: `resultLoop` receives block from result channel and calls `w.chain.WriteBlockAndSetHead(block, receipts, logs, task.state, true)` without an explicit `VerifyHeader` call at that point.
5. **NEW:** `core/blockchain.go:1295-1349`: `WriteBlockAndSetHead` calls `writeBlockAndSetHead` and `writeBlockWithState`, then may set canonical head; the inspected wrapper contains no explicit consensus `VerifyHeader` call. This is a real alternate write path, NOT proof that consensus can be subverted.
6. `consensus/istanbul/engine/engine.go:385-443`: the actual seal verifier rejects outsider/duplicate/insufficient committed seals when invoked with correct parent validator set.

## Exact invariant and counterexample
N=4, F=1: expected honest A+B+C signatures accepted; A+B+removed E, A+B+duplicate B, A+B+outsider rejected. **Observed this run:** source-level call chain only; no signed fixture, no canonical invalid block, no snapshot failure during actual commit, no production adversarial ingress. A single Byzantine validator cannot trivially manufacture the two honest signatures needed to enter `Backend.Commit` legitimately; QBFT core quorum and signed-message validation may fully defeat the suspected bypass. Moreover, a snapshot retrieval failure might prevent normal consensus operation before `Commit` is reached. These are the strongest counterexamples. The source-level distinction between miner direct-write and network `InsertChain` does not prove attacker control over this path.

## Tests and missing proof
New source retrieval executed through connector (file blob SHA miner/worker.go `61243006df9ae46797c5d163c735a51be976c999`; core/blockchain.go inspected). Local `go version`: go1.23.2; local Git DNS exit 128. **No certified Go test executed**, no honest/adversarial runtime controls, no three repetitions, no independent signed quorum oracle, no E2/E3/E4. Historical Actions 41739785577 tests only isolated committed-seal verification, not this path. No CI launched/cancelled. Duplicate/CVE check not established.

## Next one discriminating test
Use certified isolated source with four synthetic validator keys and a real QBFT core-to-Backend.Commit-to-miner result fixture. Force parent-snapshot lookup failure *after* legitimate proposal validation, compare A+B+C versus A+B+removed E and duplicate, verify whether any invalid block reaches canonical head. Instrument real `WriteBlockAndSetHead` and independent signed-quorum oracle. If snapshot failure cannot be reached after quorum, DISPROVE this hypothesis for that path. No broad fuzz.
