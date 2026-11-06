# B-PARENT-SET-TRANSITION — internal evidence assessment (2026-11-06 13:17 NPT)

**Decision: BLOCKED for new certified-runtime execution; no confirmed vulnerability.** Hypothetical P1 only if a below-quorum finalization actually occurs. E1 source inspection newly performed; historical E2 applies to direct verifier controls, not this transition. E3/E4 absent; no CVSS assigned.

## Attacker, competing explanations, independent expected result

X1: one Byzantine signer among N=4 (F=1), eventual network delivery; X0 outsider is a separate negative control. At block height h, parent h-1 has validator set V_new={A,B,C,D}; earlier canonical set V_old={A,B,C,E}. The only admissible quorum for h is three *distinct* signatures from V_new. Honest {A,B,C} must pass. {A,B,E}, {A,B,B}, and {A,B,X outsider} must fail. A legitimate transition that adds D/removes E is effected by a majority vote in the preceding canonical header, not by an attacker-chosen header extra-data validator list.

H1: verifier uses the correct parent snapshot and rejects E. H2: a transition/import path inadvertently passes the previous set or trusts header-declared validators, allowing E. H3: isolated verifier controls pass, but a production import path omits them.

## Newly traced certified source (E1)

Source revision: immutable Windeep commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0, certified tree de7f3c75a2db7e87a89918f1257820703d5b731e, upstream pin 3aeb14db0d6384243302f3a025bdff904dc28bf6, archive provenance SHA256 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b. Exact-revision connector reads, **not** fresh bootstrap.

- `consensus/istanbul/backend/engine.go:65-82`: `Backend.verifyHeader` obtains `snapshot(chain, header.Number-1, header.ParentHash, parents)` and passes `snap.ValSet` to height-selected `Engine.VerifyHeader`. It does not pass validators declared by the candidate header.
- `consensus/istanbul/backend/engine.go:514-603`: snapshot cache/disk lookup keyed by parent hash; absent cache, canonical parent traversal, reversed chronological header application via `snapApply`. It rejects parent hash/number mismatch for supplied parents.
- `consensus/istanbul/backend/engine.go:620-710`: `snapApplyHeader` authenticates header author against snapshot validators, processes vote, and applies authorization changes when tally exceeds `ValSet.Size()/2`. A transition in parent h-1 therefore affects the snapshot used for h. This source path does not establish whether all parent headers were fully verified before being cached.
- `consensus/istanbul/engine/engine.go:385-443`: `verifyCommittedSeals` recovers signatures and consumes each member once via `validators.Copy().RemoveValidator`, then requires `ceil(2*N/3)` valid signers. N=4 requires 3.
- `consensus/istanbul/backend/backend.go:258-275`: local `verifyCommitted` also obtains the parent snapshot and invokes `VerifyCommittedSeals`; on snapshot error it returns nil, so **this pre-import guard alone is not fail-closed**. This is not a confirmed bypass: production `Backend.verifyHeader` returns snapshot errors and verifies seals, and complete import-path coverage remains to be proven. Do not confuse local pre-import guard with final acceptance.

## Observed versus expected / strongest counterexample

Expected: A+B+C accepted; A+B+E rejected after transition; duplicate B and outsider X rejected; no production header accepted without correct parent-set quorum. Observed this invocation: source-level parent-hash snapshot selection and once-only signer consumption; **zero** executed transition fixtures, no accepted or rejected target-runtime transition headers. Historical Actions run 41739785577 (trigger a8601c5ed0e536ec151f12b3540b77c49fbda61b, job 126278100119) had successful isolated signer controls, but did not exercise a parent vote transition. Strongest counterexample to H2 is the explicit parent-hash snapshot derivation and once-only membership removal. Strongest remaining gap for H3 is full import-path execution with realistic canonical chain state.

## Actual command and status evidence

Local `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git refs/heads/electroneum-sc-master-audit` -> exit 128, `Could not resolve host: github.com`. No local checkout, no `source tools/electroneum_target_bootstrap.sh`, no new Go version or `go test` result, no mutant and no current-runtime output. GitHub connector exact immutable file reads succeeded. Original trigger combined status `security-audit/B=success`; historical run 41739785577 job completed success. Current active-run inventory not exhaustive; no new run dispatched or cancelled. G1/G3/G4 unmet, G2 source-level partial, G5 source/exit evidence only, G6 new parent-transition trace, G7 class-only evidence commit.

## Narrow next discriminating experiment

In a certified fresh read-only bootstrap, use disposable scratch Go package fixture with four synthetic keys and a canonical parent vote transition from E to D. Call `Backend.VerifyHeader` (not just `Engine.VerifyCommittedSeals`) with realistic chain/snapshot state, asserting A+B+C pass and A+B+E, A+B+B, A+B+outsider fail; verify the same through the actual import entry. Repeat any breach 3 times, test a deliberately weakened parent-set selection mutant, and capture `go test -count=1 -v` with named tests/exit/log. If a runner is unavailable, keep BLOCKED; do not publish a finding.
