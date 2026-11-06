# 2026-11-06 17:23 NPT — B-COMMIT-PRECHECK-IMPORT — INTERNAL ONLY

**Decision: BLOCKED (production import exploit not demonstrated). Hypothetical P1 only for proven invalid finalization; no CVSS assigned. NO CONFIRMED FINDING.**

## New executed source-contract checks (NOT target-runtime tests)
Read three files at immutable Git object `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` using GitHub connector, blob IDs:
- `vendor/electroneum-sc/consensus/istanbul/backend/backend.go` `2265b91741625fc6dc518979bd9776b2a87d4d80`
- `vendor/electroneum-sc/consensus/istanbul/backend/engine.go` `31e7729d1b930a56df3380989bd1dae6ba63bf5b`
- `vendor/electroneum-sc/consensus/istanbul/engine/engine.go` `271318012a288ca19a18544551b78107ef16ca23`

Executed six deterministic source-pattern checks against the retrieved exact bytes using JavaScript; **6/6 true**: (1) `verifyCommitted` returns nil on snapshot error; (2) `Backend.Verify(proposal)` propagates snapshot errors; (3) `Backend.Commit` invokes preliminary `verifyCommitted` then routes to `commitCh`; (4) `Backend.verifyHeader` propagates snapshot errors; (5) batch `VerifyHeaders` invokes same `sb.verifyHeader`; (6) final seal verifier consumes authorized recovered signer via `RemoveValidator`. These checks establish source facts only; they do not execute Go, sign a message, verify a header, or exercise an actual import.

**Source locations:** `backend/backend.go:202-245,262-305`; `backend/engine.go:65-113`; `engine/engine.go:385-443`. In the proposer-matching branch, the block goes to `commitCh` after preliminary checking; a missing parent snapshot makes that preliminary check return nil. This is a **trust-boundary question**, not proof of import bypass. The ordinary imported-header path propagates snapshot errors and rejects duplicate/outsider signers. Need trace miner `Seal()` and actual `InsertChain` before any stronger claim.

## Controls and expected/actual
Independent N=4 F=1 oracle: current validators A+B+C (3) should be accepted, A+B+removed E (2 current) rejected, A+B+B rejected, A+B+outsider rejected. **Actual signed target-runtime outcomes this run: NOT EXECUTED**. Positive control for the six source checks: all 6 true. Negative control: direct verifier's membership-removal guard is present and parent-snapshot errors are propagated by normal header verification. This is a source-level counterexample, not runtime disproof.

Attacker would need to control one validator's committed messages AND reach an import route that skips final parent-set verification. Neither the latter route nor a consensus safety failure is established. No measured financial impact or liveness degradation.

## Certification / execution / limits
Documentary expected identity: certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Fresh bootstrap not executed; tree hash not recomputed. Root contract/certificate/provenance paths 404 at branch; do not imply they were read. Local `getent hosts github.com` yielded no addresses; `go version` returned go1.23.2 linux/amd64. No Go target test command or exit code exists. Historical run 41739785577 is not evidence of this path. Active class CI inventory not established; no dispatch/cancel.

**Strongest counterexample:** ordinary single and batch header verification both require the parent snapshot and return errors before committed-seal validation; `RemoveValidator` prevents duplicate voting. No evidence that one Byzantine validator can cause a production importer to accept a block with only two current-set signatures.

**Next one discriminator:** On certified runner, run signed N=4 F=1 real block-import fixture at a validator-set transition, comparing A+B+C vs A+B+removed E and snapshot error, and trace whether proposer `commitCh` eventually invokes a mandatory verification boundary. No broad fuzz or status-only CI.
