# A-REWARD-ZERO-COINBASE-01 — validator-gate falsification (2026-11-07 03:11 NPT)

**Decision: DISPROVEN for ordinary non-validator external triggering of a zero-Coinbase canonical block under normal nonzero-validator configuration.** This is E1 source evidence only, not certified runtime E2. No confirmed P1–P4 vulnerability; no CVSS score assigned.

## Fresh source evidence
Read immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` using GitHub connector:
- `vendor/electroneum-sc/consensus/istanbul/backend/engine.go:184-189`: `Finalize` only credits a nonzero Coinbase.
- Same file `:466-489`: `emissionApply` accumulates the calculated reward without checking Coinbase.
- `vendor/electroneum-sc/consensus/istanbul/engine/engine.go:328-383` (blob `271318012a288ca19a18544551b78107ef16ca23`): `verifySigner` rejects non-validator Coinbase before FutureFork (`:378-380`); after FutureFork it requires a recovered proposer signature matching Coinbase and validator membership (`:338-356`).
- Same file `:320-325`: header verification calls `verifySigner` before committed-seal verification; `:544-555`: sealing sets Coinbase to local signer and post-fork signs it.

Thus, assuming the active validator set does not contain the zero address (not independently checked here), a zero-Coinbase header fails the shipped header validation path, and an ordinary transaction sender cannot select a valid canonical Coinbase. The synthetic 4 ETN difference from the previous assessment is **not** observed chain behavior or an unauthorized spendable credit.

## Controls and limitations
Positive control: nonzero configured validator Coinbase passes the *membership predicate*, subject to all other header and consensus requirements. Negative control: zero Coinbase fails the same predicate when zero is absent from validator set. Post-fork counterexample: a proposer seal must cryptographically recover to Coinbase. This invocation executed **source reads only**; no Go test, no certified bootstrap, no CI, no runtime exit code, and no measured wei transfer. Historical certification identities: tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned commit `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`; not freshly reasserted.

**Strongest counterexample to absolute disproof:** a deliberately configured zero-address validator or an alternative bypass of normal header verification. Neither is shown production-valid, externally attacker-reachable, or security-impacting; such configuration must not be called a vulnerability without proof. A byzantine authorized proposer is not equivalent to an ordinary transaction sender.

## Evidence decision
Hypothetical P3–P4 conditional on an actual unauthorized balance or issuance effect; presently **no reportable severity**. E1 source fact; E2/E3/E4 absent. Next distinct test: select a fee/reward candidate where an unprivileged signed transaction controls the relevant input and a spendable state delta can be measured in certified canonical import. Do not repeat the zero-Coinbase arithmetic model. Required root audit-contract files were 404 at specified paths; no full contract reconciliation claimed.
