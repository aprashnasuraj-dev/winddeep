# A-REWARD-ZERO-COINBASE-01 — internal evidence assessment (2026-11-07 02:09 NPT)

**Decision: SUSPECTED / E1 only; NOT REPORTABLE.** Hypothesized P3–P4 only if a consensus-valid externally inducible zero-coinbase block causes an economically consequential discrepancy. No CVSS: no E2 target execution or E4 attacker route. Do not submit externally.

## Verified certified-source facts
Immutable source reference `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` (connector read, not fresh bootstrap): `vendor/electroneum-sc/consensus/istanbul/backend/engine.go:184-192`, `Backend.Finalize` only credits reward if `header.Coinbase != common.Address{}`. Same file lines 466-490, `Backend.emissionApply`, increments `CirculatingSupply` by `GetBaseBlockReward` for every header without a coinbase predicate. Lines 258-298 calculate reward and cap. These are distinct ledgers; their difference alone is NOT proof of spendable unauthorized credit.

Required source identity (historical certification, not freshly asserted): commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0; tree de7f3c75a2db7e87a89918f1257820703d5b731e; pinned 3aeb14db0d6384243302f3a025bdff904dc28bf6; archive 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b.

## Newly executed independent oracle (NOT target runtime)
Python 3 synthetic arithmetic exit 0. For assumed reward 4e18 wei and zero coinbase: actual-credit model 0, emission model +4e18, difference +4e18 wei; for nonzero coinbase: both +4e18, difference 0. This is a **conditional source-path model**, not an observed chain discrepancy. A valid chain configuration may use a different reward due to halving/cap.

## Security counterexample and reachability gap
Strongest counterexample: consensus header validation may forbid zero coinbase, or zero coinbase may be a deliberate reward-burn policy, in which case accounting of emission can legitimately include burnt rewards. Even if allowed, a non-validator transaction sender may have no control over coinbase. No evidence of attacker-owned spendable funds, excess issuance, consensus split, or actual lost funds. This may be informational only. Must not label P3/P4 until consequence and attacker route are proven.

## One discriminating test
Inspect active IBFT header verification for zero-coinbase acceptance and production proposer control. If allowed, certified synthetic **canonical block import** comparing (a) zero coinbase and (b) valid nonzero coinbase, at heights 1/2 and a halving/cap boundary; inspect state root, actual recipient balance, emission checkpoint and total supply using a separate ledger. Run Go `-count=1 -v` with real stdout, controls and exit status. If zero coinbase is invalid or only privileged/unexploitable burn, mark DISPROVEN/P5-only and rotate. No CI was started this invocation.
