# A-REWARD-CAP-HALVING-01 — cap-before-halving ordering assessment (2026-11-07 04:10 NPT)

**Decision: SUSPECTED source-level arithmetic difference; NOT REPORTABLE (E1).** Conditional P4 only if protocol intent, reachable canonical state, and meaningful economic harm are demonstrated. No CVSS, no E2–E4, no external report.

## Source and observed behavior
Immutable certified source read via GitHub connector: `vendor/electroneum-sc/consensus/istanbul/backend/engine.go`, blob `31e7729d1b930a56df3380989bd1dae6ba63bf5b`, certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`. `Backend.GetBaseBlockReward` uses 4e18 wei base reward and 25,228,800-block halving period, first clamps base reward to remaining maximum supply, **then** shifts the clamped reward right by the halving count. The different possible policy, shift first then cap, can produce different issuance near maximum supply. Source tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` are historical expected identities, **not freshly bootstrapped or runtime-verified**.

## Independent executed integer oracle (NOT certified target runtime)
Command: `python - <<'PY' ...` using Python integers and `B=4*10**18`, `actual=min(B,remaining)>>halvings`, `alternative=min(B>>halvings,remaining)`. Exit code 0. Boundary outputs (wei):

| Remaining cap | Halvings | Actual source-order model | Alternative shift-first model | Difference |
|---:|---:|---:|---:|---:|
| 4000000000000000001 | 1 | 2000000000000000000 | 2000000000000000000 | 0 |
| 4000000000000000000 | 2 | 1000000000000000000 | 1000000000000000000 | 0 |
| 3999999999999999999 | 1 | 1999999999999999999 | 2000000000000000000 | 1 |
| 2000000000000000000 | 1 | 1000000000000000000 | 2000000000000000000 | 1000000000000000000 |
| 2000000000000000000 | 2 | 500000000000000000 | 1000000000000000000 | 500000000000000000 |
| 1 | 1 | 0 | 1 | 1 |

All are synthetic remaining-supply scenarios, **not observed canonical chain balances**. No credited funds were measured. No attacker beneficiary or unauthorized mint: the modeled difference is reduced reward versus an unproven alternative rule.

## Strongest counterexample / disproof boundary
The **implemented consensus policy itself** may intentionally clamp pre-halving base reward; there is no independent ETN-SC protocol specification proving shift-before-cap is required. The chain may never reach the synthetic remaining-supply states at the specified halving counts; block height and emission are constrained by prior canonical history. An ordinary signed-transaction sender does not select block reward or circulating supply. No external attacker control or security harm established. Even if the alternative were preferred, reduced issuance is not unauthorized spendable credit.

## Execution and missing proof
New work: immutable source inspection and independent arithmetic execution. No fresh certified bootstrap, Go test, block import, CI run, signed transaction, or chain-state read. Contract, manifest, certificate and provenance root paths returned 404; full contract reconciliation unavailable. No duplicate claim established.

## Next single discriminating test
First derive actual production genesis supply, migration offset, max supply and reachable canonical emission trajectories at halving/cap boundaries from certified configuration. If the differing state is reachable and a normative supply rule exists, run a single certified `Finalize` + emission-ledger test; otherwise mark DISPROVEN as a vulnerability, preserving the arithmetic observation.
