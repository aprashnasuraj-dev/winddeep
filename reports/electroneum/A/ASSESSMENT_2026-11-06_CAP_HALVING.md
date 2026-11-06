# Internal Class A assessment — A-EMISSION-CAP-10 — 2026-11-06 09:10 NPT

**Decision: SUSPECTED, E1 source fact only; SIMULATION_NOT_EXECUTED. NOT externally reportable.**

## Certified identity and provenance
Immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, historical archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Immutable GitHub source read; NO fresh bootstrap or Go target execution.

## Source facts (E1)
`consensus/istanbul/backend/engine.go:258-295` `GetBaseBlockReward` starts with baseReward=4e18 wei, computes halving count using `(header.Number + migrationOffset)/25228800`, then **caps the unhalved reward against remaining supply headroom before right-shifting the result by the halving count**. `engine.go:184-189` `Finalize` credits that result to nonzero Coinbase; `engine.go:466-485` `emissionApply` accumulates the same function with explicit circulating supply. This is a real ordering fact, not a demonstrated bug.

## Discriminating hypothetical numerical case (independent arithmetic, NOT observed runtime)
Assume exactly one halving and 1e18 wei supply headroom. If protocol policy is `min(halved_base_reward, remaining_headroom)`, expected reward is min(2e18,1e18)=1e18 wei. Current operation ordering yields (min(4e18,1e18) >> 1)=0.5e18 wei, a 0.5e18 wei shortfall to Coinbase for this synthetic state. This is a conditional calculation, not an observed balance, not proof that this headroom is reachable on production mainnet, and not proof that the assumed policy is authoritative. No attacker beneficiary or economic exploit established.

## Competing explanations / strongest counterexample
1. The implemented cap-before-halving ordering is intended emission policy, in which case there is no vulnerability.
2. The production issuance trajectory never places supply in this narrow headroom region at a halved height; synthetic values alone are not reachable.
3. A valid production block can reach the region and the protocol specification requires halving before cap; then the proposer would receive less than policy intends, but a security-relevant adversarial route remains to prove.
The strongest counterexample is (1)+(2), requiring independent specification and actual mainnet configuration/supply trajectory. This source observation is NOT a CONFIRMED mint/burn defect.

## Reproduction needed
Use certified bootstrap and a fresh disposable Go fixture with actual `GetBaseBlockReward`, `emissionApply`, `Finalize` and state balances at heights 0/1/2 and production-derived halving/cap boundaries. Honest control: far below cap; boundary variants: headroom 1e18 and 3e18 at halving=1, plus near cap. Independent oracle must be justified by official issuance policy, not inferred from target. Prove whether legitimate canonical history reaches the condition; otherwise defer. Record named `go test -count=1 -v` cases, exit codes, three fresh-state repetitions if a breach, and mutation sensitivity. No such tests executed in this invocation.

**Adversary:** L1 proposer at most, subject to valid consensus; no demonstrated ability to choose circulating supply or arbitrary height. **Observed loss/gain:** none. **Hypothetical shortfall:** 5e17 wei for the chosen nonproduction illustration. **Reportability:** E1 only, E2/E3/E4 absent.

## 10:09 NPT — new bounded mathematical falsification (E1 derivation, not target execution)
For a fixed halving count k>=1 and headroom H satisfying 0<H<4e18, the source returns floor(H/2^k) rather than min(floor(4e18/2^k),H). Hence the post-reward headroom is H-floor(H/2^k), which is strictly positive for all H>0; for H<2^k the reward is zero and headroom remains unchanged. This establishes a *source-level* possibility of permanently unissued residual headroom at a halved cap boundary, not an attacker-triggered balance loss. For k=1, H=1e18, expected under an alternative halving-first policy 1e18, source arithmetic 5e17, residual 5e17 wei. For H=1 wei, source arithmetic returns zero. No live production state or authoritative protocol rule has been established; this is not E2/E3/E4. The strongest defense is that the cap-before-halving rule is intentional, or no canonical production trajectory reaches the relevant H. The next discriminator is to establish the specified cap policy and whether a valid canonical emission trajectory can enter 0<H<4e18 after a halving. No Go test or bootstrap was run during this update.
