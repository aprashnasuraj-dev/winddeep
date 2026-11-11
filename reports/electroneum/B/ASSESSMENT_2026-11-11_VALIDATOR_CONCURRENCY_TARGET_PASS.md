# 2026-11-11: new validator-set concurrency target-runtime evidence (not P2 proven)

**Status:** CONFIRMED target-code concurrency defects; **REMOTE EXPLOITABILITY NOT PROVEN; NOT BOUNTY SUBMISSION READY**.

**Novelty screen:** This is separate from the already-submitted priority sender binding, downloader progress and fee width cases. The earlier Clef signing-consent reference is also excluded. Do not count this code flaw as separate P1/P2 issues until a peer-to-consensus attacker path has been demonstrated.

**Immutable target:** Windeep certified source commit \`7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0\`, subtree \`de7f3c75a2db7e87a89918f1257820703d5b731e\`, originally from upstream \`3aeb14db0d6384243302f3a025bdff904dc28bf6\`. Same vulnerable methods verified in upstream master \`db0eb8792dd57304fbc66a60377c7663e1bd44d2\`.

**New test:** [test source](https://github.com/aprashnasuraj-dev/winddeep/blob/c2fec23ba2c6a61bf3dc277540ec88c81a79b968/reports/electroneum/B/tests/audit_novel_validator_lock_test.go); [workflow](https://github.com/aprashnasuraj-dev/winddeep/blob/c2fec23ba2c6a61bf3dc277540ec88c81a79b968/.github/workflows/etn-novel-validator-lock.yml); run [42998648007](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/42998648007), job \`130448958868\`, **SUCCESS 2026-11-11 09:52:17 UTC**. Go 1.24.0, certified target bootstrap passed. Read full job logs, not just job summary.

**Exact observed markers:**
- \`CONTROL_NO_CONTENTION_CALC_COMPLETED\` — no-writer negative control passes.
- \`DEADLOCK_CONFIRMED\` and \`WRITER_BLOCKED_CONFIRMED\` — deterministic forced pending-writer interleaving with actual target package code; no production daemon or network traffic.
- \`WARNING: DATA RACE\` — concurrent \`CalcProposer\` writes race in \`consensus/istanbul/validator/default.go:118\`.
- \`TARGET_VALIDATOR_DEADLOCK_REPRODUCED\`, \`TARGET_VALIDATOR_DATA_RACE_REPRODUCED\` — workflow marks actual expected outcomes. The deliberate race test itself exits nonzero and the workflow checks this nonzero exit and source stack before succeeding.

**Mechanism:** \`CalcProposer\` takes \`validatorMu.RLock\`, calls selector which uses \`GetByIndex\`; \`GetByIndex\` takes \`RLock\` and calls \`Size\` taking \`RLock\` yet again. When an \`AddValidator\` or \`RemoveValidator\` writer is queued, nested read-acquisition blocks while original outer reader prevents the writer from advancing. Separately, \`CalcProposer\` writes \`proposer\` with read-only lock.

**Strong counterexample:** \`Backend.snapApply\` calls \`snap.copy()\` and mutates this fresh copy, while the active QBFT event loop generally owns proposer transitions serially. The test forces contention using a selector hook; it does not demonstrate that a normal hostile peer can cause the same-object writer to overlap a live \`CalcProposer\`.

**Impact gates:** exact-code reproducibility YES; outsider input NOT PROVEN; N=4/F=1 persistent finality halt NOT PROVEN; fee/reward theft or history rewrite NOT PROVEN; accepted bounty novelty NOT KNOWN.

**Next narrow test:** establish pointer identity/ownership across \`Backend.snapshot\`/\`snapApply\` and \`core.startNewRound\` under a local authenticated N=4 QBFT simulation. First attempt to falsify shared-instance concurrency with snapshot copy and event loop serialization; report P2 only if adversarial remote ingress measurably stalls block publication while 3 honest validators otherwise finalize.

**Fix direction:** remove \`GetByIndex\` -> \`Size\` nested reader; compute proposer from coherent snapshot with proper exclusive publication. Changing \`CalcProposer\` to \`Lock\` without removing selector's internal locking would introduce immediate self-deadlock. Add pending-writer and race regression tests.
