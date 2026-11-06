# Class A internal assessment — A-REWARD-PARENT-CANONICAL-01 — 2026-11-07 01:03 NPT

**Decision: DISPROVEN within the valid 1/2 canonical-parent lookup model; NOT a confirmed ETN-SC vulnerability.** Conditional P1/P2 would require ordinary external input to make every honest validator fail despite valid ancestors; no such route shown. No CVSS score because no target-runtime breach.

## Source and provenance
Immutable certified source read: `vendor/electroneum-sc/consensus/istanbul/backend/engine.go` at commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, `Backend.GetBaseBlockReward`, `Backend.emission`, `Backend.emissionApply`, `Backend.Finalize`, and `Backend.verifyHeader`. Required tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` are historical identity declarations, **not revalidated by a fresh bootstrap**.

## New executed falsification (independent Python chain-model oracle; NOT certified Go)
Executed locally with Python 3, exit 0, using immutable synthetic headers g -> h1 -> h2 and an exact hash+height parent lookup. Results:

```
height=0 parent_uint64=18446744073709551615 result=UNKNOWN_ANCESTOR visited=[]
height=1 parent_uint64=0 result=GENESIS visited=[]
height=2 parent_uint64=1 result=GENESIS visited=[1]
negative_control=UNKNOWN_ANCESTOR; assertions=PASS
```

The model directly tests the source's uint64 subtraction and emission parent traversal with valid and invalid parent-hash controls. It does **not** instantiate the certified Backend or execute `go test`. No certified-runtime test was executed; no Go exit code exists for this invocation.

## Reachability and counterexample
For a non-genesis canonical header N>=1 with a present, hash-matching parent chain, `emission` can walk backward to genesis or use a cached checkpoint. The missing-parent `ErrUnknownAncestor` branch requires an absent/mismatched ancestor in this bounded model, and `verifyHeader` itself calls `emission` before accepting the header. An external ordinary actor cannot choose a missing canonical ancestor merely by signing a transaction. A deliberately invalid parent hash reproduces the error, but is rejected before normal canonical processing; it is the strongest negative control, not a vulnerability.

**Caveat:** transient storage/database failures, cache inconsistencies, concurrent reorg behavior, non-genesis checkpoint faults and actual `Finalize` invocation are not proven safe by this model. Genesis RPC underflow is a separate previously deferred lead with RPC panic recovery and default namespace exclusion. No measured unauthorized wei, beneficiary, node crash or network halt.

## Next discriminator
Only if independent evidence of a valid canonical parent lookup failing appears: execute a fresh certified `Backend.verifyHeader` and `Finalize` fixture with actual headers 1/2 and injected missing-parent negative control, then compare runtime to this oracle. Otherwise rotate to a genuinely different production-reachable supply/reward candidate; do not reopen the genesis RPC loop.
