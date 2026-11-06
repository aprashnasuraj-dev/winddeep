# A-REWARD-GENESIS-RPC-01 — panic isolation and default exposure falsification (2026-11-07 NPT)

**Decision: DISPROVEN for default remote process-crash/consensus-halt mechanism by source-level counterexample; DEFERRED for non-default RPC availability. NO CONFIRMED REPORTABLE FINDING.** Conditional P4 only if measurable consequential impact exists with explicitly enabled RPC; no CVSS assigned. Evidence E1 only for this candidate; no fresh certified-runtime Go execution.

## Fresh immutable source observations
Read these exact files at certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` through GitHub connector:
- `vendor/electroneum-sc/consensus/istanbul/backend/api.go` blob `cc7bd30ca09305cfdc6b624d251c7a3e36c5b02a`: `API.GetBaseBlockReward` accepts genesis height 0 and forwards nil supply.
- `vendor/electroneum-sc/consensus/istanbul/backend/engine.go` blob `31e7729d1b930a56df3380989bd1dae6ba63bf5b`: `Backend.GetBaseBlockReward` computes `header.Number.Uint64()-1`, then panics if `emission` fails. `emission` looks up a missing parent by wrapped number. Normal `emissionApply` supplies nonnil circulating supply and bypasses this lookup.
- `vendor/electroneum-sc/rpc/service.go`: `callback.call` explicitly wraps callback invocation with deferred `recover()`, logs panic, and sets RPC error `method handler crashed`. `rpc/handler.go`: `runMethod` translates callback errors to an RPC error response.
- `vendor/electroneum-sc/node/defaults.go`: `DefaultConfig.HTTPModules` and `WSModules` are both `[net,web3]`, **not** `istanbul`. `node/node.go` forwards those module lists to HTTP/WS server configuration. The `Public:true` API descriptor alone is not proof of default remote exposure.

## Mechanism, controls, and strongest counterexample
The ordinary input is a genesis-height reward RPC query. Height 0 underflows to 2^64−1 and can reach unknown ancestor; heights 1/2 are non-underflow controls but were not executed against the certified runtime this run. Strongest counterexample to P1/P2 is **explicit RPC callback panic recovery** plus **default exclusion of istanbul from HTTP/WS module lists**. This defeats the proposed default remotely triggered process crash at the source-call boundary; it does not establish all deployments' behavior. Consensus reward emission uses nonnil circulating supply, so this genesis RPC path does not demonstrate canonical block validation failure.

**Observed:** four immutable-source files and node wiring inspected this invocation; GitHub fetch succeeded. **Not observed:** actual target RPC request, three repetitions, liveness/latency, configured exposed deployment, process termination, funds impact, or target Go test exit code. No fresh source bootstrap or runtime equivalence claim. Required immutable identity remains commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` (declared, not freshly verified).

## Decision and narrow next action
This is the second consecutive source-only investigation of this lead; stop repeating source-only work. Mark non-default exposure hypothesis DEFERRED. Only reopen on evidence of externally reachable `istanbul` RPC with measurable service degradation despite callback recovery. Next Class A candidate should be rescored from register for an independently production-reachable supply/reward invariant. No external vulnerability report.
