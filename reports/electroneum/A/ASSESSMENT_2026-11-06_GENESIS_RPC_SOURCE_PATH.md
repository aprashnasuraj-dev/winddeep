# A-REWARD-GENESIS-RPC-01 — source-path falsification assessment (2026-11-06 23:11 NPT)

**Decision: BLOCKED at E1; no confirmed P1–P4 finding.** Hypothesized P4 only if externally exposed RPC causes consequential availability loss; CVSS unassigned. This is an internal assessment, not a vulnerability report.

## Freshly inspected immutable target source
Read `vendor/electroneum-sc/consensus/istanbul/backend/api.go` (blob `cc7bd30ca09305cfdc6b624d251c7a3e36c5b02a`) and `vendor/electroneum-sc/consensus/istanbul/backend/engine.go` (blob `31e7729d1b930a56df3380989bd1dae6ba63bf5b`) at certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`. Required tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned source `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. These are declared identity values, **not revalidated by a fresh bootstrap**.

## New discriminating source evidence
`API.GetBaseBlockReward` passes the canonical genesis header and nil circulatingSupply to `Backend.GetBaseBlockReward`. The backend evaluates `header.Number.Uint64()-1` and calls `emission(chain, wrappedHeight, header.ParentHash, nil)`; it panics on returned error. Crucially, `emission` only uses the genesis initialization branch when **number == 0**, not when the supplied hash is genesis or zero. With genesis height zero, the wrapped height is `18446744073709551615`, bypassing genesis initialization. The function first probes the emission cache keyed by parent hash; then checkpoint storage only when `number % checkpointInterval == 0`; otherwise it requests `chain.GetHeader(hash, number)` and returns `consensus.ErrUnknownAncestor` when absent. This makes the missing-parent error plausible on ordinary valid genesis, without malicious blockchain corruption, unless an unexpected cache/checkpoint entry resolves it.

**Observed:** source control flow and historical independent integer oracle only. **Not observed:** an actual Go RPC invocation, recovered/unrecovered panic, process exit, liveness degradation, default public-network RPC exposure, or adverse effect. No new certified runtime test executed in this invocation; no Go test exit code exists. GitHub connector file reads succeeded.

## Controls, counterexample and threat boundary
Honest controls: canonical height 1/2 (valid parent), genesis height 0 with valid chain config; malicious input is an ordinary RPC query selecting block zero, **not** a malicious canonical block. Strongest counterexample is RPC panic recovery plus default RPC module allowlisting: a recovered per-request panic may yield only an error response, which is not automatically a P4 vulnerability. Another counterexample is a cached emission for genesis parent hash. `Public: true` in `Backend.APIs` does not prove externally exposed `istanbul` module. Consensus issuance via `emissionApply` passes nonnil circulatingSupply and does not use the nil lookup path.

## Next exact test
Execute an isolated in-process certified-source RPC fixture against valid genesis with `istanbul_getBaseBlockReward(0)` and heights 1/2, capture panic/error and liveness, then inspect default module exposure. If panic is recovered without consequential service loss, mark this lead DISPROVEN as a security finding in that scope. Do not submit external report or infer network-wide DoS from the source panic.
