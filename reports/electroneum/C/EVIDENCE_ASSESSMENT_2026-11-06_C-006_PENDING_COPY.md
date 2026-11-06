# C-006 — pending eth_call state ownership falsification (2026-11-06)

## Scope and source provenance
Read immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` using GitHub repository connector. Expected certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e` and upstream pinned commit `3aeb14db0d6384243302f3a025bdff904dc28bf6` are bootstrap-script declarations, **not** newly materialized/hashed runtime objects. No Go test was run in this invocation.

## Newly inspected source path
- `miner/miner.go:195-196`: `Miner.Pending()` delegates to `miner.worker.pending()`.
- `miner/worker.go:355-363`: `worker.pending()` takes `snapshotMu.RLock`, returns nil when snapshot absent, and otherwise returns `w.snapshotBlock, w.snapshotState.Copy()` — **not the shared snapshotState pointer**.
- `core/state/statedb.go:653-674`: `StateDB.Copy()` constructs a distinct StateDB/trie and journal (previously inspected evidence; not re-executed).
- `eth/api_backend.go:145-164`: pending state path obtains `b.eth.miner.Pending()`; latest/historical paths use `BlockChain().StateAt(header.Root)`.
- `eth/api_backend.go:211-219`: `GetEVM` passes the supplied StateDB to `vm.NewEVM`; it does not itself commit state.

## Verdict and counterexample
**DISPROVEN (E1 source scope):** The prior C-006 counterexample that ordinary pending `eth_call` directly mutates the miner's shared snapshot through a returned alias is contradicted by the explicit `snapshotState.Copy()` boundary. A fake simulation message may mutate its *copy*; that does not by itself establish canonical persistence, signing bypass, or theft. **No confirmed P2+ issue.**

**Strongest remaining counterexample:** `StateDB.Copy()` might share lower-level mutable storage in a way that leaks writes, or an alternate backend/custom caller might persist a simulation state. Neither has been shown; only a synthetic certified-runtime before/after state test can close those broader hypotheses. Pending returns the same snapshot block pointer; this inspection does not prove all block-header consumers are mutation-safe.

## Execution accounting
Fresh immutable source reads: miner/miner.go, miner/worker.go, eth/api_backend.go. Go tests **0**; new Actions runs **0**; independent state oracles **0**; attacker-reachable exploit reproductions **0**. No shell command or exit code. No new vulnerability report. Existing certified runtime signing evidence remains historical and is not recounted as fresh.

## Next discriminating test
Certified isolated runner: construct synthetic pending snapshot, call RPC simulation with a state-changing message, assert snapshot balance/nonce/storage unchanged; independently verify latest state and canonical signed nonce N-1/N/N+1. Only elevate if persistent adverse effects are reproducible and reachable through default-enabled ingress.
