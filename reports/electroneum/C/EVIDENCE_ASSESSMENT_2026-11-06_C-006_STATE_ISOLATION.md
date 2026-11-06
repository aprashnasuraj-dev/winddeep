# C-006 — 2026-11-06 19:33 NPT — RPC simulation state isolation, source-path falsification

**Decision:** DISPROVEN for the narrow claim that the reviewed ordinary `eth_call` simulation commits its fake-message nonce-bypass changes into canonical chain state. **Overall reportability:** NO CONFIRMED FINDING; E1 only. This is not a runtime proof of full state isolation.

## Newly inspected certified source and observations

Immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` was fetched by GitHub connector (not bootstrapped locally). Four source files were independently read this invocation:
- `internal/ethapi/api.go:902-946`: `DoCall` gets state through `StateAndHeaderByNumberOrHash`, applies optional state overrides, builds `args.ToMessage`, and calls `core.ApplyMessage` on the resulting EVM; no state commit is present in this inspected block.
- `eth/api_backend.go:145-164,166-185`: for a numbered historical/latest block or block hash, backend resolves header and calls `BlockChain().StateAt(header.Root)`. Pending block uses `miner.Pending()` instead and requires separate proof.
- `internal/ethapi/transaction_args.go:181,249-252`: RPC simulation uses `types.NewMessage(..., true, ...)`; the fake flag is deliberately set.
- `core/state_transition.go:218-235`: fake messages skip the nonce equality/overflow and sender-EOA checks, while non-fake messages check both nonce directions and overflow.
- `core/state/statedb.go:653-674`: `StateDB.Copy` constructs a separate trie/state object and journal, but the reviewed `DoCall` does not itself invoke `Copy`; do not substitute this function's existence for proof that every backend state path is isolated.

## Controls, counterexample, limitations

Positive source control: canonical signed `Transaction.AsMessage` sets `isFake:false` (`core/types/transaction.go:637-651`), and `state_processor.go:78` uses it. Negative source control: `TransactionArgs.ToMessage` sets `isFake:true` for simulation. Boundary variations: state nonce N vs transaction N-1 and N+1 are rejected in `preCheck` for non-fake messages, while fake simulation skips those checks. These are source-derived expectations, NOT observed Go-test results.

**Strongest counterexample:** `eth_call` on `pending` uses `miner.Pending()`; the returned state's ownership/copy semantics and `GetEVM` side effects are not proven by the above trace. Likewise, an unusual custom backend could return a shared mutable StateDB. This assessment does not claim these routes safe.

**Attacker route and impact:** `eth_call` accepts externally supplied transaction arguments where enabled, but the reviewed implementation does not show those arguments producing canonical transactions, persistent unauthorized balances, or signatures. No P2+ adverse effect demonstrated.

**Execution provenance:** GitHub connector source reads succeeded; zero fresh certified-runtime Go tests, zero independent ledger-oracle tests, zero breach reproductions, zero new CI dispatches. No shell exit code to report. Expected certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. These expected values were not independently reverified this run.

**Next discriminating test:** On certified isolated runner, execute `eth_call` using synthetic account balances against latest and pending state, then independently re-fetch state before/after; compare with signed `ApplyTransaction` at N-1/N/N+1. Do not promote unless persistent adverse state effect and attacker reachability are demonstrated.
