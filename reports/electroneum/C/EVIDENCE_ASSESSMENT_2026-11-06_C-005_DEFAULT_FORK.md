# C-005 — Default-configuration reachability check (2026-11-06 13:29 NPT)

**Decision: DEFERRED for P2+ Class C; no confirmed finding. Evidence E1 (immutable source inspection), not E2/E3/E4.**

## Question and actor
Can Y0 submit a priority transaction that crosses a future-fork transition and exploit stale `TxPool.futureFork` during reorg reinjection to spend another user's funds or bypass signing authorization under shipped mainnet settings?

## Newly checked certified source and observed result
Read GitHub Git objects at immutable commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` (certificate subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`). This is **not** a fresh bootstrap or executed target test.

- `params/config.go:46-63`: shipped `MainnetChainConfig.FutureForkBlock = math.MaxInt64` (9,223,372,036,854,775,807). `StagenetChainConfig` and other visible built-in config also use MaxInt64. `ChainConfig.IsFutureFork` at :406-408 compares the requested block to this threshold. No ordinary current-height transition is therefore available in these shipped defaults. A custom genesis/config may override it; actual deployed chain state was not queried.
- `core/tx_pool.go:1450-1477`: `reset` calls `addTxsLocked(reinject, false)` before updating `pool.futureFork = IsFutureFork(next)`. The source-order concern is real but requires a transition between the old and new fork modes and reorg reinjection.
- `core/tx_pool.go:703-717`: `validateTx` recovers ordinary sender, then priority signer with `pool.prioritySigner()`, then verifies the priority key exists in `currentPriorityTransactors`. Thus a stale priority signer is **not** an ordinary sender signature bypass; a valid sender signature remains required.
- `core/types/transaction_signing.go:48-57,392-426`: block-number-based signer selection and post-fork sender-bound priority signature hashing. No accepted transaction, victim balance mutation, or leaked key was observed.

## Expected versus observed; strongest counterexample
Expected: default production configuration cannot cross the future-fork signature transition before block MaxInt64; an attacker cannot spend a victim's assets without the victim's ordinary sender signature. Observed: source configuration and signature checks support this counterexample; no runtime acceptance/rejection or state balance was measured. Therefore **no demonstrated P1/P2 Class C route** in default settings. A chain with an explicitly changed FutureForkBlock is outside this default-config conclusion, and even there block execution might reject a pool-only mismatch.

## Execution and limitations
Actual this run: immutable GitHub connector `fetch_file` for `params/config.go`, `core/tx_pool.go`, `core/types/transaction_signing.go` succeeded; local `git rev-parse --is-inside-work-tree` exited **128** (`fatal: not a git repository`). `source tools/electroneum_target_bootstrap.sh` **not executed**; Go target tests **0**, oracle **0**, mutation sensitivity **0**, no CI dispatched. Current CI inventory not established. This is a source-level falsification of the **default fork-transition prerequisite**, not a V3 runtime DISPROVEN claim. The external confirmed-only report remains untouched.

## Next discriminating action
Check whether any shipped or actually deployed mainnet genesis/config overrides `FutureForkBlock`; if not, close this fork-transition lead for Class C and prioritize a default-reachable signing/nonce or keystore permission boundary. If an override is found, execute a short synthetic certified-runtime reorg reinjection versus fresh-admission and block-import comparison with honest and adversarial signatures.
