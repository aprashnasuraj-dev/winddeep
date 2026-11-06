# C-005 fork-transition reinjection ordering — 2026-11-06 12:28 NPT

**Decision: SUSPECTED source-level ordering discrepancy (E1), NOT REPORTABLE.** This is a newly traced branch of C-005, not a proven P2+ vulnerability. No certified-runtime execution occurred in this invocation.

## Newly verified source trace
Immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, certificate tree `de7f3c75a2db7e87a89918f1257820703d5b731e` (connector reads; bootstrap not executed):
- `core/tx_pool.go:1383-1477`, `TxPool.reset`: sets `next = newHead.Number + 1` and refreshes priority transactors; **then** calls `senderCacher.recover(pool.signer, reinject)` and `pool.addTxsLocked(reinject, false)`; **afterward** updates `pool.futureFork = pool.chainconfig.IsFutureFork(next)`.
- `core/tx_pool.go:657-665`, `prioritySigner`: selects the future-fork signer based on the mutable `pool.futureFork` flag.
- `core/tx_pool.go:703-717`, `validateTx`: uses `types.PrioritySender(pool.prioritySigner(), tx)` and verifies registry membership.
- `core/types/transaction_signing.go:343-346,352-426`: pre-fork priority hash excludes ordinary sender V/R/S; post-fork hash binds them.
- `core/types/transaction_signing.go:190-228`: cached recovered identities are reused only when signer equivalence matches.

## Concrete discriminating question
On a head change crossing the fork, does `reset` re-inject a priority transaction while the previous fork flag is still in force, thereby accepting it into the pool although execution at `next` would reject it? Reverse transition/reorg must also be tested. The observed code ordering is real; acceptance, persistence, execution, and security impact are NOT observed. No victim or unauthorized spending is established.

**Competing explanations:** (1) reinjected priority transactions are transiently admitted under stale rules; (2) another reset/add/validation path rejects or subsequently evicts them; (3) chain configuration never activates the fork in shipped production, eliminating actual exposure. The strongest counterexample is that block execution independently enforces fork-aware sender/priority validation, so even a stale pool entry need not execute or move funds. A mere stuck pool entry is not P2 without measured substantial availability impact.

## Exact next test, if certified runner and active-CI inventory permit
Using a disposable certified `core` package fixture, construct valid synthetic pre/post-fork priority transactions with separate sender and priority keys. Exercise head `fork-2 -> fork-1 -> fork` and reverse reorg; compare `reset` reinjection and fresh `AddRemote` admission to block execution. Include honest success, tampered sender signature, tampered priority signature, and two fork-height variations. Oracle computes expected fork from `next` independently; deliberately weaken the flag update order in scratch to confirm detection. Require `go test -count=1 -v`, named executed tests, exit code, and logs; three fresh reproductions if breach. First establish production fork activation and whether any P2+ attacker impact exists. If not, close as low-severity/non-reportable.

## Actual operations and limitations
- GitHub connector `fetch_file` succeeded on immutable source `core/tx_pool.go`, `core/types/transaction_signing.go`, and `core/state_transition.go`; no source bytes modified.
- Local `git rev-parse --is-inside-work-tree`: exit 128, no checkout. `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD`: exit 128, DNS resolution failed.
- Combined-status lookup on earlier C commit `682f948dd32155d73fa7335e44192fa10d3d6e63` returned empty statuses; active CI remains UNKNOWN. No new workflow dispatched; no existing job interrupted.
- Target bootstrap: NOT RUN; Go tests: 0; independent oracle: NOT RUN; mutation control: NOT RUN; E2-E4: NOT MET. The certificate identifiers are historical identity metadata, not current-run verification.
- Phase-0 exhaustive backlog remains unavailable: `BACKLOG.md` absent and upstream geth comparison base unspecified. Do not assert exhaustive coverage.
