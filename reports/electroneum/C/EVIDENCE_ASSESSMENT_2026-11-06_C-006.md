# C-006 — Nonce authorization at transaction admission and execution (2026-11-06 NPT)

**Decision: DISPROVEN within the narrow source-level hypothesis** that a normally signed, non-fake transaction with nonce unequal to state nonce can execute because the pool permits future nonces. **Not a certified-runtime disproof**; E1 only. No reportable finding.

## New inspection and exact evidence
Read immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e` (tree identity from certificate, not freshly bootstrapped), upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, provenance archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.

* `core/tx_pool.go:702-705`: `types.Sender(pool.signer,tx)` must recover sender or return `ErrInvalidSender`.
* `core/tx_pool.go:750-752`: pool rejects nonce below state nonce; higher nonce may be queued. Pool acceptance is not execution authorization.
* `core/state_transition.go:218-235`: `StateTransition.preCheck` checks non-fake messages against state nonce, returning `ErrNonceTooHigh` or `ErrNonceTooLow`, and guards uint64 nonce overflow and EOA sender.
* `core/types/transaction_signing.go:191-207`: sender-cache reuse requires equal signer; otherwise re-derive sender from signature.

## Boundary/control matrix (source-derived, NOT runtime test output)
State nonce 4 / signed tx nonce 4: pool nonce gate permits; execution nonce gate permits (other checks may reject).
State nonce 4 / signed tx nonce 3: pool returns `ErrNonceTooLow`; execution also returns `ErrNonceTooLow`.
State nonce 4 / signed tx nonce 5: pool nonce gate permits queuing; execution returns `ErrNonceTooHigh`.
State nonce max uint64 / signed tx nonce max uint64: execution returns `ErrNonceMax` via wraparound guard.
Invalid sender signature: pool returns `ErrInvalidSender`; execution-message construction and fake-message privilege must be separately traced.

**Strongest counterexample / scope limitation:** `IsFake()` deliberately skips nonce/EOA checks in `preCheck`, so a caller able to manufacture a fake message could avoid those checks. No production path accepting an untrusted transaction as a fake message has been demonstrated. This is an unresolved reachability question, not an exploit.

## Execution and severity
Actual target Go test commands: **none** this invocation. Bootstrap: **not executed** (no certified checkout available). Historical signing test: `TestWorkerCChainDomainAndAuthorization`, CI run 41629623384, exit 0; this is historical and not a nonce state-transition oracle. Current GitHub Actions listing (100 latest branch runs) showed most recent Class C runs 42096715181 and 42096702516 completed success; not a comprehensive active-run census. No new CI dispatched. No funds moved or secret accessed.

**Attacker route:** signed transaction submitted to pool is plausible; bypass of block execution nonce gate is not established. **Maximum demonstrated severity:** none. E2, E3, E4 unmet.

**Next discriminating test:** use existing class-owned fixture on freshly bootstrapped certified runtime to call real `ApplyMessage` for synthetic signed messages at state nonce 4, with tx nonce 3/4/5 and max-uint64; independently assert state balances and nonce unchanged on rejection. Explicitly trace `IsFake` production construction before considering a bypass claim.
