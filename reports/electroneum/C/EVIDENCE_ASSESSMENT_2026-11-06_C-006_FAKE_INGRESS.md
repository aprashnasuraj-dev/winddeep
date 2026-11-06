# C-006 — IsFake ingress reachability assessment (2026-11-06 17:27 NPT)

**Decision: DISPROVEN for the hypothesis that ordinary remotely submitted signed transactions acquire IsFake=true through the reviewed block execution paths.** Overall: NO CONFIRMED REPORTABLE FINDING; source-level E1 only. Not a universal proof about custom Message callers.

## New immutable source evidence

Certified source commit: `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; expected tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; pinned source `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Immutable connector reads succeeded, but the bootstrap and hash re-verification were **not executed**.

- `core/types/transaction.go:637-665`: `Transaction.AsMessage` explicitly sets `isFake: false`, recovers priority signer if applicable, and derives sender through `Sender(s, tx)`; failure returns error.
- `core/state_processor.go:78` and `:173`: block processing and `ApplyTransaction` both use `tx.AsMessage(...)`, rather than user-provided `NewMessage(..., true, ...)`.
- `core/state_transition.go:218-235`: `preCheck` enforces exact nonce equality, nonce overflow, and EOA checks for `!IsFake()`.
- `internal/ethapi/transaction_args.go:181-251`: `TransactionArgs.ToMessage` constructs `NewMessage(..., true, ...)` for simulation.
- `internal/ethapi/api.go:902-946`: `DoCall` obtains a state via `StateAndHeaderByNumberOrHash`, applies optional state overrides, converts args through `ToMessage`, creates EVM with `NoBaseFee:true`, and invokes `ApplyMessage` as a call/simulation. This is the strongest counterexample: a remote caller can influence a fake message in simulation, but the reviewed call path does not submit it as a canonical signed transaction.

## Deterministic source-level falsification matrix (NOT runtime observations)

| Route | IsFake | Sender signature | Canonical block execution? | Consequence |
|---|---|---|---|---|
| Signed transaction in block via `StateProcessor.Process` | false | recovered/checked by `AsMessage` | yes | nonce precheck applies |
| Signed transaction via `ApplyTransaction` | false | recovered/checked by `AsMessage` | yes | nonce precheck applies |
| RPC simulation via `DoCall` / `ToMessage` | true | caller-specified simulation sender | no, in inspected call path | nonce precheck intentionally bypassed in simulation |
| Direct custom application caller of `NewMessage(...,true,...)` | true | caller-controlled | unknown | outside demonstrated production ingress |

**Expected:** untrusted RPC simulation must not become a canonical balance-changing transaction without signature and nonce validation. **Observed source:** signed block paths construct nonfake messages independently. **Strongest surviving counterexample:** an unreviewed custom caller might persist simulation state or pass fake messages into canonical execution; none was demonstrated. State isolation was inferred from the call path and must be verified in runtime before any broader claim.

## Execution and reportability

Actual target Go tests: **none**; no bootstrap, independent oracle, 3-run breach reproduction, mutation, new CI or network transaction. Connector file reads succeeded; no shell exit codes are applicable. Historical signing CI run 41629623384 is not new evidence. E2/E3/E4 unmet. No demonstrated unauthorized funds/signature/nonce effect; no P2+ impact. External vulnerability report must remain unchanged.

**Next narrowly scoped test:** certified isolated runtime: invoke `DoCall` with synthetic state and arbitrary sender/nonce, assert canonical StateDB and receipts unchanged, then invoke real `ApplyTransaction` with invalid signature and nonce±1, assert rejection. Use independent balance/nonce oracle.
