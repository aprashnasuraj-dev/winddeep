# Internal evidence assessment — HYP-E-006 — 2026-11-06 04:55 NPT

**Verdict:** SUSPECTED / E1 (V1), NOT REPORTABLE. No current certified target-runtime execution, no independent adversarial oracle result, no E3/E4. This is not an external vulnerability report.

**Source identity:** immutable audit source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; expected certified subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`; pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Identity from manifest, not newly bootstrapped.

**Observed (source inspection only):** `internal/ethapi/api.go:1585-1594` ignores `types.Sender` error when constructing receipt.from. `core/state_processor.go:172-175` derives message with height-specific signer and returns any derivation error during canonical block execution. `core/tx_pool.go:703-706` rejects invalid sender in mempool. `core/types/transaction_signing.go:48-57` chooses signer by fork height.

**Expected invariant:** a canonical included transaction's receipt.from equals the sender recovered independently under the shipped block-height signer; no sender-error transaction can be accepted as canonical. **Actual target runtime:** NOT OBSERVED in this run. No mismatched canonical receipt, no false deposit credit, no error-path test result. No quantified loss.

**Strongest counterexample:** canonical block processing invokes `AsMessage` and rejects a sender-recovery error before a receipt can be committed. The source code therefore weakens the naive malformed-signature exploit; it does not prove all fork/priority variants are safe. Synthetic backend errors alone would be R3 characterization.

**Competing explanations:** (1) canonical block validity precludes sender errors; (2) fork/priority signer mismatch creates a valid transaction whose RPC recovery fails; (3) backend inconsistency/corruption is necessary. **Cheapest discriminating test:** import valid synthetic transactions around the actual FutureFork activation using certified Go core, compare receipt.from and transaction.from to independent sender oracle, add malformed-signature rejected-block control, then scratch mutation sensitivity. Require 3 fresh-state reproductions of any mismatch and external relying-party decision before escalation.

**Execution record:** local `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git refs/heads/electroneum-sc-master-audit` exit 128, `Could not resolve host: github.com`. Bootstrap not run; Go tests not run; zero fresh cases. Historical Actions run 41923789539 / job 126902759599 successful for other test families, not proof of this hypothesis. No CI dispatched. **Next:** certified canonical-import fork-boundary test; if valid cases all recover sender, close only the exercised scope as DISPROVEN after mutation control.
