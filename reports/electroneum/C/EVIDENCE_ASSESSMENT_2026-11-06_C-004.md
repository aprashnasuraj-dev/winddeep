# Internal evidence assessment — C-004 — 2026-11-06 09:31 NPT

**Decision: SUSPECTED source-level priority authorization design question (E1), NOT REPORTABLE as Class C. SIMULATION_NOT_EXECUTED.** Actor Y1 (account owner with their own valid signing key), potentially Y0 only if an independently valid sender transaction exists; no unauthorized victim transfer or secret access proven.

## Certified identity and provenance
Immutable source read through GitHub connector at source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`. Certificate specifies tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. These are certificate values, NOT independently revalidated bootstrap outputs this invocation. No certified runtime path was materialized.

## Source facts (E1, not executed)
- `core/types/transaction_signing.go:343-346`: pre-fork `londonSigner.PriorityHash` hashes the transaction body, excluding the ordinary sender's signature. `:352-426`: future-fork `PriorityHash` includes sender V/R/S. `:285-298`: `PrioritySender` checks chain ID and cryptographically recovers a priority public key.
- `core/state_transition.go:389-427`: `validatePriorityGasFields` looks up the recovered priority key in the state-cached priority transactor map, checks `IsGasPriceWaiver`, requires both fee fields zero for waiver keys, and rejects zero feeCap for non-waiver keys. This shows the *priority key*, not the sender address, selects fee-waiver eligibility in this function. It does NOT prove that other ingress, contract or policy guards permit unauthorized reuse.
- `params/config.go:63,96,128`: three source chain-config literals set `FutureForkBlock=math.MaxInt64`; whether production overrides this with transitions or a different runtime config is not established. Do not equate source defaults with observed production state.
- `core/types/priority_tx.go:12-29,99-111`: priority transactions have separate ordinary sender V/R/S and priority V/R/S.

## Competing explanations and strongest counterexample
A. A third party who observes a pre-fork priority signature on a given body may independently sign that same body and reuse the priority signature, inheriting the priority key's gas-waiver classification.
B. A priority key is intentionally a transferable/delegated authorization for body-matched transactions, making reuse permissible rather than a vulnerability.
C. Pool/block admission, mapping policy, signature-binding at actual active fork, or account nonce/balance rules reject the attempted reuse.

**Strongest counterexample:** neither the priority signature nor a gas waiver authorizes spending another account's balance. A second sender must produce its own valid ordinary signature, and the same nonce/body may not be executable from that sender. A waiver is a possible network-fee-policy issue (Class A/economics), not established Class C theft. No victim account or amount has been shown.

## Expected vs observed
Expected: only authorized sender spends its balance; priority-key use follows the chain's intended delegation policy. Observed: source-level distinction between body-only and sender-bound priority hash plus priority-key fee-waiver lookup. No transaction was admitted, imported or executed; no balances or receipt were measured; no synthetic key fixture, independent oracle or scratch mutant was executed.

## Execution ledger
GitHub connector `fetch_file` on immutable source: succeeded for `core/types/transaction_signing.go`, `core/types/priority_tx.go`, `core/state_transition.go`, `params/config.go` (source reads only). `get_commit_combined_status` for prior C LATEST commit `5b00794992695baffbf320b97793170a5b7f8ec8`: returned zero statuses, not an active-run inventory. Local bootstrap NOT RUN; Go tests NOT RUN; test count 0; target exit code N/A; independent oracle NOT RUN; mutation sensitivity NOT RUN; fresh CI NOT dispatched. Existing campaigns not touched.

## Missing proof / next discriminating experiment
Before any Class C confirmation, inspect certified `core/types/transaction_signing.go` sender verification and block/pool priority admission, and the priority transactor registry policy. If a victim-controlled privilege boundary is found, execute one certified scratch two-sender, one-priority-key, identical-body fixture with valid and invalid sender signatures, waiver and non-waiver keys, and pre/post fork signers; independently assert balances, gas charged, priority mapping and replay behavior. Otherwise classify fee-waiver portability as intended or hand off the economic policy question to A without asserting theft. Do not repeat C-003 source-only work.

**E1 source facts only; E2/E3/E4 absent. External vulnerability report unchanged.**
