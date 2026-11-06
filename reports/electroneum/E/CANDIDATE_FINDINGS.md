# Worker E — Evidence-graded candidate register

## HYP-E-004 — Receipt effectiveGasPrice width mismatch
- Status: ACTIVE; grade **V1** (certified immutable source read, NOT target-runtime executed for this case); attacker label **R0** conditional on valid transaction inclusion.
- Entry: `internal/ethapi/api.go:1604-1615`, `PublicTransactionPoolAPI.GetTransactionReceipt`; `effectiveGasPrice` serialized as `hexutil.Uint64(gasPrice.Uint64())`.
- Sibling: `internal/ethapi/api.go:1244-1303`, `newRPCTransaction`, serializes gas price as `*hexutil.Big`.
- Production config: `params/config.go:46-62` mainnet chain ID 52014, LondonBlock=0.
- Admission guard: `core/tx_pool.go:669-693` fee cap bit length >256 rejected; this is only one guard, NOT proof of admission or block validity.
- Q6 expected: a receipt's fee field must round-trip full-width price and agree with transaction RPC. At price 2^64+1, `Uint64()` mathematically returns 1; fee discrepancy 2^64 wei/gas. This is a source-derived numerical counterexample, not observed target-runtime output.
- Competing explanations: (1) real admitted and funded transaction triggers truncation; (2) production validity/balance constraints prohibit the boundary; (3) representation mismatch occurs but no consequential third-party financial decision uses receipt gas price.
- Falsification: certified scratch in-process receipt API and transaction API tests at 2^64-1, 2^64, 2^64+1, valid mainnet config; independent big-int oracle; scratch mutant that preserves full width must make strict regression pass; test transaction admission and actual execution under realistic balance and block gas limits. Prove relying-party wrong economic decision or classify as cosmetic.
- Strongest counterexample: ordinary exchanges credit transferred value, not gas fee, and verify receipt status and canonicality; fee reporting mismatch alone cannot credit an orphaned deposit.
- Result: **SIMULATION_NOT_EXECUTED** in this invocation; V4 not established. No Bugcrowd confirmed report.

## HYP-E-003 — Receipt canonicality TOCTOU across reorg
- Status: ACTIVE; grade V1 source path plus prior V2 synthetic characterization, **not V4**; attacker label R0 only for ordinary chain reorg.
- Source: `internal/ethapi/api.go:1571-1626` transaction lookup then separate receipt lookup; `core/rawdb/accessors_indexes.go` canonical lookup rejects orphan when lookup starts after reorg.
- Competing explanations: (1) genuine reorg interleaves between calls and creates stale response; (2) actual backend locks or reorg sequencing prevent inconsistent read; (3) temporary answer is revalidated by exchange before credit, so no wrong financial decision.
- Falsification: imported competing consensus-valid blocks, actual canonical head transitions, receipt queries at N-1/N/N+1, independent ledger+deposit oracle, HTTP and adapter restart. Reproduce three times and show an incorrect credit despite canonicality checks.
- Strongest counterexample: post-reorg canonical lookup returns null for orphaned transaction in certified rawdb fixture.
- Result: earlier mock/rawdb interleaving is characterization, not an attacker-reachable financial exploit.

## Certified CI supervision
- Trigger SHA `cd579153353f0e5560bfc5439fa30a71a482e581`; run `41923789539`, job `126902759599`, completed success; full log checked 2026-11-05. `FuzzWorkerEReorgLookup` 43,753,576 executions / 3600.10 seconds, PASS within rawdb fixture scope. CI historical evidence is not new execution for this candidate.
- Source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; source provenance archive SHA-256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.


### 2026-11-05 08:00 NPT — HYP-E-004 new executable falsification
- Grade remains **V1**; **SIMULATION_PREPARED_NOT_EXECUTED** at commit time. Added four real ethapi adapter fee-width cases at 2^64-1, 2^64, 2^64+1, 2^65+17, with full-width independent big-int oracle and cross-method newRPCTransaction comparison, in `test_rpc_receipt_cases_test.go` (commit cf23abe9). The test detects current truncation as characterization; a PASS does **not** demonstrate a financially reachable exploit.
- Workflow test selector now includes FeeWidthBoundary (commit 19b45652), and default push fuzz budget is one minute to prioritize new distinct semantic cases; manual sustained fuzz remains available. Both triggering commit statuses were empty on immediate inspection; **run ID unknown/pending**, no claimed target-runtime execution.
- Strongest remaining counterexample: a realistic funded transaction cannot satisfy effective fee/consensus validation at these prices, or no relying-party fee-reimbursement decision relies on this field. Next: inspect fresh CI logs and actual named four test cases, then model real transaction admission/consensus and monetary consequence.


## HYP-E-005 — Receipt header disappearance produces RPC panic (new 2026-11-05 12:00 NPT)
- **Grade V2 for synthetic adapter behavior; V1 for production backend wiring; R0 conditional on naturally occurring reorg/pruning race; status SUSPECTED, NOT CONFIRMED.** Certified `internal/ethapi/api.go:1608-1615` dereferences `header.BaseFee` after `HeaderByHash`; `eth/api_backend.go:99-101` returns `(blockchain.GetHeaderByHash(hash), nil)` even when the header is absent. An earlier transaction lookup and receipt lookup do not guarantee that the header still exists by the later read.
- **Actual prior certified-runtime observation:** CI 41953894517, job 127025405296, `TestWorkerEReceiptIdentityAndNilHeader/nil_header_no_backend_error` logged `E_RPC_NIL_HEADER_PANIC_FROM_SYNTHETIC_BACKEND` on 2026-11-05T03:16:31Z. The test intentionally supplies nil header and recovers the panic. This is characterization of a synthetic inconsistent backend, not an observed real-node crash or attacker-reachable race.
- **Competing explanations:** (1) reorg/pruning/restart can remove header between successful transaction and receipt reads, causing an actual RPC panic; (2) block/header lifetime and chain locking prevent this interleaving; (3) header may be absent only under corrupted storage, making it R3 hardening.
- **Q8/Q7 potential effect:** failed RPC request/availability, not deposit miscredit; no financial loss shown. **Cheapest discriminator:** in certified scratch, import competing valid blocks, pause `HeaderByHash` after `GetTransaction`/`GetReceipts`, cause actual canonical transition, observe whether `GetHeaderByHash` can return nil without storage tampering; run controls for stable chain, missing tx, and reorg without header removal. Repeat three times if a real panic occurs. Add a strict test that fails on panic (existing characterization currently PASSes when panic occurs) and a nil-header defensive mutant. No new execution this invocation.


## HYP-E-006 — Receipt sender-recovery error discarded (2026-11-06 04:55 NPT)
- **R0 conditional; SUSPECTED, E1/V1 only; not reportable.** Receipt adapter `internal/ethapi/api.go:1585-1594` ignores `types.Sender` error. Canonical import counterexample: `core/state_processor.go:172-175` calls `tx.AsMessage(MakeSigner(...))` and returns an error on invalid signature; `core/tx_pool.go:703-706` independently rejects invalid senders. Source reads at immutable commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; no executed runtime test.
- **Competing explanations:** canonical signature validation makes failure unreachable; fork/priority signer differences permit a canonical but unrecoverable sender; only a corrupt/mocked backend triggers it. **Strongest counterexample:** real block import's AsMessage error path, not merely txpool screening. **Decision:** not DISPROVEN (requires V3 executed controls), not CONFIRMED (no attacker-reachable wrong external decision). **Next falsification:** valid canonical priority/fork-boundary import, independently derive sender, compare transaction and receipt APIs, malformed signature negative control, scratch mutation sensitivity, three fresh-state reproductions if any breach. `SIMULATION_NOT_EXECUTED`; local Git DNS exit 128. See E/LATEST.md 2026-11-06 04:55 NPT.


### 2026-11-06 05:55 NPT — HYP-E-006 decision update
- **DEFERRED / SUSPECTED (E1/V1, not reportable)** after two consecutive source-only investigations; no new certified runtime execution. Shipped mainnet `params/config.go:46-70` sets `FutureForkBlock=math.MaxInt64`; receipt `internal/ethapi/api.go:1586-1588` and block processing `core/state_processor.go:172-175` use `MakeSigner` with the same chain config and block height. The strongest defense is block-processing rejection of `AsMessage` errors, not merely txpool rejection. A near-term FutureFork boundary is not production-reachable under shipped mainnet config. This **does not** prove all priority or persisted-data cases safe.
- **Observed vs expected:** source-path consistency only; zero new executed cases, zero observed wrong senders or external credits. Historical run 41923789539 is not a signer-error proof. Detailed assessment: `EVIDENCE_HYP-E-006_2026-11-06_0555.md`.
- **Reactivation condition:** actual imported consensus-valid transaction with mismatched receipt sender or credible production configuration evidence. **Rotation:** prioritize HYP-E-004 full-width fee receipt, but require real block admission and wrong economic decision before reporting.


### 2026-11-06 06:52 NPT — HYP-E-004 production-reachability constraint assessment
- **Decision SUSPECTED / E1-V1, NOT REPORTABLE.** New internal assessment: `EVIDENCE_HYP-E-004_2026-11-06_0652.md`. Shipped mainnet London=0; `core/tx_pool.go:687-705` and `core/state_transition.go:196-215,239-268` enforce gas/fee-bit-length, signature, sender balance and base-fee checks but do not establish a 64-bit gas-price ceiling. This weakens the blanket “consensus necessarily rejects >2^64” counterargument, without proving block inclusion.
- **Independent conditional arithmetic:** 21000 gas at `2^64+1` wei/gas requires `387381625547900583957000` wei (~387381.625547900584 ETN at 18 decimals); receipt narrowing would show 1 wei/gas. **Not an observed loss or executed target case.** Strongest economic counterexample: a canonical-deposit verifier never uses receipt gas price to credit transfer value.
- **Execution:** Git DNS exit 128; no checkout/bootstrap or fresh target Go test; historical E CI success does not prove fee admission. **Missing E2–E4:** consensus-valid funded block, strict actual RPC cross-method comparison, mutation control, three reproductions and credible wrong fee-dependent third-party decision. Next one bounded certified-runner import test; no new broad campaign.


### 2026-11-06 08:00 NPT — HYP-E-004 bounded execution checkpoint
- **DEFERRED / SUSPECTED E1-V1, not reportable** after two consecutive source-only investigations. Existing receipt fee-width source mismatch remains; a funded canonical >2^64 transaction and wrong relying-party decision remain unproven. No new Go test, no new target runtime execution. Git DNS exit 128; GitHub connector lacks workflow dispatch. Historical run 41923789539 is not a funded block-admission test. Strongest counterexamples: real admission/funding constraints and fee-independent deposit accounting. Internal assessment: `EVIDENCE_HYP-E-004_2026-11-06_0800.md`. Reactivate only with a bounded actual imported-block admission experiment; rotate to HYP-E-003 actual reorg/restart receipt canonicality. No confirmed vulnerability report edit.


### 2026-11-06 08:55 NPT — HYP-E-003 source-path discriminator
- **SUSPECTED E1/V1; SIMULATION_NOT_EXECUTED; not reportable.** Real backend `eth/api_backend.go:265-268` calls canonical `rawdb.ReadTransaction`; receipt API `internal/ethapi/api.go:1571-1626` then calls `GetReceipts` by the previously returned block hash (`eth/api_backend.go:185-187`) without post-receipt canonical revalidation. This creates a source-level *possible* read-gap, not evidence of a real interleaving or miscredit.
- **Strongest defense:** canonical lookup after reorg rejects orphaned tx; exchange may revalidate block hash at decision time. **Unknown:** real backend locking/receipt persistence during reorg, plus external N-confirmation behavior.
- **Evidence:** `EVIDENCE_HYP-E-003_2026-11-06_0855.md`; local Git DNS exit 128; zero current target tests, no fresh bootstrap. Next: bounded real-backend competing-block reorg/receipt/credit oracle; no broad fuzz.
