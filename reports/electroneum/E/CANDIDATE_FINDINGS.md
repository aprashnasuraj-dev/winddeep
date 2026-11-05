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
