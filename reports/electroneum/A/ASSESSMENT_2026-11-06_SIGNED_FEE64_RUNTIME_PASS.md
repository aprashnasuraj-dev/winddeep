# A-FEE-01 — Signed EIP-1559 fee64: certified runtime log verification (2026-11-06 21:03 NPT)

**Decision: DISPROVEN in the nine signed ApplyTransaction fixture cases; no confirmed reportable finding.** Hypothesized P1 only if externally controlled signed transaction could cause unauthorized spendable credit; observed P-band: none. CVSS: not assigned because no security breach. This is **not** a complete canonical-block-import or all-fork disproof.

## Newly verified execution
GitHub Actions run 42234131519, original trigger SHA a71af72e97e75f308b1f2a479a47221ee89da5fc, job 127947234617, completed SUCCESS. Raw job stdout retrieved and inspected in this investigation, not a newly started execution. Runner Go 1.24.0 linux/amd64. Certified bootstrap printed immutable source path and tree de7f3c75a2db7e87a89918f1257820703d5b731e. Workflow required all four checks: certified source commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0; source tree de7f3c75a2db7e87a89918f1257820703d5b731e; pinned commit 3aeb14db0d6384243302f3a025bdff904dc28bf6; archive SHA256 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b. The bootstrap and signed-test steps both exited 0.

Exact executed command: `go test -count=1 -timeout=10m -run '^TestWorkerASignedFee64Processing$' -v ./core`; exit 0. Fixture: `reports/electroneum/A/tests/signed_fee64_processing_test.go`. It uses a deterministic synthetic ECDSA key, signs, serializes, decodes, recovers sender, calls certified `core.ApplyTransaction` against fresh in-memory StateDB, and independently reconciles sender/coinbase/burn. No public transaction, live chain or real secret.

## Observed vs expected
All nine subtests passed, with explicit raw stdout:
- success offsets -1,0,+1: gas 21000; sender fee 210000 wei; burn 168000; coinbase tip 42000, matching independent big.Int ledger.
- revert offsets -1,0,+1: gas 21006; sender fee 210060 wei; burn 168048; coinbase tip 42012; receipt failed, matching ledger.
- unfunded offsets -1,0,+1: REJECT with unchanged sender and miner balances.
- Both gas-limit-specific boundary families were exercised: success/unfunded 21000 gas and revert 50000 gas. For each, q=floor(2^64/gasLimit), offsets -1/0/+1; only +1 crosses 2^64.
- Supporting direct EVM six-case test and fee burn/revert/waiver oracle also passed in the same job. Raw logs include `WORKER_A_SIGNED_FEE64_PROCESSING_COMPLETE`.

Expected invariant: sender delta = gasUsed × (baseFee+tip), coinbase delta = gasUsed × tip, burned = gasUsed × baseFee; failed EVM execution still charges gas; unaffordable signed tx is rejected without balance mutation. Actual: no deviation in nine tested cases; observed unauthorized credit **0 wei**, beneficiary **none**.

## Attacker route, strongest counterexample and limits
An ordinary sender can form/sign a transaction with extreme EIP-1559 fee cap, but must fund maximum gas escrow. The tested certified implementation uses arbitrary-precision accounting and affordability checks. The strongest counterexample to the original vulnerability claim is the successful above-2^64 signed processing case, with exact post-state conservation and the unfunded negative control. No evidence of attacker-triggered spendable mint, incorrect burn, or chain halt.

The fixture calls `ApplyTransaction` and is not a consensus-validated block import; it uses a synthetic London-at-zero chain config. Canonical production activation, full block validation, fee recipients under reorg, and non-London boundaries remain outside this decision. Thus E2 runtime execution verified, E3 breach absent, E4 absent. A P1–P4 report is not justified.

## Next discriminating action
Mark this overflow mechanism resolved in its tested scope; re-score a genuinely different class-owned lead (parent-emission lookup failure reachable through **valid** canonical blocks), first proving the error state can occur without invalid chain or trusted local corruption. Do not rerun the nine-case fixture or start a broad fuzz campaign without a new discriminating premise.
