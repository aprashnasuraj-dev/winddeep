# A-FEE-01 — signed EIP-1559 fee64 processing assessment (2026-11-06 17:xx NPT)

**Decision: BLOCKED pending certified runtime execution; NOT reportable.** Hypothesized economic P1 only IF an external sender obtains unauthorized spendable wei; no severity assigned and no CVSS because no violation observed.

## Fresh work
Read the shipped `core/state_processor.go:ApplyTransaction -> applyTransaction -> ApplyMessage`, `core/evm.go:NewEVMBlockContext`, and `core/types/transaction_signing.go:SignNewTx / Sender`. Added class-owned `tests/signed_fee64_processing_test.go` (commit `8e97be222d5a763cd79c4b7a285578c61d825f1c`) and certified-scratch workflow step (commit `e0ffcfa7c8a898759212c1f8e924103c51ac2c47`). Test uses a deterministic synthetic ECDSA key, signed EIP-1559 transaction, wire encode/decode, recovered sender, real `ApplyTransaction`, real receipts, fresh StateDB, three fee caps q−1/q/q+1 where q=floor(2^64/21000), and success/revert/insufficient-funds cases (nine cases). Independent oracle: sender debit gasUsed×10, validator credit gasUsed×2, basefee burn gasUsed×8; insufficient funds must reject without state mutation. No public-node transaction.

**Precise scope:** Signed transaction application and receipt construction, **not canonical block import or consensus Finalize**. This is an extension of historical six-case direct `ApplyMessage` evidence, which disproved only simple 64-bit escrow wrap. The strongest counterexample is the preflight big.Int affordability check and previously observed correct 210000/42000/168000 wei reconciliation. Any compiler/test harness error is not a vulnerability.

## Runtime identity and execution status
Required source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, source tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned source `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Workflow asserts all four via `source tools/electroneum_target_bootstrap.sh` before copying the immutable source to scratch.

**No newly executed Go target output inspected at assessment creation.** Workflow step command is `go test -count=1 -timeout=10m -run '^TestWorkerASignedFee64Processing$' -v ./core`; exit code **pending**, not PASS. A run triggered by test-file commit `8e97be2` was in progress (run 42209491174); the subsequent workflow commit may queue another run. No job cancelled, restarted or counted as successful. Historic run 42186908937 was successful for six direct `ApplyMessage` cases only. No external E4 finding or unauthorized credit.

## Remaining proof and next discriminating test
Inspect the new workflow's original-trigger SHA, certified bootstrap identity, signed test stdout and exit code. If it fails due to test harness, repair only class-owned fixture and run once; if it passes, record DISPROVEN in signed-processing scope and move to a genuinely different reachable mechanism rather than repeat 2^64 arithmetic. If a real breach appears, repeat 3 fresh states and establish canonical block acceptance and actual spendable impact before external reporting.
