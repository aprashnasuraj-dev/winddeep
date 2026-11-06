# A-FEE-01 — certified-runtime log reconciliation (2026-11-06, 16:12 NPT)

**Decision:** DISPROVEN only for simple uint64 escrow-wrap in the six `ApplyMessage` synthetic EVM cases; signed canonical block-import path remains UNTESTED. **External reportability:** NO CONFIRMED FINDING; P-band/CVSS unassigned.

## New evidence inspected this invocation

Retrieved and inspected full GitHub Actions job log for run 42186908937, job 127789325044 (completed/success), original trigger SHA `af09bb9a9acb62bac6c6289f8dfd62c304cfb3e8`. Log explicitly prints `go version go1.24.0 linux/amd64`, `go test -count=1 -timeout=10m -run '^TestWorkerAFeeCap64Boundary$' -v ./core`, all six individual PASS/REJECT cases, `PASS`, and `WORKER_A_FEE64_BOUNDARY_COMPLETE`. Shell uses `-e -o pipefail`; completed step success implies command exit 0. This is **historical runtime execution verified by newly retrieved raw stdout**, not a fresh test invocation. Source identity recorded by runner environment: certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. The job bootstrapped an immutable source and used a scratch copy. Current invocation did not run bootstrap or Go tests.

### Observed stdout, exact numbers

| offset | escrow (wei) | funded | insufficient funds | actual fee | burn | tip |
|---:|---:|---|---|---:|---:|---:|
| -1 | 18446744073709518000 | PASS | REJECT | 210000 | 168000 | 42000 |
| 0 | 18446744073709539000 | PASS | REJECT | 210000 | 168000 | 42000 |
| +1 | 18446744073709560000 | PASS | REJECT | 210000 | 168000 | 42000 |

Independent local Python integer calculation executed in this invocation (exit 0): `q,r=divmod(2**64,21000)`; `q=878416384462359`; `r=12616`; `q+1=878416384462360` is first cap exceeding 2^64 when multiplied by 21000. At offset -1/0/+1, escrow minus 2^64 = -33616/-12616/+8384 wei. Thus the first two cases are below the boundary; the third is above it. Historical claims that offset zero itself crosses 2^64 are inaccurate. No observed unauthorized credit in these tested states.

**Honest control:** funded synthetic EVM call consumes 21000 gas and reconciles sender debit 210000, coinbase credit 42000, burn 168000. **Negative control:** sender balance one wei below maximum escrow is rejected without sender/miner mutation. **Strongest counterexample:** arbitrary precision escrow arithmetic, preflight balance check, and successful state assertions. **Attacker route:** externally signed EIP-1559 transaction with chosen fee cap is plausible, but canonical signed transaction acceptance, production block import, and fork configuration were **not** executed by this test. The test uses `types.NewMessage(..., checkNonce=true, ...)` and direct `ApplyMessage`; it does not sign/import a block. E1+historical E2 exists for this exact fixture, but E3/E4 violation absent.

**Missing proof:** a signed synthetic EIP-1559 transaction imported through the canonical block path, including reverted execution, actual receipts, fee-burn and coinbase accounting; fork-activation check and three fresh repetitions only if a breach is observed. No mutation/target vulnerability claimed. No duplicate/CVE determination made this invocation. No external report created.

**Next single discriminating action:** run a class-owned certified scratch signed-transaction/block-import test with fee cap `878416384462360`, clean below-boundary control and revert/insufficient-funds variants; do not start another job while any class-A CI is active.
