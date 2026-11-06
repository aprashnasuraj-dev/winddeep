# A-FEE-01 — signed fee64 revert-boundary control correction (2026-11-06 20:11–20:xx NPT)

**Decision: BLOCKED** for signed certified-runtime execution; **NO CONFIRMED FINDING**. Conditional P1 only if spendable unauthorized credit is demonstrated; no actual CVSS or Bugcrowd severity assigned.

## Newly executed evidence
Read class-owned signed fixture from branch and independently executed Python integer boundary oracle (exit 0). The previous fixture used q=floor(2^64/21000) in *all* modes, but its revert case sets gasLimit=50000. Thus its three revert escrow cases were **all above 2^64**, invalidating the intended below/at/above boundary controls. This is a **test-fixture defect**, not an ETN-SC vulnerability. Repaired class-owned test in commit a71af72e97e75f308b1f2a479a47221ee89da5fc to compute q=floor(2^64/gasLimit) per mode.

Independent Python results (escrow minus 2^64 wei):

| gas limit | q (wei/gas) | q−1 | q | q+1 |
|---:|---:|---:|---:|---:|
| 21000 | 878416384462359 | −33616 | −12616 | +8384 |
| 50000 | 368934881474191 | −51616 | −1616 | +48384 |

**Positive control:** q+1 crosses 2^64 for both modes. **Negative controls:** q−1 and q remain below 2^64. **Other controls:** funded success, revert with fee charged, unfunded rejection without mutation, independent ledger (sender debit, tip, burn). **Strongest counterexample:** existing six-case certified ApplyMessage tests passed and big.Int arithmetic/affordability checks prevent simple overflow in that scope. No unauthorized funds were observed.

## Source identity and execution limitation
Required source commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0; tree de7f3c75a2db7e87a89918f1257820703d5b731e; pinned upstream 3aeb14db0d6384243302f3a025bdff904dc28bf6; archive 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b. **These are required identities, not newly verified runtime identities.** No certified bootstrap, Go test, or signed block import executed in this invocation. Historical workflow runs 42217753209 and 42217786630 reported zero jobs; no Go exit code. The new commit triggers the existing class workflow; do not presume a PASS or initiate overlapping jobs. No live chain interaction.

**Attacker route:** an ordinary sender may choose signed fee cap, but cannot directly set credited balances; production canonical block ingress and adverse effect remain unproven. E1 source/fixture inspection plus independent arithmetic only, E2–E4 for signed processing unmet.

**Next discriminating action:** inspect the job-bearing run for commit a71af72e97e75f308b1f2a479a47221ee89da5fc; require exact source bootstrap identity and `go test -count=1 -timeout=10m -run '^TestWorkerASignedFee64Processing$' -v ./core` stdout and exit code. If zero jobs persist, diagnose GitHub workflow validation without more status-only commits and defer this lead after two blocked attempts.
