# Worker R — verified recovery and next test handoff (2026-11-04)

## Last verified audit state
- Audit integration branch: `audit/r-stateful-fuzz-seed`. Last substantive Worker R audit commit before recovery: `82ac0b373dd1af07064aa6c1a88813fe1dcbf3bd` (04:04:17 UTC).
- Tested source is immutable Electroneum commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`. The audit did **not** patch the certified source.
- The latest specialized production-depth campaign, P1g, passed: [run 41770476077](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41770476077). It showed that a single post-read canonical-block check still permits a TOCTOU race if the canonical chain changes after that read.

## Correct classification of E-RPC-004
- **Reproduced:** `GetTransactionReceipt` can return an already-noncanonical successful receipt during reorg; the shipped `bind.WaitMined` consumer can surface that receipt as mined, and a later canonical header-hash comparison rejects it.
- **Conditional actor boundary:** the end-to-end QBFT + TCP/RLPx/ETH66 + downloader demonstration has 3-of-4 validator signatures. It does **not** show an ordinary external peer can create the conflicting QBFT-finalized branch.
- **Negative control:** exact-signature-quorum verification accepts legitimate committed blocks; subquorum, duplicate validators and outsiders fail in the tested verifier. This precondition is not merely a transport detail.
- **Not demonstrated:** theft, authorization bypass, financial loss, irreversible finality guarantee violation, or unauthenticated remote exploitation. `WaitMined` promises mining, not finality.
- **Remediation implication:** a standalone canonicality recheck is not atomic; a defensible consumer needs an explicitly reorg-aware/finality-based decision policy or an atomic view where the underlying data layer supports it.

## CI diagnosis and completed repairs
- [Run 41770943925](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41770943925) was a **no-job** workflow failure on `audit/r-stateful-fuzz-seed`; [run 41770474844](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41770474844) was the matching no-job failure on production-depth branch 11. Do not count either as a failing source test.
- The inherited `.github/workflows/electroneum-reverse-independent-ci.yml` ended with an unterminated shell `-run '` regex, a dedented stray `-v` command and duplicated test/status lines. The already-fixed authoritative copy on `electroneum-sc-master-audit` had blob `40c8951b65e5d78e2c6a0a6fa163dbf3cd25c014` and passed as [run 41750891833](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41750891833).
- The corrected workflow was committed on the stateful seed (`b9c5d983`), production-depth branch 11 (`3a24cbdc`), deep seed (`02224c9b`), next10 seed (`fbf2173c`) and production-depth seed (`a0373b5a`). Historical branch check records are immutable and will remain red.
- A new dedicated `electroneum-r-workflow-lint.yml` parses YAML and syntax-checks the embedded Bash without executing it, pinned to each event SHA and using read-only checkout. Verified **PASS**:
  - stateful seed [41774644944](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41774644944);
  - production-depth 11 [41774686161](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41774686161);
  - deep seed [41774886264](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41774886264);
  - next10 seed [41774891237](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41774891237);
  - production-depth seed [41774896148](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41774896148).
- This proves the corrected workflow and Bash blocks parse in those branches. It is **not** a fresh re-execution of every reverse audit test on each branch.

## Preserve existing stateful-fuzz outcome; do not mark all five green
| Track | Latest run | Result | Meaning |
|---|---:|---|---|
| 01 RPC/wallet | 41755733838 | PASS | Tested wallet sequence properties hold |
| 02 receipt reorg | 41754226567 | FAIL (named oracle) | Reproduced `R_REORG_TOCTOU_ORACLE_FAIL` and minimized corpus `2fde656d41007dc7`; not a workflow syntax error |
| 03 downloader cancellation | 41753148881 | PASS | Tested queue/peer state properties hold |
| 04 parser exhaustion | 41754079807 | PASS | Tested constrained parser limits hold |
| 05 mempool reorg | 41756030280 | PASS | Tested pool/reorg assertions hold |

## Next nonredundant evidence gates
1. **P1h — lower-authority end-to-end negative control:** supply an actual ETH66 peer with a malformed, outsider-signed, or 2-of-4-committed competing fork through real TCP/RLPx and the downloader, without directly importing it or rewriting rawdb. Record the protocol receipt, verifier rejection and unchanged canonical head. Include a 3-of-4 positive control traversing the same pipeline. This would test ordinary-peer reachability beyond the existing direct `VerifyHeader` negative control. Do not claim it passes until certified CI runs.
2. **Consumer-finality decision test:** test a deliberately specified deposit-credit/confirmation consumer against `mined` versus `finalized` and against a concurrent canonical replacement. Keep consumer assumptions explicit and avoid claiming a real exchange is affected unless that integration is verified.
3. **Crash fault model expansion:** current LevelDB tests cover `os.Exit` after completed writes, not torn writes or filesystem/power failure. Label such a new campaign as separate and require precise fault-injection evidence.

### Gating policy
Source defect != public-network exploit. A candidate security finding requires exact source identity, positive control, named oracle, durable reproducer, counterexample, lower-trust production reachability, and concrete impact (G1–G7). A zero-job workflow, generic panic, test compile error or unexpected fuzz assertion is **not** security evidence without triage. Do not modify A–E-owned files or certified source. Do not merge or release based on CI syntax validation alone.
