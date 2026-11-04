# Worker R — verified recovery and next test handoff (2026-11-04)

## Last verified audit state
- Audit integration branch: `audit/r-stateful-fuzz-seed`. Last substantive Worker R audit commit before recovery: `82ac0b373dd1af07064aa6c1a88813fe1dcbf3bd` (04:04:17 UTC).
- Tested source is immutable Electroneum commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`. The audit did **not** patch the certified source.
- The latest specialized production-depth campaign, P1g, passed: [run 41770476077](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41770476077). It showed that a single post-read canonical-block check still permits a TOCTOU race if the canonical chain changes after that read.
- P1h lower-authority end-to-end control also passed: [run 41776625295](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41776625295). A real loopback TCP/RLPx/ETN66 retrieval peer carrying 2-of-4 QBFT committed seals reached the real downloader and was rejected as `invalid committed seals`; 73 concurrent receipt reads produced 0 stale results. The identical wire path accepted the 3-of-4 positive control.

## Correct classification of E-RPC-004
- **Reproduced:** `GetTransactionReceipt` can return an already-noncanonical successful receipt during reorg; the shipped `bind.WaitMined` consumer can surface that receipt as mined, and a later canonical header-hash comparison rejects it.
- **Conditional actor boundary:** the end-to-end QBFT + TCP/RLPx/ETH66 + downloader demonstration has 3-of-4 validator signatures. It does **not** show an ordinary external peer can create the conflicting QBFT-finalized branch.
- **Negative control strengthened by P1h:** exact-signature-quorum verification accepts legitimate committed blocks; subquorum, duplicate validators and outsiders fail in the tested verifier. Run 41776625295 additionally shows a 2-of-4 lower-authority peer can deliver the candidate over real TCP/RLPx/ETN66 into the real downloader, but the candidate still cannot become canonical; the same-path 3-of-4 control succeeds. This precondition is not merely a transport detail.
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

## P1h completed — certified lower-authority network boundary

- Dedicated branch: `audit/r-production-depth-20261104-12-lower-authority-peer`.
- Certified run: [41776625295](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41776625295), PASS.
- 3-of-4 same-wire positive: 5 header responses + 1 body response, canonical import succeeds.
- 2-of-4 lower-authority control: same 5-header/1-body path, direct verifier rejects `invalid committed seals`, downloader rejects `retrieved hash chain is invalid: invalid committed seals`, canonical head unchanged.
- Receipt concurrency during rejection: 73 calls, 0 stale/noncanonical responses.
- Invalid candidate was served directly by the peer; it was not pre-imported and rawdb was not rewritten.
- Classification: ordinary/lower-authority reachability is **DISPROVEN for this tested 2-of-4 subquorum model**. Do not generalize this into proof that every possible lower-authority, protocol-valid reorg mechanism is impossible.

## Next nonredundant evidence gates
1. **Consumer-finality decision test:** implement a deliberately specified exchange/deposit-style crediting policy in the lab and compare `mined`, N-confirmation and `finalized` decisions under a concurrent canonical replacement. Keep the consumer synthetic unless a real integration is independently verified.
2. **Alternative lower-authority protocol-valid reorg model:** only if a concrete mechanism exists that can create a canonical replacement without validator quorum (for example a legitimate non-finalized branch transition under the shipped rules). Do not manufacture impossible QBFT finality states.
3. **Crash fault model expansion:** current LevelDB tests cover `os.Exit` after completed writes, not torn writes or filesystem/power failure. Label such a new campaign as separate and require precise fault-injection evidence.
### Gating policy
Source defect != public-network exploit. A candidate security finding requires exact source identity, positive control, named oracle, durable reproducer, counterexample, lower-trust production reachability, and concrete impact (G1–G7). A zero-job workflow, generic panic, test compile error or unexpected fuzz assertion is **not** security evidence without triage. Do not modify A–E-owned files or certified source. Do not merge or release based on CI syntax validation alone.
