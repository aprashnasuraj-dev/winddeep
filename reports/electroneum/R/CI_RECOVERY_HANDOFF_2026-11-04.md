# Worker R — verified recovery and next test handoff (2026-11-04)

## Last verified audit state
- Audit integration branch: `audit/r-stateful-fuzz-seed`. Last substantive Worker R audit commit before recovery: `82ac0b373dd1af07064aa6c1a88813fe1dcbf3bd` (04:04:17 UTC).
- Tested source is immutable Electroneum commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`. The audit did **not** patch the certified source.
- The latest specialized production-depth campaign, P1g, passed: [run 41770476077](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41770476077). It showed that a single post-read canonical-block check still permits a TOCTOU race if the canonical chain changes after that read.
- P1h lower-authority end-to-end control also passed: [run 41776625295](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41776625295). A real loopback TCP/RLPx/ETN66 retrieval peer carrying 2-of-4 QBFT committed seals reached the real downloader and was rejected as `invalid committed seals`; 73 concurrent receipt reads produced 0 stale results. The identical wire path accepted the 3-of-4 positive control.
- P1i consumer-policy/finality visibility passed on corrected branch head `36f5c7917784c1e3ecec676669c4d8823571313b`: [run 41778377285](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41778377285). In the deterministic stale-receipt case, a synthetic `mined` policy and a naive 4-confirmation policy both credited an orphaned receipt even with 5 apparent confirmations; a canonical-hash-aware 4-confirmation policy rejected it. A separate valid 3-of-4 QBFT committed block did not populate the generic `finalized` RPC marker.

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

## P1i completed — consumer decision boundary and QBFT finalized-tag visibility

- Dedicated branch: `audit/r-production-depth-20261104-13-consumer-finality`.
- Certified corrected run: [41778377285](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41778377285), PASS. Evidence artifact: `r-production-depth-41778377285-1` (artifact ID `13297104747`).
- Deterministic stale receipt: receipt block `0x2118fb81fc1ac90e51dbe4f2dd06c1e583764dbcbd462ef849bed8a3053637a8`; canonical block at the same height `0xa074042bbe13cf87c5ce8ec218ff5e03616568794c13a9a65883a8a413acb60b`.
- Synthetic `mined` policy: **false credit reproduced**.
- Synthetic naive `N=4` height-only confirmation policy: **false credit reproduced with 5 apparent confirmations**. This proves confirmation count alone is insufficient if the receipt's block identity is not revalidated against the canonical chain.
- Canonical-hash-aware `N=4` policy: **rejected the stale receipt** in the deterministic case. This is a mitigation counterexample, not an atomic no-reorg guarantee.
- QBFT control: a valid block carrying 3-of-4 committed seals imported and became the chain head, but `CurrentFinalizedBlock()` remained nil and `eth_getBlockByNumber("finalized")`-equivalent block lookup returned no block. The shipped generic finalized marker is therefore **not populated by this tested QBFT import path**.
- Source trace: the generic finalized marker is set by `BlockChain.SetFinalized`; in the certified tree the observed setter call is in beacon/Engine-API forkchoice handling. Do not prescribe the generic `finalized` tag as an ETN/QBFT fix without a separately verified ETN finality integration.
- Scope: the consumer is synthetic. **No real exchange integration, financial loss, or arbitrary remote exploit is claimed.**
- Superseded red runs [41778274857](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41778274857) and [41778309547](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41778309547) are harness-only build failures (wrong QBFT decoder call; then incomplete helper mount set). They are not source findings.

## External integration review after P1i

Public-source review did **not** justify promoting the synthetic consumer model to a real explorer/exchange exploit.

- Electroneum Smart Chain's public project description states that its Istanbul/QBFT-derived consensus provides immediate/1-block finality and that valid blocks are not expected to have ordinary concurrent forks. This reinforces the actor boundary from P1h: the demonstrated competing branch requires quorum authority beyond the normal fault model, rather than an ordinary peer-triggered reorg.
- The official Smart Chain explorer repository (`electroneum/electroneum-sc-block-explorer`, inspected at commit `0d4d3e2dd62f834e2620bcd3ebc77aaeb963d1c6`) contains explicit reorg handling. Its `Explorer.Chain.confirmations/2` returns confirmations only for `consensus: true` blocks and returns `{:error, :non_consensus}` otherwise. Its import regression tests also require receipt fields to be cleared when a transaction ends up in a non-consensus block after reorganization.
- The explorer indexer contains block-hash mismatch logic that explicitly identifies a reorg. These are concrete counterexamples to assuming the official explorer simply trusts height-only confirmation arithmetic.
- Therefore **official explorer display impact remains NOT DEMONSTRATED**. A transient race would need a dedicated explorer-level reproducer that survives its own reorg/indexing safeguards before category-E impact can be claimed.
- The legacy Electroneum exchange guide's five-confirmation recommendation belongs to the retired legacy chain and must not be used as proof of Smart Chain exchange behavior.

References:
- https://github.com/electroneum/electroneum-sc
- https://github.com/electroneum/electroneum-sc-block-explorer/blob/0d4d3e2dd62f834e2620bcd3ebc77aaeb963d1c6/apps/explorer/lib/explorer/chain.ex
- https://github.com/electroneum/electroneum-sc-block-explorer/blob/0d4d3e2dd62f834e2620bcd3ebc77aaeb963d1c6/apps/explorer/test/explorer/chain/import_test.exs
- https://github.com/electroneum/electroneum-sc-block-explorer/blob/0d4d3e2dd62f834e2620bcd3ebc77aaeb963d1c6/apps/indexer/lib/indexer/block/fetcher.ex

## Next nonredundant evidence gates
1. **Real third-party integration evidence:** only strengthen invariant E beyond the synthetic model if an actual wallet/explorer/exchange integration can be verified to credit on `mined` or height-only confirmations without canonical block identity/reorg handling. Do not infer this from the SDK alone.
2. **Alternative lower-authority protocol-valid reorg model:** only if a concrete mechanism exists that can create a canonical replacement without validator quorum. P1h already disproves the tested 2-of-4 subquorum path; do not manufacture impossible QBFT states.
3. **Crash fault model expansion:** current LevelDB tests cover `os.Exit` after completed writes, not torn writes or filesystem/power failure. Treat this as a separate campaign with precise fault injection.
### Gating policy
Source defect != public-network exploit. A candidate security finding requires exact source identity, positive control, named oracle, durable reproducer, counterexample, lower-trust production reachability, and concrete impact (G1–G7). A zero-job workflow, generic panic, test compile error or unexpected fuzz assertion is **not** security evidence without triage. Do not modify A–E-owned files or certified source. Do not merge or release based on CI syntax validation alone.

## P2b completed — synthetic LevelDB WAL tail fault recovery

- Isolated branch: `audit/r-production-depth-20261104-14-leveldb-wal-fault`. Certified run: [41785659278](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41785659278), **PASS**. Workflow syntax guard [41785659245](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41785659245), **PASS**.
- A child writes the fully completed checkpoint, then exits with code 97 without closing LevelDB. Four independent copies of the same DB are recovered: unaltered, WAL last byte truncated, last 64 bytes truncated, and final WAL byte flipped. The synthetic faults are applied only *after* the child process exits.
- Clean recovered full head at block 1; truncate-1 recovered full=1; truncate-64 recovered full=0 while retaining canonical mapping at height 1; flip-last recovered full=1. All passed the test's header/transaction/receipt commitment assertions and real `NewBlockChain` restart.
- This test shows coherent recovery **under these four narrow conditions**, not full durability of every write. The 64-byte truncation demonstrates lost latest full-head advancement; no confirmed invalid transaction execution, remote exploit, loss of funds, or vulnerability classification.
- The first branch-14 runs [41785530770](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41785530770) and [41785532512](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41785532512) failed at workflow parsing/lint because the generated shell-regex string was accidentally expanded by a JavaScript replacement operation. This was corrected in commit `f6337873ff640d930fd0fffc185b23c1c3d5e17d`; they are **superseded harness registration failures**, not vulnerabilities.
- Next evidence gate: test faults at independently identified LevelDB journal batch/write/fsync boundaries, with documented power-loss assumptions, rather than implying an arbitrary post-exit bit flip is production-reachable. Separately, do not promote E-RPC-004 without confirming third-party client/explorer impact and its QBFT authority precondition.
