# Reverse Audit Worker R — Latest Independent Run

## 2026-11-04 05:39 NPT — Reverse pass 1 of 14: E-RPC-010 verified runtime error-handling defect

**Owner R (independent of A–E).** Start at newest open E item, traverse older E items, then D → C → B → A in descending item chronology. Existing A–E files, workflows, automations, schedules and ongoing CI are **READ-ONLY** for R. All R write paths: `reports/electroneum/C/reports/REVERSE_AUDIT_*`, `reports/electroneum/C/reverse/`, and `.github/workflows/electroneum-reverse-independent-ci.yml`. Never overwrite the existing C report or C/LATEST.md. Findings use existing four-section security report headings **only in candidate analysis** unless reproducible lower-trust security impact is confirmed.

### Executive forensic result

**Confirmed software defect under a conditional state; security risk still open.** Electroneum's actual `PublicTransactionPoolAPI.GetTransactionReceipt` panics when the synthetically supplied backend gives `(nil,nil)` for a London-era block header while a validly shaped receipt and transaction index remain available. The independent fail-closed oracle rejected the original source. A defensive missing-header guard applied **only to a disposable scratch copy** made that exact oracle pass. Runtime results were obtained from the certified Go source. There is **no proof** that an untrusted JSON-RPC caller can produce the missing-header precondition on a coherent live full node, that the RPC panic escapes server recovery, or that assets/history/finality are affected.

### Exact source and attacker path

- Source: [`internal/ethapi/api.go:1571–1614`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1571-L1614) `GetTransactionReceipt`; separate transaction/receipt lookups, `HeaderByHash` and unchecked `header.BaseFee`.
- Production backend: [`eth/api_backend.go:99–101`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L99-L101) returns `GetHeaderByHash(hash),nil`, potentially `(nil,nil)`.
- Attacker-controlled request: transaction hash query (when public `eth` RPC module exposed). **Unproven trust crossing:** can that query cause a transaction+receipt to exist while its header becomes inaccessible during concurrent reorg/pruning/db failure? An ordinary full node may preserve coherent hash-indexed data, defeating the attack.

### Certified execution and decisive log

| Gate | Evidence and status |
|---|---|
| G1 source certification | **PASS in CI** via `source tools/electroneum_target_bootstrap.sh`, four identity assertions; immutable source path `/home/runner/work/_temp/windeep-electroneum-tree.ANMK50FT/source`. Windeep commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, source tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Local checkout unavailable (GitHub DNS exit 128); no false local execution claimed |
| G2 attacker path | **PARTIAL** actual exported `eth_getTransactionReceipt` adapter and backend source traced. Real full-node lost-header precondition / remote attacker control unproved |
| G3 target runtime | **PASS**, five real adapter cases on certified synthetic backend: coherent London receipt; no-receipt early null; pre-London missing-header bypass; London missing-header panic; injected receipt.TxHash disagreement. Four counterexample/behavior variations + baseline |
| G4 independent oracle/sensitivity | **PASS for tested nil-header condition**: independent structured-error oracle intentionally failed on original source (exit 1, named mismatch marker) and passed after defensive guard injection on R's **scratch-only** copy. No source or other worker file mutation |
| G5 commands/logs | **PASS**: `go test -count=1 -timeout=10m -run '^TestReverseEReceiptDefenseMatrix$' -v ./internal/ethapi` exit 0. `go test -count=1 -timeout=10m -run '^TestReverseEFailClosedOracle$' -v ./internal/ethapi` original exit **1 expected** with `REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH`; after injecting scratch guard both `TestReverseE*` cases PASS, and immutable-source SHA check PASS |
| G6 new path | **YES**: independently challenged original E source hypothesis by validating no-receipt/pre-London controls and a reversible fail-closed oracle. This is new R evidence, independent of E's job |
| G7 committed report | **YES** once this R-only checkpoint and state ledger commit. Confirmed-vulnerability report deliberately untouched |

**CI run:** [41742642862](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41742642862), job `126287716651`, trigger SHA `9cd0963117ee3fd93990a999cafa009eed836f5b`, **COMPLETED/SUCCESS**. Exact observed job output:

```text
REVERSE_E_VALID_LONDON_CONTROL_PASS
REVERSE_E_NO_RECEIPT_DEFENSE_PASS
REVERSE_E_PRE_LONDON_COUNTEREXAMPLE_PASS
REVERSE_E_RUNTIME_NIL_HEADER_PANIC_OBSERVED type=runtime.errorString value=runtime error: invalid memory address or nil pointer dereference
REVERSE_E_SYNTHETIC_RECEIPT_MISMATCH: public adapter emits requested hash; real backend consistency unproven
REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH: header=nil yielded panic type=runtime.errorString
REVERSE_R_ORIGINAL_SOURCE_ORACLE_REJECTED exit=1
REVERSE_E_SCRATCH_GUARD_INJECTED
REVERSE_E_FAIL_CLOSED_ORACLE_PASS
REVERSE_R_E_GUARD_SENSITIVITY_AND_CERTIFIED_SOURCE_INTACT_PASS
```

The `##[error]` prefix on successful `sha256sum --check` output is a GitHub log presentation artifact; the verification exited successfully and the job was SUCCESS. No benchmark fuzz counts claimed: this campaign is a targeted bounded deterministic oracle, not a sustained fuzz job; elapsed test runtime on log output is ~0.03s for Go test bodies after compilation.

### Reverse-order queue and next action

**First analyzed:** E-RPC-010 (software defect **VERIFIED**, production exploitability **OPEN**, no remote-impact claim). **Second item:** E-RPC-008, partial-success `eth_getLogs` with a nil intermediate header; validate both missing-first and missing-middle counterexamples, and run the independent fail-closed oracle on actual `eth/filters` source before any promotion. Then move to E-RPC-004 receipt canonicality, E-RPC-002 fee serialization, D newest-to-oldest, C, B, and A. Disproven claims are skipped; unresolved reachability remains in the backlog rather than marked fixed. If a class R CI is RUNNING/QUEUED, do not dispatch overlap; pursue independent certified source falsification.

### Recommended engineering fix, NOT applied to upstream

After `HeaderByHash`, reject `header == nil` with a structured error; on London forks also check `header.BaseFee` is present; add a race/reorg regression with a real in-process `EthAPIBackend`. Treat the already executed scratch guard as **sensitivity proof**, not a production patch. Correctness and severity must be established on a full-node interface before reporting a remotely exploitable vulnerability.

### Preservation and handoffs

- New class R-only path: [reverse CI](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/.github/workflows/electroneum-reverse-independent-ci.yml), [E fixture](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reverse/reverse_e_rpc_header_test.go), scratch defensive guard script, [candidate ledger](REVERSE_AUDIT_CANDIDATES.md), [state ledger](REVERSE_AUDIT_STATE.json).
- No changes to A–E's original `LATEST.md`, fixture files, workflows, branch ownership, active CI, or scheduled automations.
- Findings report for confirmed security vulnerabilities stays blank/uncreated until reachable impact proof. This latest and candidate report are process/candidate evidence, not a disclosure.


## 2026-11-04 05:46 NPT — Reverse pass 2 of 14: E-RPC-008 silent incomplete log range confirmed in certified Go runtime

**Result:** [class R Actions 41743587384](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41743587384), job `126290902950`, trigger `04acc6fa5ce171e6182c3b90ed116602aa533334`, **COMPLETED/SUCCESS**. Independent original-source target-runtime test on `eth/filters/Filter.Logs` proves that a synthetic missing intermediate `HeaderByNumber=(nil,nil)` can cause **silent partial success** for `eth_getLogs`: requested block [1..3] yields only block 1's log with a nil error. That is a **software error-handling defect**, not proof of exchange theft or attacker-accessible canonical gaps.

### Source trace and strongest defense

- [`eth/filters/api.go:365–396`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/filters/api.go#L365-L396) `PublicFilterAPI.GetLogs` → range filter and successful return.
- [`eth/filters/filter.go:224–238`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/filters/filter.go#L224-L238) `unindexedLogs` returns the accepted prefix and `err` when header=nil, even if `err` is nil; `indexedLogs` at lines 206–210 exhibits a similar source pattern but **remains untested**.
- [`eth/api_backend.go:70–82`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L70-L82) `HeaderByNumber` can return `(nil,nil)` if no header is found.
- **Defeating control:** shipped full nodes normally maintain contiguous canonical headers. An arbitrary `eth_getLogs` request does not independently erase a canonical header; adversarial reachability and impact remain **OPEN**, not confirmed.

### Exact execution evidence / G1–G7

| Gate | Observed status |
|---|---|
| G1 | PASS from mandatory certified Actions bootstrap. Source Windeep `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, historical archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. No local bootstrap; local Git DNS exit 128 previously demonstrated |
| G2 | PARTIAL: real exported `GetLogs` adapter and backend path source-grounded, but local corruption/reorg production precondition and lower-trust influence unverified |
| G3 | PASS: real Go `Filter.Logs` called on certified scratch with 5 structured test cases: all-valid, missing-middle, missing-first, explicit backend error and range-limit enforcement |
| G4 | PASS: independent strict error oracle rejected original source with named failing marker and exit 1; locally repaired missing-header guard in disposable scratch made oracle PASS; immutable source unchanged |
| G5 | PASS: `go test -count=1 -timeout=12m -run TestReverseELogRangeDefenseMatrix -v ./eth/filters` exit 0; `go test -count=1 -timeout=10m -run TestReverseELogFailClosedOracle -v ./eth/filters` original exit 1 **expected and marker-checked**; post-scratch-guard `go test -count=1 -timeout=12m -run '^TestReverseELog' -v ./eth/filters` exit 0 |
| G6 | PASS: new actual `eth_getLogs` incomplete success branch and explicit error/range-cap negative controls absent from previous E nil-header receipt campaign |
| G7 | PASS when this R-only LATEST checkpoint is committed |

**Decisive job markers:**
```text
REVERSE_E_LOG_COMPLETE_RANGE_PASS count=3
REVERSE_E_LOG_MISSING_MIDDLE_SILENT_PARTIAL_OBSERVED count=1 requested=3
REVERSE_E_LOG_MISSING_FIRST_SILENT_EMPTY_OBSERVED
REVERSE_E_LOG_EXPLICIT_ERROR_CONTROL_PASS
REVERSE_E_LOG_RANGE_CAP_CONTROL_PASS
REVERSE_E_LOG_FAIL_CLOSED_ORACLE_MISMATCH: query [1..3] returned 1 logs with nil error and missing block 2
REVERSE_R_LOG_FAIL_CLOSED_ORACLE_REJECTED exit=1
REVERSE_E_LOG_SCRATCH_GUARD_INJECTED
REVERSE_E_LOG_FAIL_CLOSED_ORACLE_PASS err=missing block header 2 while scanning logs returned_prefix=1
REVERSE_R_E_LOG_GUARD_SENSITIVITY_AND_SOURCE_INTACT_PASS
```

**Infrastructure distinction:** Initial reverse step extension [Actions 41743525868](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41743525868) failed at YAML parsing (truncated Go command, **zero jobs**). Workflow-only repair `04acc6fa5ce171e6182c3b90ed116602aa533334` initiated the above certified successful run. The invalid YAML run is **not** an Electroneum defect or a completed Go test.

**Progression:** E-RPC-010 and E-RPC-008 verified as conditional runtime software defects; real-world attack reachability retained OPEN. Cursor advanced to third task **E-RPC-004** (transaction/receipt canonicality and real reorg; stronger actual backend oracle needed), then E-RPC-002, D newest to oldest, C, B, A. Skip disproven candidates. 12 queued/active tasks remain; no claim that reverse auditing all five classes is complete.

**Scheduling control:** Attempt to create a sixth hourly ChatGPT automation `ETN Reverse Audit R` returned `too_many_active_automations` — account limit **5**, already occupied by A–E. **No** A–E task was altered or paused. R remains independently executable via its own branch-scoped GitHub Actions push/manual workflow; GitHub cron does not run from this nondefault branch (`main` is default), and the worker is not represented as autonomously scheduled until a task slot is freed. No changes to default branch or upstream.

**Recommended correction:** Handle `header == nil` as an explicit error in both indexed and unindexed filters, and add real backend gap/reorg/rollback tests before classifying remote financial risk. Keep the original target immutable; the proven guard exists only in an isolated scratch.


## 2026-11-04 05:57 NPT — Reverse pass 3 of 14: E-RPC-004 rawdb-backed canonicality TOCTOU reproduced

**Run mode: USER-REQUESTED LIVE SESSION, NOT HOURLY.** Independent reverse Worker R acts only in `reports/electroneum/C/reports/`, `reports/electroneum/C/reverse/` and `.github/workflows/electroneum-reverse-independent-ci.yml`. No A–E existing reports, tests, workflows or task automations were modified, stopped or restarted.

**Executive result:** Source-backed **conditional RPC read-consistency defect** reproduced by real certified `PublicTransactionPoolAPI.GetTransactionReceipt` using actual `rawdb.ReadTransaction` and `rawdb.ReadReceipts` on synthetic in-memory chain data. A transaction seen as canonical during the first read was returned as a *successful orphan receipt* after the canonical mapping changed before the second read. **No proof of a below-BFT-threshold attacker-induced live QBFT reorg, exchange credit error or real loss**.

### Certified source / reverse evidence gates

- **G1 PASS:** certified source bootstrap in [GitHub Actions #41744841662](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41744841662), job `126295379539`. Immutable Windeep commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, historical archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Passed shell gate/identity; scratch-only Go test, source file SHA unchanged.
- **G2 PARTIAL** production path source-linked: `internal/ethapi/api.go:GetTransactionReceipt` [1571–1627](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1571-L1627), `EthAPIBackend.GetTransaction` [265–269](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/api_backend.go#L265-L269), `rawdb.ReadTransaction` [94–120](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/core/rawdb/accessors_indexes.go#L94-L120), and `BlockChain.GetReceiptsByHash` [203–217](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/core/blockchain_reader.go#L203-L217). Original tx lookup canonicality is a verified defense **against completed reorg**; subsequent receipt lookup by original block hash has no new canonical check. Synchronized real full node QBFT reorg precondition remains unproved.
- **G3 PASS:** `go test -count=1 -timeout=12m -run '^TestReverseECanonicalRawdbDefenseMatrix$' -v ./internal/ethapi`, exit **0**. Five cases: honest canonical receipt, stale lookup after completed reorg (null), new canonical receipt, missing stored receipt (null), and **forced mid-request block replacement** (stale receipt success). Go test executed actual `ethapi` and `rawdb`, not a mocked return-value matrix. Synthetic backend is not full `EthAPIBackend`.
- **G4 PASS (in tested state):** `go test -count=1 -timeout=10m -run '^TestReverseECanonicalTOCTOUOracle$' -v ./internal/ethapi` on unmodified certified scratch returned **exit 1 expected**, marker `REVERSE_E_CANONICAL_TOCTOU_ORACLE_MISMATCH`; not a Go compile error. Adding a `BlockByNumber` identity guard to *scratch only* via `reverse_e_canonical_guard_patch.py` made `go test -count=1 -timeout=12m -run '^TestReverseECanonical' -v ./internal/ethapi` return **0**, with all controls and strict oracle PASS. Immutable source SHA check OK. A post-read guard itself is not a full atomic snapshot mechanism.
- **G5 PASS:** 662-line decisive Actions job log fetched; workflow run `41744841662`, job `126295379539`, trigger SHA `58360148aa9bbc2f6739170f3206aaba750c4446`, overall **COMPLETED/SUCCESS**. Prior R runs `41744708472`, `41744735795` were completed SUCCESS on earlier file-only push SHAs, not the new E-004 tests. CI run `41744841662` finished 2026-11-04 00:12:12Z; no fuzz throughput claimed.
- **G6 PASS:** independent counterexample-first **time-of-check/time-of-use** boundary added after previous E-010 nil header/E-008 partial logs; source-backed negative controls prevented interpreting a normal stale index as a flaw. Attacker control/reorg timing remains open.
- **G7 PASS:** four-heading candidate assessment added to [`REVERSE_AUDIT_CANDIDATES.md`](REVERSE_AUDIT_CANDIDATES.md), commit `5a22577b9599db394788e287a78c6eb1b10975d7`; state updated `f3fa1bc69ca8cb7285544e53b1211ccee79ba3b5`; this latest entry committed. Dedicated CONFIRMED security-vulnerability report unchanged.

**Runtime markers:**
```text
REVERSE_E_RAWDB_COHERENT_RECEIPT_PASS
REVERSE_E_RAWDB_ORPHAN_INDEX_DEFENSE_PASS
REVERSE_E_RAWDB_NEW_CANONICAL_PASS
REVERSE_E_RAWDB_MISSING_RECEIPT_NULL_PASS
REVERSE_E_RAWDB_TOCTOU_STALE_RECEIPT_OBSERVED
REVERSE_E_CANONICAL_TOCTOU_ORACLE_MISMATCH (original, intentional exit=1)
REVERSE_R_CANONICAL_ORACLE_REJECTED_ORIGINAL exit=1
REVERSE_E_CANONICAL_SCRATCH_GUARD_INJECTED
REVERSE_E_CANONICAL_TOCTOU_ORACLE_PASS
REVERSE_R_CANONICAL_GUARD_SENSITIVITY_CERTIFIED_SOURCE_INTACT_PASS
```

**Preservation and next hypothesis:** Reverse traversal cursor **3/14** complete, E-RPC-004 conditionally reproduced; E-RPC-002 **ACTIVE**. Trace actual receipt `effectiveGasPrice` `big.Int -> Uint64` narrowing at `internal/ethapi/api.go:1606,1615`, use synthetic signed transactions with gas price crossing 2^64 while verifying legitimate chain/rpc fee cap constraints; execute a true source-backed Go response test and independent arbitrary-precision oracle. Then proceed D → C → B → A, newest unresolved items first; skip disproven cases. No new automations required, and A–E are untouched.


## 2026-11-04 06:02 NPT — Reverse pass 4 of 14: 2^64 RPC gas price precision loss reproduced

**Live request only; no hourly task or automation change.** Independent R files and class-specific workflow only. Existing A–E work read-only.

- **New verified defect:** [`internal/ethapi/api.go:1606,1615`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L1601-L1616) truncates `big.Int` `effectiveGasPrice` to `hexutil.Uint64`. Certified actual Go receipt handler [run 41745455574](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41745455574), job `126297338355`, COMPLETED/SUCCESS, source commit SHA `8c2a28cd75792baf2b3b4bc69a0c1812f364ffe8`. Test fixture [`reverse_e_fee_width_test.go`](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reverse/reverse_e_fee_width_test.go) with **synthetic signed** transactions.
- **G1 PASS CI:** Windeep `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance SHA `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Certified source hash unchanged. No public chain queries or real keys.
- **G2 PARTIAL:** RPC receipt source path verified, but attacker ability to get such a high-fee transaction mined under default submission path is not confirmed. [`eth/ethconfig/config.go:97`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/ethconfig/config.go#L97) default `RPCTxFeeCap=100000`; [`internal/ethapi/api.go:2017–2031`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/internal/ethapi/api.go#L2017-L2031) enforced by `SubmitTransaction`. At `2^64` wei per gas, 21k gas costs ~387,381.63 native coin units (10^18 source denominator), 3.87× cap, so normal default RPC fee submission is a strong defeating control. [`core/state_transition.go:243–249`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/core/state_transition.go#L243-L249) permits up to 256-bit fee widths; configured/custom inclusion/large balances remain possible inference.
- **G3 PASS:** `go test -count=1 -timeout=10m -run '^TestReverseEReceiptFeeWidthCharacterization$' -v ./internal/ethapi` exit 0. Honest London price 10 matched; `2^64-1` matched; signed test price `18446744073709563961` (2^64+12345) reported **12345** in *both* London and pre-London paths. No claim the transaction was actually mined.
- **G4 PARTIAL:** `go test -count=1 -timeout=10m -run '^TestReverseEReceiptFeeWidthOracle$' -v ./internal/ethapi` original exit 1 intentional and named marker `REVERSE_E_FEE_FULLWIDTH_ORACLE_MISMATCH` twice; workflow verified exact marker, not arbitrary failure. Scratch corrective mutation was NOT executed: a separate file-write attempt was rejected by connector safety policy. Do not fabricate defensive mutation evidence.
- **G5 PASS:** 726-line finished job log fetched. Markers `REVERSE_E_FEE_IN_RANGE_PASS fee=10`, `REVERSE_E_FEE_IN_RANGE_PASS fee=18446744073709551615`, `REVERSE_E_FEE_HIGH_TRUNCATION_OBSERVED london=true original=18446744073709563961 reported=12345`, identical `london=false`, and `REVERSE_R_E_FEE_ORACLE_REJECTED_ORIGINAL exit=1`. Other prior reverse stages remained successful.
- **G6 PASS:** source-backed high-fee serialization boundary, independent numeric oracle, positive/negative controls, default RPC fee cap counterexample; confirms *numeric representation defect*, not balance/theft/finality compromise. Distinct from prior E receipt/reorg cases. G7 PASS with this R-only checkpoint committed. Four-section candidate report [`REVERSE_AUDIT_CANDIDATES.md`](REVERSE_AUDIT_CANDIDATES.md) updated commit `d2e73229955c0c4c682996510edaddd546da1a76`.
- **State/cursor:** passes #1 E-010, #2 E-008, #3 E-004, #4 E-002 complete as conditional target software behaviors; **0 confirmed attacker-reachable security exploit**. Reverse cursor now **4/14**. Next `D-PARTIAL-RECEIPT`, then remaining D, C, B, A from most recent to oldest. No separate R scheduled automation; run remains live-only.

**Remaining E reachability:** actual mainnet BFT reorg/missing header path, full-node receipt race, larger accepted fees bypassing standard 100000 cap, and any consequential end-user accounting reliance. No confirmed vulnerability disclosure produced.


## 2026-11-04 06:07 NPT — Reverse D partial receipt pass: four peer/replay defenses survive

**Owner R LIVE, not scheduled.** Only R-owned `C/reverse/`, `C/reports/REVERSE_AUDIT_*` and reverse workflow changed; no A–E original tests, reports, workflows, certified source bytes or automations were altered.

- **New source-backed target test:** [`reports/electroneum/C/reverse/reverse_d_receipt_peer_revoke_test.go`](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reverse/reverse_d_receipt_peer_revoke_test.go), installed only into a disposable certified `eth/downloader` Go test package. It uses actual `queue.ReserveReceipts`, `Revoke`, `DeliverReceipts`, peer rejection, header-commitment checks and RLP decoding.
- **Certified execution:** [Actions 41746131665](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41746131665), job `126299468491`, trigger SHA `ed9d1bda1e100d31cdf70118626f25aa1df7e106`, **COMPLETED/SUCCESS**. `go test -count=1 -timeout=15m -run '^TestReverseDReceiptPeerRevocationAndReplay$' -v ./eth/downloader`, exit **0**, four executed subtests:
  1. Revoke pending 3-receipt peer, reject stale peer delivery; reassigned peer receives and commits all 3: `REVERSE_D_RECEIPT_REVOKED_STALE_PEER_REJECTED_PASS reassigned=3`.
  2. Valid first receipt, malformed second root, then revoke a second peer before retrying; surviving prefix 1 plus correctly accepted suffix 2: `REVERSE_D_RECEIPT_PREFIX_REVOKE_RETRY_PASS accepted=1+2`.
  3. Replay already accepted peer batch; reject duplicate without restoring completed tasks: `REVERSE_D_RECEIPT_DUPLICATE_REPLAY_REJECTED_PASS`.
  4. Bad first RLP receipt, reject all and requeue 3; a new peer supplies valid batch: `REVERSE_D_RECEIPT_INVALID_RLP_NO_LOSS_PASS`.
- **Prior CI distinction:** [41745900912](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41745900912) FAILED before running D Go test because the new R-only fixture at line 48 contained invalid Go declaration (`expected ';', found ':='`). Another concurrent writer corrected the same R-only line; my stale SHA update was rejected with 409 and no overwrite occurred. The corrected succeeding run is **not a claimed Electroneum bug fix**.
- **Gates:** G1 PASS in certified CI (Windeep source `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6` and archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`); G2 PARTIAL real downloader's peer-controlled receipt input path traced, full restart/rewind not tested; G3 PASS actual queue Go four adversarial cases; G4 PARTIAL independent header-root/count acceptance expectations, no deliberately weakened queue mutation; G5 PASS logged command/exit and 760-line decisive job log; G6 PASS distinct revoked/duplicate/malformed wire controls and follow-up; G7 PASS on commit.
- **Classification:** **NO_VULNERABILITY_IN_THE_FOUR_TESTED_PEER_RETRY_CASES**, NOT blanket downloader/history security proof. Prior valid-prefix handling was robust in this fixture. Remote history rewrite and canonical root manipulation are not demonstrated.
- **Next actionable D hypothesis:** [`eth/downloader/queue.go:874–898`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/downloader/queue.go#L874-L898) `deliver` calls `GetDeliverySlot`, then attempts to reconstruct if `err==nil` even if a *stale* slot returned `nil,nil`; [`eth/downloader/resultstore.go:99–122`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/downloader/resultstore.go#L99-L122) returns `nil,true,nil` for header number below advanced `resultOffset`. Test a synthetic in-flight fetch followed by `q.Prepare(newOffset)`, with Revoke-before-advance and normal-start controls. **Strongest defeating control:** [`eth/downloader/downloader.go:592`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/downloader/downloader.go#L592) normally calls `queue.Prepare` **before** launching concurrent fetchers; no natural in-flight offset change is yet source demonstrated. Do not label an artificial invalid queue call a real attacker-reachable outage. Once bounded, move D-HEADER-ROLLBACK.
- **Reverse cursor:** four completed E candidates; D-PARTIAL receipt control subfamily executed and left ACTIVE for restart/offset. Confirmed network exploit total remains **0**. No A–E tasks or CI runs stopped. No new hourly automation created.

## 2026-11-04 06:08 NPT — Reverse D pass 5: peer-revoke/replay checked; reset and expiry regression queued

**Scope and ownership:** live, ad-hoc independent reverse Worker R on `electroneum-sc-master-audit`, not an hourly automation. No writes to A–E files, their workflows, schedules or certified target source. All test fixtures use local synthetic receipt queues and immutable certified source copied to scratch.

**Status:** D-PARTIAL-RECEIPT is **partially DISPROVEN** for specific stale-peer/replay/lost-retry hypotheses under standard in-process queue conditions. It remains **ACTIVE** for cancel/reset, expiry, restart and real peer admission. No security vulnerability is confirmed.

- **Mandatory G1 certification:** Actions [41746131665](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41746131665) completed SUCCESS after pinned bootstrap. Windeep commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, provenance SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.
- **Actual runtime:** run `41746131665`, job `126299468491`, command `go test -count=1 -timeout=15m -run '^TestReverseDReceiptPeerRevocationAndReplay$' -v ./eth/downloader` exited 0. Four target-runtime subtests PASS: `REVERSE_D_RECEIPT_REVOKED_STALE_PEER_REJECTED_PASS reassigned=3`; `REVERSE_D_RECEIPT_PREFIX_REVOKE_RETRY_PASS accepted=1+2`; `REVERSE_D_RECEIPT_DUPLICATE_REPLAY_REJECTED_PASS`; `REVERSE_D_RECEIPT_INVALID_RLP_NO_LOSS_PASS`. Actual completed job log independently inspected (760 lines); no unsafe state observed in these controls.
- **Runner defect correction:** earlier [41745900912](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41745900912) failed to compile: Go `worker_r_reverse_receipt_peer_revoke_test.go:48:40: expected ';', found ':='`, from an invalid test declaration `p1:=...,p2:=...`. The same exact fixture on branch has been corrected to `p1,p2:=...`, and certified run `41746131665` PASS. This was a **test syntax defect**, not an Electroneum exploit.
- **NEW production-boundary counterexample traced:** [`eth/protocols/eth/handlers.go:572–607`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/protocols/eth/handlers.go#L572-L607) derives `Response.Meta` receipt-root hashes locally as `make([]common.Hash,len(receipts))` after `decodeLimitedList` and `rlp.SplitList` validation; [`eth/downloader/fetchers_concurrent_receipts.go:90–99`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/downloader/fetchers_concurrent_receipts.go#L90-L99) passes that local metadata to [`queue.DeliverReceipts`](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/eth/downloader/queue.go#L805-L829). Thus a hypothetical directly supplied shorter hash array causing `receiptListHashes[index]` out-of-range is **not shown remotely controllable** by an eth/66 peer: the shipped handler maintains equal raw receipts/hash counts. Do not publish it as network DoS.
- **New independent runtime hypothesis:** sequence: accept valid prefix; receive corrupted second receipt; close and reset downloader queue; reject a stale old-session delivery; re-schedule six trusted headers; accept three valid receipt batches. Separate timeout path: expire receipt fetch, reject late response, reassign and accept all three. Fixture [`reverse_d_restart_expire_test.go`](https://github.com/aprashnasuraj-dev/winddeep/blob/electroneum-sc-master-audit/reports/electroneum/C/reports/fixtures/reverse_d_restart_expire_test.go) committed `e14287a00c580e1a6cc9894245d5db82bcb71d68`, then integrated in *R-owned* workflow commit `fd1010a59552ddf70b49a98c1adca4c5fd293f17`. [Run 41746346715](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41746346715) **QUEUED** at this checkpoint. This fixture is prepared and has **not yet been counted as executed**; do not claim outcomes before Go job step/logs.
- **Gates:** G1 PASS prior completed certified CI; G2 true receipt peer -> decoded response -> locally derived root metadata -> queue source path traced, adversarial network crash unproven; G3 four actual valid/malicious/duplicate/invalid replay variants PASS, new reset/expiry pending; G4 independent header-root oracle and semantic invalid RLP controls, dedicated mutation sensitivity incomplete; G5 exact executed command and four log markers recorded; G6 new expiry/reset path queued and stronger metadata counterexample traced; G7 this report update. No public network probes, real chain sends or credentials used.
- **Next:** inspect Actions `41746346715` to distinguish Go harness defect from actual queue invariant violation; only then advance reverse cursor from D-PARTIAL to D-HEADER-ROLLBACK. Preserve prior E-010/E-008/E-004/E-002 findings, their production reachability OPEN and existing A–E work.


## 2026-11-04 06:07 NPT — reverse pass 5/14: D receipt peer revocation, invalid RLP and replay defended

**Status: PASS within four peer-adversarial scenarios; no reproduced D historical rewrite.** The current task was an actual live, on-demand Worker R audit, not an hourly automation. Only R-owned `reports/electroneum/C/reverse/` and `reports/electroneum/C/reports/` changed; A–E schedules, workflows and files are untouched.

- **Certified Go source:** `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, Git tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, provenance archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b` (not re-hashed). The GitHub runner successfully bootstrapped immutable `WINDEEP_ETN_SOURCE`, then copied it to disposable `REVERSE_R_SCRATCH`; no public chain or live accounts involved.
- **Attacker boundary:** untrusted ETH peer sends RLP receipts on requested blocks; `eth/downloader/queue.go:805-922` `DeliverReceipts -> deliver` roots checked against admitted headers and `q.lock` held, `Revoke` clears the peer reservation, `errNoFetchesPending` rejects stale unsolicited/replay deliveries, invalid suffix requeued.
- **Initial false failure:** [Actions 41745900912](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41745900912) **FAILED due only to Go syntax error** at R-owned fixture line 48 `expected ';', found ':='`; the D test did not execute and no target defect was established. Corrected `p1,p2 := ...,...` at commit `ed9d1bda1e100d31cdf70118626f25aa1df7e106`.
- **Decisive certified execution:** [Actions 41746131665](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41746131665), job `126299468491`, trigger SHA `ed9d1bda1e100d31cdf70118626f25aa1df7e106`, **COMPLETED/SUCCESS**. Command `go test -count=1 -timeout=15m -run '^TestReverseDReceiptPeerRevocationAndReplay$' -v ./eth/downloader`, exit **0**, four subtests PASS. Exact markers:
  - `REVERSE_D_RECEIPT_REVOKED_STALE_PEER_REJECTED_PASS reassigned=3`
  - `REVERSE_D_RECEIPT_PREFIX_REVOKE_RETRY_PASS accepted=1+2`
  - `REVERSE_D_RECEIPT_DUPLICATE_REPLAY_REJECTED_PASS`
  - `REVERSE_D_RECEIPT_INVALID_RLP_NO_LOSS_PASS`
- **Independent oracle:** trusted synthetic block header receipt root computed from actual RLP. The invalid hash/RLP and revoked-peer replay are deliberate negative controls, validated by rejection and zero missing tasks; counts after valid retry are exact (3/3, 1+2/3, 3/3). No separate scratch-disabled-root mutation was run. Four pass cases demonstrate these particular defenses, NOT restart/pivot/finality safety.
- **G1–G7:** G1 YES (certified CI, not local); G2 PARTIAL (synthetic peer admissions, actual peer topology untested); G3 YES four source-runtime adversarial cases; G4 PARTIAL independent receipt root and failure controls, no injected guard mutation; G5 YES full CI job log 760 lines retrieved, exact commands/output/exit; G6 YES independently exercises revoke-after-request, revoked-suffix retry, duplicate and malformed RLP; G7 YES once this latest file committed. Total runtime for D subtest ~0.01s after compilation, no sustained fuzz counts.
- **Status and rotation:** `D-PARTIAL-RECEIPT` tested for these four subpaths and **no vulnerability found in that scope**; crash/restart/pivot revalidation remains open. Cursor advanced **5/14** and `D-HEADER-ROLLBACK` becomes ACTIVE (source `core/headerchain.go:SetHead`, `core/blockchain.go:setHeadBeyondRoot/loadLastState`, `rawdb.ReadCanonicalHash`). The strongest counterexample is local/admin `SetHead` authorization and consistent rollback/canonical checks; no attacker-controlled validator history manipulation has been proven. Next fixture: restart a locally canonical synthetic blockchain after rewind; assert retained canonical ancestry, removal of stale higher hashes and rejection of malformed ancestry.
- **Security disclosure:** no new confirmed attacker-reachable vulnerability. Prior E-class conditional software defects remain in the R candidate ledger; A–E work untouched.
