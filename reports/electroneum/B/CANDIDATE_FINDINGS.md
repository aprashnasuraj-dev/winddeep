# Worker B — Evidence-backed candidate findings

## B-ROUND-SEAL-DOMAIN — round truncation in QBFT committed-seal signing domain

- **Status:** OPEN / NOT CONFIRMED. **Severity if proven:** potentially HIGH for consensus liveness or finality, but actual severity is unknown. **Confidence:** HIGH that a 32-bit narrowing exists; LOW that a Byzantine actor can exploit it under shipped consensus limits.
- **Immutable certified source:** Windeep `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`. [engine.go lines 61–66, 101–105, 580–606, 630–634](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/consensus/istanbul/engine/engine.go); [roundchange.go](https://github.com/aprashnasuraj-dev/winddeep/blob/7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0/vendor/electroneum-sc/consensus/istanbul/core/roundchange.go).
- **Attacker prerequisites / boundary:** Byzantine authenticated validator(s) capable of contributing valid round-change/commit messages; must induce an accepted round >= 2^32 for the same sequence, under F+1/quorum and future-round admission limits. Unauthenticated outsider cannot simply set the header round and finalize it.
- **Suspected invariant:** committed-seal signing domain should distinguish every round the consensus state machine can accept. `writeRoundNumber` casts `round.Uint64()` to `uint32`; `Signers` recovers over `PrepareCommittedSeal(header, extra.Round)`, which calls `QBFTHashWithRoundNumber(uint32)`. This creates an apparent encoding/signature-domain collision between 0 and 2^32 on otherwise equal header data.
- **Observed evidence:** exact immutable source function bodies and types inspected via connected GitHub file reads. **Not observed:** actual runtime collision test, reachable high-round progression, signature replay acceptance, invalid finality or liveness harm. No security vulnerability confirmed.
- **Strongest defeating control:** `handleRoundChange` limits future round to current + `MaxFutureRoundGap`; authenticated round-change messages and quorum are required. This may make high-round collision infeasible within a single block height.
- **Exact safe decision experiment:** after the currently active B campaign finishes, run Go scratch fixture against freshly bootstrapped `WINDEEP_ETN_SOURCE`: construct two otherwise identical synthetic headers and call actual `PrepareCommittedSeal` at 0 and 2^32; compare with independent full-width domain oracle and deliberate 32-bit weakened oracle; then exercise actual signed round-change admission and verify whether the high round can be reached. Record outputs, controls and exit codes; classify arithmetic collision separately from attacker-reachable exploit.
- **Potential consequence if reachable:** reuse/confusion of committed-seal authority across distinct round states, possibly harming finality/liveness. This is inference, not demonstrated impact.
- **Next action:** await active Actions run 41636770711 and inspect full logs; then implement target-runtime round-domain fixture without overlapping the active campaign.

## B-SAME-SEQUENCE-FUTURE-PREPARE — 2026-11-06 08:24 NPT assessment
- **Decision:** SUSPECTED E1, SIMULATION_NOT_EXECUTED; NOT reportable. X1 authenticated faulty validator, N=4, F=1, eventual honest delivery. No demonstrated unauthorized finalization or permanent stall.
- **Certified immutable source inspected:** commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree identity documented `de7f3c75a2db7e87a89918f1257820703d5b731e`; `consensus/istanbul/core/backlog.go:withinBacklogFutureWindow` (approx. lines 197–225) allows same-sequence PREPARE/COMMIT irrespective of round, but caps ROUND_CHANGE at current round + MaxFutureRoundGap. `core/roundchange.go:handleRoundChange` (approx. lines 101–151) independently rejects far-future ROUND_CHANGE before adding to the round-change set. `core/handler.go:handleEvents` (approx. lines 103–175) serializes event handling. These are exact-revision connector source reads, not executed tests.
- **Competing explanations:** (1) authenticated future PREPARE/COMMIT inputs are safely bounded by backlog budgets and cannot impede 3 honest validators; (2) repeated valid high-round messages monopolize event handling enough to measurably delay quorum despite finite queue budgets; (3) any apparent delay is an unrealistic scheduler/mocked-backend artifact. The direct ROUND_CHANGE route is explicitly bounded, the strongest code-level counterexample to arbitrary high-round progression.
- **Expected vs observed:** expected under attack is honest 3/4 eventual finalization with bounded resource use; actual finalization, latency, heap, goroutines, message counts and mutation sensitivity **not measured**. Only the source-level admission asymmetry was observed. E2/E3/E4 missing. No production-reachable security impact established.
- **Next discriminating test:** once no active class CI is verified, use fresh certified bootstrap and actual Go handler/event loop with signed N=4/F=1 messages; compare honest baseline with one faulty sender at same-sequence rounds 99/100/101 and 1/64 queued messages, delivery barriers, independent finality oracle and scratch mutant. Do not launch a broad fuzz campaign.

### 2026-11-06 09:23 NPT queue-isolation refinement (E1; SUSPECTED)
- Verified immutable-source `core/backlog.go:338-416`: future-message requeue breaks the **per-sender inner loop** only; the outer iteration continues to other validators' backlogs. This is the strongest source-level counterexample to cross-validator priority starvation, not a runtime proof of liveness.
- `core/handler.go:103-174` asynchronously receives posted backlog events, so a deterministic barrier-counted handler test is still required to distinguish bounded queue isolation from event-loop resource pressure. `core/roundchange.go:113-145` rejects far-future ROUND_CHANGE before set insertion.
- Attacker X1, N=4 F=1, eventual delivery; no malicious accepted finality, stall duration or memory increase measured. **SIMULATION_NOT_EXECUTED**; no E2/E3/E4. Internal assessment: `EVIDENCE_ASSESSMENT_2026-11-06_BACKLOG_QUEUE_ISOLATION.md`.


## B-BACKLOG-ASYNC-FANOUT — 2026-11-06 10:22 NPT
- **Status:** SUSPECTED E1, SIMULATION_NOT_EXECUTED; NOT reportable. **Adversary:** X1 N=4 F=1, authenticated one faulty validator, eventual honest delivery, no full partition.
- **Source:** certified immutable `core/backlog.go:338-416` (`processBacklog` pops eligible entries and spawns `go c.sendEvent(event)` at line 408); `core/handler.go:handleEvents` processes posted events sequentially. Retained per-sender bounds 1024 messages/32 MiB, global 4-validator floor 4096/128 MiB; they do not themselves bound transient spawned goroutines.
- **Competing explanations:** prompt event delivery; bounded transient latency; or persistent liveness loss under authentic state transition. Strongest counterexample: per-sender authentication/caps, three honest validators, eventual event delivery. No finalization delay, heap growth or unbounded goroutines observed.
- **Expected vs actual:** honest 3/4 quorum progress expected; actual only source-level fanout mechanism inspected. No new target Go execution, oracle or mutant. E2–E4 missing. Full assessment: [EVIDENCE_ASSESSMENT_2026-11-06_ASYNC_FANOUT.md](EVIDENCE_ASSESSMENT_2026-11-06_ASYNC_FANOUT.md).
- **Next:** certified N=4 F=1 signed backlog/event fixture with delivery barriers and 1/64/256/1024 queues; measure goroutine peak and finalization against honest control, then kill or escalate.

- **2026-11-06 11:21 decision refinement:** DEFERRED E1 after repeated non-executed investigations. Hypothesized P3–P4 only if a measured availability degradation survives fair-delivery controls; no CVSS because no new E2. Source establishes a conditional upper bound of 1,024 preexisting messages from one faulty sender in one drain (assuming no concurrent re-insertion), not an unbounded burst from a static queue. No new certified-runtime test, no outage. Assessment updated at `EVIDENCE_ASSESSMENT_2026-11-06_ASYNC_FANOUT.md`. Rotate to distinct-validator committed-seal acceptance; reactivate only with source-enabled execution.

## B-COMMITTED-SEAL-DISTINCT-QUORUM — 2026-11-06 12:15 NPT
- **Decision:** SUSPECTED (no observed invariant breach), E1 exact source plus E2 historical certified Go controls, **not reportable**. Hypothesized P1 *only if* an N=4 F=1 safety violation is reproduced. No demonstrated CVSS vector.
- **X0/X1 attacker:** outsider or one faulty validator, N=4, F=1, eventual delivery; must induce acceptance of a block with fewer than 3 distinct members of the correct parent validator set.
- **Historical runtime evidence newly reconciled:** Actions 41739785577 / job 126278100119, original SHA `a8601c5ed0e536ec151f12b3540b77c49fbda61b`, Go 1.24.0, `TestWorkerBActualCommittedSeals` PASS, 13×6 cases including honest, Q−1, duplicate, outsider, oversize and wrong round. These are historical tests; **no fresh Go execution this invocation**.
- **Strongest defense:** certified `engine.go:385-443` copies trusted validator set and `RemoveValidator` consumes each recovered signer exactly once before `ceil(2N/3)` check. A duplicate or outsider cannot increase the counted quorum in that direct verifier path. Source-only reasoning alone is not runtime disproof; historical tests lack dedicated membership-check mutant and validator transition.
- **Unresolved highest-value boundary:** current-set vs previous-set signatures across a real parent-snapshot transition and production header import. Full assessment: `EVIDENCE_ASSESSMENT_2026-11-06_DISTINCT_SEAL_QUORUM.md`. One next test: signed N=4 transition fixture with three current signers accepted, 2 current+1 old rejected, duplicate/outsider controls and scratch membership mutant.


### 2026-11-06 13:17 NPT — B-PARENT-SET-TRANSITION (BLOCKED, E1 fresh / E2 historical isolated only)
- **Hypothetical P1, not assigned.** X1 N=4 F=1, eventual honest delivery. Actual new certified-runtime transition executions: zero. Source-backed parent snapshot path is `backend/engine.go:65-82,514-603,620-710` → `engine/engine.go:385-443`. For height h, header verification uses the h-1 parent-hash snapshot, not candidate-declared validators; `snapApplyHeader` applies majority votes before verifying child h. This is a concrete defeating control for stale-set signer substitution.
- New boundary: `backend/backend.go:258-275` local pre-import `verifyCommitted` returns nil on snapshot lookup failure, but `Backend.verifyHeader` propagates the error; **not** proof of production bypass. Need actual import path and state fixture.
- Independent expected N=4 transition controls: current A+B+C accepted; current A+B+previous E rejected; A+B+B and A+B+outsider rejected. No actual observations for these transition cases. Historical direct verifier controls are not transition proof. Local Git DNS exit 128; fresh bootstrap/test unavailable. Decision **BLOCKED**, E3/E4 absent; no CVSS or external report.
- Internal assessment: `EVIDENCE_ASSESSMENT_2026-11-06_PARENT_SET_TRANSITION.md`. Next: one certified Backend.VerifyHeader and production import transition fixture, with scratch membership mutant.


## B-BATCH-PARENT-SNAPSHOT — 2026-11-06 16:18 NPT
- **Decision: DISPROVEN only for batch-specific bypass of parent-snapshot error propagation**, E1 source, not a general import-path disproof. Hypothetical P1 if actual invalid finalization, but none observed.
- Certified `backend/engine.go:89-113` invokes `sb.verifyHeader` for each batch header, passing preceding headers; `backend/engine.go:69-82` returns snapshot errors before committed-seal verification. Following batch elements receive `ErrUnknownAncestor`. The preliminary `backend/backend.go:262-275` nil-on-snapshot-error behavior does not change that fact.
- X1 authenticated faulty validator N=4 F=1. No Go execution or E2-E4, no CVSS. Assessment: `EVIDENCE_ASSESSMENT_2026-11-06_BATCH_HEADER_SNAPSHOT.md`. Next: real import path N=4 transition fixture, not another batch-only source review.


## B-COMMIT-PRECHECK-IMPORT — 2026-11-06 17:23 NPT
- **Decision BLOCKED; no confirmed P1–P3 vulnerability.** Hypothetical P1 only if invalid finalization is shown; no E2–E4 or CVSS.
- **New executed evidence:** 6/6 deterministic exact-source checks against immutable certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` (JavaScript checks, NOT target-runtime Go). `Backend.Commit` sends matching proposed blocks to `commitCh` after `verifyCommitted`, which skips snapshot lookup failure; ordinary `Backend.verifyHeader` propagates snapshot failure. Distinct signer check consumes each validator once. This establishes a potentially interesting entry-point difference but no bypass.
- **Strongest counterexample:** mandatory parent-snapshot lookup in normal header verification and signer deduplication. No proof that `commitCh` path imports without later verification. Real N=4 transition signature fixtures absent. Full internal assessment: `EVIDENCE_ASSESSMENT_2026-11-06_COMMIT_PRECHECK_IMPORT.md`. Next: trace miner `Seal` and execute certified import fixture; do not recycle source-only checks.


## B-MINER-DIRECT-WRITE — 2026-11-06 18:23 NPT
- **SUSPECTED E1; not reportable.** Hypothetical P1 only if invalid canonical finalization with <=F faulty validators is actually demonstrated. New immutable source trace: `Backend.Commit` -> `commitCh` -> `Seal` result -> `miner/worker.go:resultLoop` -> `BlockChain.WriteBlockAndSetHead` -> `writeBlockAndSetHead`, without explicit header verifier at those inspected wrappers. `verifyCommitted` can return nil on snapshot retrieval failure, but actual attacker-reachable failure after honest quorum is unproven. Strongest counterexample: signed QBFT core quorum and valid proposal validation may preclude malformed seals/failed snapshot state from reaching this route. No certified Go runtime this run; E2/E3/E4 absent. See `EVIDENCE_ASSESSMENT_2026-11-06_MINER_DIRECT_WRITE.md`. Next: real certified N=4 core-to-miner snapshot-failure fixture, honest vs removed signer and duplicate.


## B-MINER-SNAPSHOT-FAILURE-REACHABILITY — 2026-11-06 19:16 NPT
- **DISPROVEN for persistent missing-parent-snapshot normal proposer path (E1); transient post-validation failure remains BLOCKED, not reportable.** Hypothetical P1 only. `Backend.Seal` and `Backend.Verify` require parent snapshot before proposal can be admitted, contradicting the persistent-failure precondition of the suspected direct-write bypass. `handleCommitMsg` verifies authenticated sender/commit seal before quorum. The preliminary `verifyCommitted` does skip checking on snapshot failure, but no attacker-reachable post-validation snapshot loss or invalid canonical write was observed. No fresh Go execution; local Git DNS exit 128. Evidence: `EVIDENCE_ASSESSMENT_2026-11-06_MINER_SNAPSHOT_PREREQUISITE.md`. Next: only test a real reachable transient invalidation; otherwise rotate to distinct stateful round-change message sequencing.


## B-ROUNDCHANGE-HETEROGENEOUS-QUORUM — 2026-11-06 20:24 NPT
- DISPROVEN within exact source path: one authenticated Byzantine validator cannot pool ROUND_CHANGE signatures from different rounds to meet same-round F+1 (N=4 F=1 requires two distinct validators for one round). Direct and backlog round-change ingress cap current+15. Seven new exact-source assertions passed; **no certified Go execution**, no E2–E4, no CVSS, no P1–P3 report.
- Strongest unresolved counterexample: uint64/int64 narrowing at extreme rounds and actual signed message sequencing not tested. Evidence: EVIDENCE_ASSESSMENT_2026-11-06_ROUNDCHANGE_HETEROGENEOUS.md. Next: signed event-loop positive/negative/boundary Go fixture.


## B-BACKLOG-PRIORITY-COLLISION — 2026-11-06 21:19 NPT
- Decision SUSPECTED E1, no reportable P1–P3 weakness; hypothetical P3 only if measurable liveness harm. Exact certified source `vendor/electroneum-sc/consensus/istanbul/core/backlog.go:toPriority` at `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, blob `e6089fcde59ae8810ea007f4fc5ead2419ca00ad`.
- Fresh local standalone Go 1.23.2 arithmetic oracle (NOT ETN runtime) exit 0: priority(seq1,round100,code2) = priority(seq2,round0,code2) = -2002; round 2^64 aliases round 0 due Uint64 narrowing. No signed ingress or finalization tested; E2/E3/E4 absent.
- Strongest counterexample: per-validator backlog isolation, authenticated admission, future-window and capacity limits; 3 honest validators can still reach quorum. No observed delay or safety breach. Assessment: `EVIDENCE_ASSESSMENT_2026-11-06_PRIORITY_COLLISION.md`. Next only one certified signed N4/F1 handler fixture at rounds 99/100/101; measure finalization latency versus honest control.


## B-PRIORITY-TIE-HEAD-OF-LINE — 2026-11-06 22:24 NPT
- **Decision SUSPECTED E1 / NOT REPORTABLE**, hypothetical P3 only if actual prolonged finalization is observed. This narrows B-BACKLOG-PRIORITY-COLLISION.
- New standalone Go 1.23.2 arithmetic/heap oracle exit 0: (seq1,round100,COMMIT) and (seq2,round0,COMMIT) tie at -2002, and equal-priority heap order depends on insertion in the simplified oracle; **not target runtime**.
- Strongest falsifier: at current seq2, seq1 round100 is **OLD**, dropped by `checkMessage` and processing continues; at current seq1, seq2 round0 remains FUTURE and cannot yet be an eligible quorum message. Per-validator isolation further limits cross-sender interference. No measured liveness impact, E2–E4 absent.
- Full assessment: `EVIDENCE_ASSESSMENT_2026-11-06_PRIORITY_TIE_FALSIFIER.md`, commit `539c52d0005d67125f4b35fccba0e500b62d8236`. Next one certified actual-prque/processBacklog test for old-vs-eligible ordering, then close if progress is intact.


## B-PRIORITY-TIE-CURRENT-ROUND — 2026-11-06 23:23 NPT
- **SUSPECTED E1, not reportable; conditional P3–P4 only.** Corrected previous overbroad old-message falsifier: at receiver current (seq1,r100), same-sender COMMIT (seq1,r100) is eligible while (seq2,r0) is future; both have priority -2002. A heap tie may allow future-head requeue/break to hold that sender's eligible COMMIT. At receiver seq2 the seq1 message is old, as previously observed.
- New standalone Go 1.23.2 `GO111MODULE=off go test -count=1 -v ./...` **exit 0**, 4 named tests PASS (tie, r99/100/101, 2^64 narrowing, independent 3-of-4 quorum). This is copied arithmetic/oracle only, **NOT certified runtime**; E2–E4 missing. Git DNS exit 128; no new CI.
- **Strongest counterexample:** each sender has an isolated backlog, outer loop proceeds to other validators, and 3 honest validators can finalize without the one Byzantine validator's eligible vote. Delaying one's own COMMIT is not necessarily a stronger attack than withholding it. No measured finalization delay or network harm.
- Assessment: `EVIDENCE_ASSESSMENT_2026-11-06_PRIORITY_TIE_CURRENT_ROUND.md` commit `6af126c32eff8e65bc78c44073b202642d724b55`. Next one certified actual-prque/processBacklog test with both tie insertion orders and 3-honest finality control; close if no excess liveness effect.


## 2026-11-07 00:17 NPT — B-PRIORITY-TIE-CURRENT-ROUND DEFERRED
- Second successive invocation without certified-runtime E2. Source-inspected exact `prque/sstack.go:Less` strict `a>b` tie handling; no guaranteed FIFO or eligible-first tie ordering. `processBacklog` future-head break is sender-local. N=4 F=1 honest 3/4 quorum remains strongest counterexample; no measured stall or unauthorized finalization. P3–P4 only hypothetical, not reportable. Local Git DNS exit 128, no target Go tests. Assessment: `EVIDENCE_ASSESSMENT_2026-11-07_PRIORITY_TIE_DEFERRED.md`.
- Rotation: select distinct authenticated stateful message-sequence hypothesis next, not another arithmetic collision. Reopen this lead only with certified signed actual-prque/handler fixture.

## B-RC-PREPARED-BODY-SUBSTITUTION — 2026-11-07 01:21 NPT
- **Decision:** DISPROVEN within exact shipped decoder source-contract scope, E1 only, not reportable. Hypothetical P1 safety impact was not observed.
- **New work:** 7/7 fresh connected immutable-source assertions passed for `handler.go` pre-verification and `types/roundchange.go:RoundChange.DecodeRLP` digest/header, transaction-root and uncle-root checks. No certified Go runtime execution. Local Git DNS exit 128.
- **Strongest counterexample:** unsigned prepared block body cannot be changed while retaining signed header digest without failing the decoder's transaction/uncle commitment checks; normal empty prepared-block encoding is intentional.
- **Evidence:** `EVIDENCE_ASSESSMENT_2026-11-07_ROUNDCHANGE_PREPARED_BODY.md`, commit `c46edab8587ffa8dd88991ac0b6cc231dccc1f24`. No E2–E4, no invalid finalization, no CVSS.
- **Next:** distinct authenticated stateful QBFT handler fixture on certified runtime, no further source-only iterations on this candidate.


## B-BACKLOG-EVENT-REAUTH — 2026-11-07 02:24 NPT
- **Decision:** DISPROVEN for ordinary external MessageEvent -> authenticated backlog -> internal backlogEvent source path (E1 only); hypothetical P1 if an unauthorized vote were possible, but none observed. No CVSS/E2–E4.
- **New checks:** 8/8 immutable-source contract assertions PASS against `handler.go` and `backlog.go` at certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; no target Go runtime. External message passes `verifySignaturesWith` before `addToBacklog`, which checks source validator membership; internal backlog event is emitted from stored authenticated entry. Skipping redundant verification at internal replay is not an external signature bypass.
- **Strongest counterexample:** a privileged local event-mux injection would be a different trust boundary, not demonstrated peer ingress. N=4/F=1 signed runtime negative controls remain unexecuted. Local Git DNS exit 128; bootstrap not executed; no CI started.
- **Assessment:** `EVIDENCE_ASSESSMENT_2026-11-07_BACKLOG_EVENT_REAUTH.md`, commit `23fd490686f300a87b407d5a2373825eb7d4d024`. Next only if alternate externally reachable event injection is identified; otherwise rotate.

## B-FUTURE-PREPARE-QUORUM — 2026-11-07 03:17 NPT
- **BLOCKED, E1 only; not reportable.** Hypothetical P3–P4, no CVSS. Certified immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` inspected, no fresh bootstrap or target runtime.
- Signed message ingress and validator membership checks precede backlog admission; same-sequence future PREPARE/COMMIT have no +15 round cap but retained messages are bounded by per-sender/global count and bytes. Three honest validators can meet N=4 F=1 quorum without the faulty sender, although event-loop resource interference remains unmeasured.
- Independent Go quorum oracle: 3 tests PASS, exit 0, **not target runtime**; git DNS failed exit 128. No measured finalization or adverse effect, E2–E4 absent. Full assessment: [EVIDENCE_ASSESSMENT_2026-11-07_FUTURE_PREPARE_QUORUM.md](EVIDENCE_ASSESSMENT_2026-11-07_FUTURE_PREPARE_QUORUM.md). Next: certified handler test with deterministic barriers and honest finality control.

## B-FUTURE-ROUND-WINDOW-BOUNDARY — 2026-11-07 04:17 NPT
- **BLOCKED / E1; not reportable**, hypothetical P3–P4. Source: certified `core/backlog.go:withinBacklogFutureWindow` same-sequence PREPARE/COMMIT admits arbitrary round while RC caps at current+15; `addToBacklog` enforces per-sender count/byte limits. Standalone Go predicate oracle (2 tests PASS, exit 0) confirms 115/116 and 2^32/2^64/2^128 boundaries, **not certified runtime**. Strongest defense: three honest validators form quorum, sender-isolated queues, finite budgets. No E2/E3/E4, no finalization latency measured. Assessment: [EVIDENCE_ASSESSMENT_2026-11-07_FUTURE_ROUND_WINDOW_BOUNDARY.md](EVIDENCE_ASSESSMENT_2026-11-07_FUTURE_ROUND_WINDOW_BOUNDARY.md). Next certified signed event-loop experiment only, not fuzz.


## B-FUTURE-SEQUENCE-ROUND-WINDOW — 2026-11-07 05:20 NPT
- **Decision SUSPECTED E1, not reportable; conditional P3–P4.** Source `backlog.go:withinBacklogFutureWindow` checks future sequence <= current+32 but not future round, including ROUND-CHANGE. Same-sequence RC is capped at current round+15. Go 1.23.2 standalone predicate-model tests 4/4 PASS, exit 0, **not certified runtime**. Future-sequence RC at seq 2/33 and round 2^64 accepted by predicate model. Authenticated network ingress, later handler rejection, honest finalization and actual resource cost untested. Strongest counterexample: per-validator 1024/32 MiB cap, signature admission, three honest validators, future-round handler rejection. No E2–E4. See `EVIDENCE_ASSESSMENT_2026-11-07_FUTURE_SEQUENCE_ROUND_WINDOW.md`. Next: certified signed N=4/F=1 future-sequence RC handler fixture, honest finalization and resource measurements.
