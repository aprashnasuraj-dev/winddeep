# B-SAME-SEQUENCE-FUTURE-PREPARE — queue-isolation falsification assessment (2026-11-06 09:23 NPT)

**Decision: SUSPECTED E1; SIMULATION_NOT_EXECUTED; not reportable.** This is a narrow source-path assessment, not a runtime disproof. Adversary X1: one authenticated Byzantine validator of N=4, F=1, eventual delivery among three honest validators. Invariant F8: no persistent chain stall caused by one faulty validator.

## Verified source observations (immutable certified Git revision 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0)
- `consensus/istanbul/core/backlog.go:197-214`: same-sequence future PREPARE/COMMIT pass the round-window predicate, unlike ROUND_CHANGE. This does not mean they are immediately processed.
- `backlog.go:338-416`: `processBacklog` iterates separately over each source-address queue. On an entry still classified as future by `checkMessage`, it conditionally requeues and **breaks only the inner loop for that source**, not the outer loop over validators. This materially weakens the hypothesis that one high-priority Byzantine entry blocks every honest validator's backlog.
- `backlog.go:374-408`: actual delivery is asynchronous (`go c.sendEvent(event)`); source-order and event-arrival order are not equivalent.
- `core/handler.go:103-174`: the event loop serializes state changes and calls `handleDecodedMessage` on backlog events; a real latency claim must measure the event loop, not infer it from queue ordering.
- `core/roundchange.go:113-145`: far-future ROUND_CHANGE is rejected before entering round-change set, independent of backlog admission.
- `backlog.go:187-193,347-355`: membership is checked for backlog source, and an obsolete validator's queue is removed during processing.

## Competing explanations / decisive observation
H1: one Byzantine validator can block only its own backlog; the honest 3/4 quorum still progresses. Source code supports isolation but cannot prove timely event delivery. H2: repeated valid authenticated future messages cause measurable event-loop or memory pressure despite per-validator queue isolation. H3: apparent starvation is an artifact of scheduling an unrealistic fixture.

**Expected under protocol:** honest 3/4 finalize under eventual delivery, bounded backlog memory. **Observed this invocation:** only E1 control-flow behavior; no authenticated fixture, no finalization count, latency, heap, goroutine count, event count or mutation-sensitivity result. **Strongest counterexample:** the inner-loop-only `break`, separate validator queues, cap checks and the independent round-change guard. No confirmed liveness or finality breach.

## Execution / identity
Certification documentary identity: source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream pin `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. No fresh bootstrap or Go execution. Local `pwd` exit 0 (/) ; `git status -sb` exit 128 (not repository); `git ls-remote ... refs/heads/electroneum-sc-master-audit` exit 128 (DNS resolution failure). GitHub immutable-object source reads succeeded; commit status checks for `6513f031` and `699e17e3` returned empty arrays, so current active CI inventory is UNKNOWN. No dispatch, cancellation or modification of other workers' files.

**Next discriminating experiment:** on an authorized certified runner, execute a signed N=4 F=1 fixture through actual `handleEncodedMsg`/backlog/event loop with honest quorum baseline, one faulty validator injecting same-sequence future PREPARE and COMMIT at 99/100/101, and matching ROUND_CHANGE controls; assert 3/4 finalization with barrier-counted events and memory/goroutine measurements. Include a scratch-only weakened queue-isolation mutant to demonstrate detection. No broad fuzz campaign.