# B-FUTURE-ROUND-WINDOW-BOUNDARY — 2026-11-07 NPT

**Decision: BLOCKED / not reportable.** Hypothetical P3–P4 availability only; E1 source verified, no certified target-runtime E2, no E3/E4. No CVSS or external report.

## Source and ingress
Immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e` (identity from certificate; local bootstrap not executed). `consensus/istanbul/core/backlog.go:withinBacklogFutureWindow` accepts same-sequence PREPARE/COMMIT at any round while bounding ROUND_CHANGE at current+15; `addToBacklog` applies per-validator 1024 entries/32 MiB and global budgets; `processBacklog` isolates each sender and stops on a future head. `core/roundchange.go:handleRoundChange` separately rejects far-future ROUND_CHANGE. `core/handler.go:handleEvents` serializes event processing.

## Fresh executed control (independent oracle, NOT target execution)
Local Go standalone boundary oracle: `GO111MODULE=off go test -count=1 -v ./...` exit **0**, `TestFutureRoundBoundaryOracle` and `TestExtremeRoundOracle` PASS. At current round 100, ROUND_CHANGE 115 accepted and 116 rejected; PREPARE/COMMIT 116 accepted. At 2^32, 2^64, 2^128, ROUND_CHANGE rejected while PREPARE admitted by the copied window predicate. The oracle copies the inspected predicate; it is **not independent confirmation of the target runtime** and is not a proof of vulnerability. Honest and malicious signed-message target controls **not executed**. No latency, finalization, memory or goroutine measurements. Local `git ls-remote` failed DNS, exit 128; bootstrap not run.

## Security decision
Attacker: one authenticated Byzantine validator in N=4,F=1. Observed source-level admission asymmetry may allow bounded future-message storage; no proof of cross-validator delay. Strongest counterexample: 3 honest validators can form quorum; sender-isolated queues and entry/byte caps limit retention; a faulty validator can withhold its own vote anyway. The independent oracle proves only the intended branch behavior, not a violated safety/liveness invariant. **BLOCKED** for lack of certified-runtime handler execution and measurable honest-quorum degradation. Do not submit.

## Next discriminating test
Only after confirming no active Class B CI: execute actual certified `core.handleEncodedMsg`→`addToBacklog`→`processBacklog`→`handleEvents` with signed N=4/F=1 validators, compare 0/1/64/1024 future PREPARE+COMMIT from one faulty validator against clean finalization, and record latency, queue caps, goroutines and timeout recovery. Stop if honest quorum remains unaffected. No new CI dispatched here.
