# B-FUTURE-SEQUENCE-ROUND-WINDOW — 2026-11-07 05:20 NPT

**Decision: SUSPECTED (E1 source predicate; independent model only), NOT REPORTABLE. Hypothesized P3–P4 conditional on measured availability impact.** This is a distinct branch of the future-window predicate, not a certified consensus-runtime exploit.

## Source identity and mechanism
Immutable certified fork source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, declared subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`. Read `vendor/electroneum-sc/consensus/istanbul/core/backlog.go:withinBacklogFutureWindow` directly at immutable commit through GitHub connector. Fresh bootstrap unavailable: local `git ls-remote` failed DNS, exit 128. The declared tree hash was **not independently recomputed** this run.

For same-sequence ROUND-CHANGE, the source checks `round <= currentRound+15`. For *future-sequence* messages, it checks only `sequence <= currentSequence+32` and does **not** check the round, including ROUND-CHANGE. Thus future-sequence RC at sequence 2 and huge round passes this *window predicate*. This does not establish network admission or eventual consensus processing.

## Executed independent predicate controls (not ETN runtime)
Go 1.23.2; `GO111MODULE=off go test -count=1 -v ./...`; exit 0, four named tests PASS. Standalone Go code transcribed the exact future-window branching, not linked to the certified source; it is an independent model of the branch, not E2.

- `TestRoundChangeBoundary`: current (1,100), same-sequence RC 115 accepted; 116, 2^32, 2^64 rejected.
- `TestFuturePrepareBoundary`: same-sequence PREPARE 116, 2^32, 2^64 accepted by replicated predicate.
- `TestSequenceBoundary`: sequence 0 rejected; 33 accepted; 34 rejected at current sequence 1.
- `TestFutureSequenceHugeRound`: future-sequence RC at 2 and 33, each with rounds 116, 2^32, 2^64 accepted by replicated predicate.

**Observed vs expected:** This predicate asymmetry is real in source. Whether a signed authenticated validator can reach `addToBacklog` with these messages, how decoding handles the large round, whether backlog remains resident, and whether honest finalization slows are all **not tested**.

## Attacker route and strongest counterexample
Potential route: one authenticated Byzantine validator sends future-sequence ROUND-CHANGE with oversized round. This is speculative until signature verification, decoding and event-handler route are executed. Existing per-sender caps (1024 entries, 32 MiB), global caps, validator authentication and eventual three-honest-validator quorum are strong counterexamples to network-wide denial of service. `handleRoundChange` rejects far-future same-sequence rounds when eventually processed, and old entries may be discarded after view changes. No safety breach, irreversible liveness loss, resource metric or quantified economic effect observed.

**E2/E3/E4 absent. No CVSS or external report.** No CI launched; existing runs not cancelled.

## Next discriminating test
One certified signed N=4/F=1 handler fixture: send future-sequence ROUND-CHANGE at (2, 2^64) from one Byzantine validator, compare clean control and (2, 115)/(2, 116) boundary, then advance the honest view to sequence 2. Measure retention/rejection, event-loop delay, three-honest finalization and recovery. If clean progress and caps hold, close this branch as non-impactful.
