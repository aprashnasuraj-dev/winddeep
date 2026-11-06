# Class B assessment — 2026-11-07 00:17 NPT — B-PRIORITY-TIE-CURRENT-ROUND

**Decision: DEFERRED (not confirmed; E1 only).** Hypothetical P3–P4 only if availability impact is reproduced. No CVSS score assigned. This is the second successive investigation of the same scheduling-collision lead without certified runtime execution; rotation is required.

## Source and evidence
Immutable source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, documented certified subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, provenance archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Fresh immutable file reads: `vendor/electroneum-sc/consensus/istanbul/core/backlog.go` blob `e6089fcde59ae8810ea007f4fc5ead2419ca00ad`, `common/prque/prque.go` blob `54c78b5fc2ba1e85ce6bf9ea42e4bc89895abd5a`, `common/prque/sstack.go` (exact immutable revision). Contract, manifest, certificate, provenance read at `reports/electroneum/`.

## Mechanism and decisive limits
At receiver view (sequence 1, round 100), COMMIT(seq=1,r=100) and COMMIT(seq=2,r=0) share priority -2002. `prque.New` uses `newSstack(..., false)`; `sstack.Less` compares priorities using strict `a > b`, so ties have **no guaranteed secondary order**. `processBacklog` pops one entry; a future entry is requeued and breaks the **sender's inner queue only**. The outer loop still visits other validators. This proves that ordering is not guaranteed to favor the eligible message; it does not prove that the future entry actually wins in a production heap configuration, that an attacker can inject messages as another honest validator, or that honest quorum is delayed.

**Strongest counterexample:** With N=4,F=1, the three honest validators can form a 3/4 quorum without the faulty sender. If the only affected queue belongs to the Byzantine validator, holding that sender's eligible vote is no stronger than withholding it. A realistic attack would need to demonstrate honest-sender backlog interference without forgery, or measurable event-loop contention across senders.

## Observed versus expected
Expected: honest 3/4 finalization progresses with one faulty validator; no P1/P2 safety or irreversible liveness breach. Observed this invocation: source reads and comparison of actual `prque` comparator and backlog loop; **zero** certified target-runtime Go tests, **zero** signed message fixture executions, **zero** measured latency, **zero** observed invalid finalizations. Local `go version`: go1.23.2; `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` exit 128 (`Could not resolve host: github.com`). Bootstrap not run; no new CI dispatched. Previous standalone Go oracle was NOT certified runtime and is not upgraded to E2.

## Missing proof / next discriminator
On a certified runner, execute the actual `prque` and `processBacklog` with two insertion orders, signed messages and 4 validators; assert eligible-message delivery, honest 3/4 finalization, and latency under one faulty sender. Include negative invalid/outsider signatures and boundary rounds 99/100/101. If honest finality is unaffected, close the P1–P3 liveness hypothesis within this configuration. Do not submit externally absent E4.
