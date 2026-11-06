# B-FUTURE-PREPARE-QUORUM — 2026-11-07 NPT

**Decision: BLOCKED / NOT REPORTABLE. Hypothesized P3–P4 only if measurable availability degradation; no assigned CVSS.**

## Source identity and scope
Immutable certified source object commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` inspected via GitHub connector: `vendor/electroneum-sc/consensus/istanbul/core/backlog.go` blob `e6089fcde59ae8810ea007f4fc5ead2419ca00ad`, `core/handler.go` blob `4deb6cdf1afef94684c750021e264910b7a62f23`, `core/roundchange.go` blob `fe623c4bff604edecd47752d15e252336470e077`. Documented tree SHA `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. **Fresh bootstrap not executed; identity of runtime test environment not certified.**

## Investigation and executed controls
Candidate: a single authenticated faulty validator sends same-sequence PREPARE/COMMIT for rounds 99/100/101 to accumulate future backlog and delay finalization at N=4 F=1. External ingress `handleEncodedMsg` calls `preVerifySignature`, `Decode`, `verifySignaturesWith`, then `handleDecodedMessage`; `addToBacklog` checks validator membership, future window, global/per-validator count and byte caps. Same-sequence PREPARE/COMMIT lack the +15 round cap applied to ROUND-CHANGE. This is a source-level admission asymmetry, not an observed availability violation.

Local `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` failed exit 128 (DNS). Independent *non-target* Go oracle ran: `GO111MODULE=off go test -count=1 -v ./...` exit 0, `TestFourValidatorQuorum`, `TestFaultySenderCannotSupplyHonestVotes`, `TestThreeHonestVotes` all PASS. Oracle tests distinct signer counting and the existence of 3 honest votes, **not ETN-SC consensus runtime**. No certified target test names, log, or CI execution obtained; E2/E3/E4 absent.

## Expected versus observed; strongest counterexample
Expected invariant: 3 honest validators finalize with at most 1 Byzantine validator and eventual delivery. Observed: signed peer ingress and bounded per-sender backlog are present in source; independent oracle confirms three distinct honest signers satisfy a 3-of-4 threshold. No actual handler-level finalization time, CPU, heap or goroutine peak measured. Strongest counterexample is that a faulty sender's backlog is isolated, and its own vote is not required; an adversary cannot turn its own delayed messages into missing honest votes without an additional cross-sender/event-loop effect. That cross-sender effect is unproven. A simple quorum oracle is not proof of liveness under scheduling.

## Next discriminating experiment
Only after verifying no active B Actions run, execute actual certified Go handler/event loop on fresh immutable `WINDEEP_ETN_SOURCE` with four signed validators and deterministic delivery barriers: honest baseline versus one sender's future PREPARE/COMMIT at rounds 99,100,101; compare 1/64/1024 queued inputs, cap rejection, 3 honest finalization, latency and peak goroutines. Require a three-run actual breach and external reachability before any external report. No upstream/other-class files changed.
