# B-BACKLOG-PRIORITY-COLLISION — 2026-11-06 21:19 NPT

Decision: **SUSPECTED arithmetic alias, NOT CONFIRMED security weakness**. Hypothetical P3 only if an authenticated faulty validator can measurably delay honest finalization. No CVSS, no external report.

## Certified source and actual work

Immutable source connector read: `vendor/electroneum-sc/consensus/istanbul/core/backlog.go` at certified commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, blob `e6089fcde59ae8810ea007f4fc5ead2419ca00ad`. Documented certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`; fresh bootstrap **not executed**.

Actual local command: `go run /tmp/priority_oracle.go` exited **0** with Go **1.23.2**. The scratch oracle copied only the isolated arithmetic expression from `toPriority`; it is **not an ETN-SC runtime test**, is not a production handler, and supplies **no E2**.

| Sequence | Round | Synthetic PREPARE priority (code=2) |
|---:|---:|---:|
| 1 | 99 | -1992 |
| 1 | 100 | -2002 |
| 1 | 101 | -2012 |
| 2 | 0 | -2002 |
| 1 | 4294967296 | -42949673962 |
| 1 | 18446744073709551616 | -1002 |

Observed: the fixed 1000-per-sequence arithmetic causes a **priority key collision** between (sequence 1, round 100) and (sequence 2, round 0), while Uint64 narrowing aliases extreme rounds. Expected if keys were globally unique: distinct keys; actual source expression does not guarantee that. This is a priority scheduling property, not a quorum/safety breach. The 2^64 input is a synthetic arithmetic boundary, **not proven accepted at ingress**.

## Reachability and counterexamples

Attacker X1: one authenticated faulty validator in N=4,F=1. `withinBacklogFutureWindow` limits future sequence to current+32 and same-sequence ROUND_CHANGE to current+15; `addToBacklog` checks membership, count and byte caps; `processBacklog` rechecks `checkMessage` and breaks on a still-future message **per sender**, continuing the outer sender iteration. Therefore key collision does not by itself cause cross-validator starvation. An honest 3/4 quorum can progress independently under eventual delivery. No actual delay, queue-order change, memory growth, or finality error observed. The full signed event-loop is necessary to distinguish harmless ordering alias from a measurable liveness degradation.

## Evidence bar and next discriminator

E1 verified source expression and local independent arithmetic oracle. E2/E3/E4 absent. Local `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` failed with DNS error, exit **128**. No certified Go target tests, no CI launch, no mutation control, no three-run reproduction, no CVSS. Source-only duplicate review incomplete. The best defense is per-sender queue isolation plus eventual 3/4 quorum. Next: run one certified N=4 F=1 actual backlog handler fixture at rounds 99/100/101 comparing honest finalization latency with one faulty validator; test priority collision against the independent exact-view oracle. If no measurable excess latency, DISPROVE liveness impact and defer arithmetic alias.
