# D bounded assessment — 2026-11-06 16:44 NPT

**Lead:** HYP-D-002 (deferred); narrowly scoped remote advertised-height / snap-pivot / ancient-limit route. **Decision:** SUSPECTED / BLOCKED for certified-runtime reachability; no confirmed vulnerability. Conditional P3 only if attacker-triggered persistent stall can be reproduced. Evidence E1 public upstream only, not certified runtime E2.

## Observed versus expected
Public Electroneum master `eth/downloader/downloader.go` in `syncWithPeer` obtains legacy `latest,pivot` from `fetchHead`, then runs `findAncestor`; beacon mode instead obtains skeleton bounds and uses `findBeaconAncestor`. In SnapSync it persists `rawdb.WriteLastPivotNumber(d.stateDB,pivotNumber)` before subsequent block import. This ordering makes aborted sync/restart a legitimate investigation target, but is not itself an integrity breach. Public source explicitly comments that a malicious peer can advertise an inflated height to affect ancient-store placement, and documents a checkpoint/height-dependent limit. Neither actual bypass nor certified-source parity was established this invocation.

Expected: invalid advertised heights or unauthenticated ancestry cannot rewrite canonical/finalized history; aborted import may require intentional resync. Observed: public-source control flow only. No execution, independent oracle, honest/hostile chain fixture, restart, canonical-state delta, or three reproductions. No measured financial or availability impact.

## Strongest counterexample and reachability
`fetchHead`, `findAncestor`, beacon skeleton bounds and subsequent header validation may reject or constrain peer-supplied histories. An earlier pivot metadata write can be deliberate rollback bookkeeping, not attacker-controlled history acceptance. The source itself includes an ancient-limit mitigation for malicious advertised heights. Peer-origin is plausible but bypass of validation is **not proven**.

## Commands and provenance
GitHub connector read `https://raw.githubusercontent.com/electroneum/electroneum-sc/master/eth/downloader/downloader.go` successfully (public mutable master; not immutable certified tree). Three certified-commit file reads for `handlers.go`, `dispatcher.go`, `queue.go` returned GitHub 404 in this invocation. No shell commands or Go tests run; no exit codes exist. Historical certified identities (NOT revalidated): source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Prior certified queue CI 42172102719 is unrelated to pivot execution and cannot establish this result.

## Decision and next discriminating experiment
Do not reopen a broad fuzz campaign. Keep HYP-D-002 DEFERRED pending certified runner availability. One narrowly bounded certified-runner experiment: two valid sibling chains with verified headers, honest pivot and adversarial pivot, interrupt after persisted pivot before import, reopen DB, independently compare canonical hashes, state roots and ancient length; include invalid ancestry negative control and two height boundary variants. Require actual peer-path entry and repeat any breach three times. Until then no CVSS, external report or claim of canonical rewrite.
