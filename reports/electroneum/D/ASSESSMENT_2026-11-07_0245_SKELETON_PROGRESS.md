# Class D internal evidence assessment — 2026-11-07 02:45 NPT

**Lead:** HYP-D-006 — peer-delivered beacon skeleton segment continuity at restart. **Decision:** BLOCKED (E1 only); conditional P3 if externally induced persistent sync unavailability is proven, not a severity assertion. **Reportability:** NO CONFIRMED FINDING IN TESTED SCOPE.

## Source and observed behavior
Read immutable certified source object `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, `vendor/electroneum-sc/eth/downloader/skeleton.go` via GitHub fetch_file, success. Certificate records subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. No fresh bootstrap or executable certified runtime in this invocation.

New distinct path: skeleton.go around lines 792-810 explicitly checks adjacent parent-hash progression and reverts malformed requests. Around lines 592-625 `processNewHead` checks a new head's parent against stored skeleton parent and restarts on mismatch. Around lines 939-956 `processResponse` checks local body and receipt presence when linking a downloaded segment. These are positive *source-level defenses*, not executed controls. The remaining question is whether a response that is internally contiguous but references a stale local body/receipt pair can persist inconsistent skeleton progress across interruption/restart. No such response has been accepted in a target test.

## Expected vs actual, attacker route, counterexample
Expected: honest contiguous segment advances skeleton; malformed adjacent parent linkage is rejected; stale-but-contiguous sibling segment must not cause canonical corruption or unrecoverable stall after restart. Actual: only static source checks, **zero** Go test executions and no measured restart effect. Hypothesized actor is an untrusted sync peer; production ability to control the beacon head or bypass skeleton ancestry and downstream header/finality validation is unverified.

**Strongest counterexample:** explicit adjacent-parent hash progression check, `processNewHead` parent equality, segment restart, and downstream consensus/header checks may defeat the proposed stale-sibling input. Local body/receipt existence is not proof of accepted canonical history. Safe resync is not a vulnerability.

## Evidence and missing proof
Read four contract/certificate files from `reports/electroneum/` successfully; earlier root-path 404 is a path error, not lost provenance. No shell/Go commands executed; exit codes not applicable. No honest/malicious/boundary controls or independent oracle executed; no 3 fresh-state reproductions, no E2/E3/E4, no CVSS. Prior receipt CI 42172102719 is unrelated. No external report created.

**Next single discriminator:** certified-runtime synthetic skeleton fixture with honest chain A, internally contiguous stale sibling B, broken adjacent-parent boundary and a restart; independently compare skeleton subchain tail/next, canonical hashes, body/receipt roots and progress after reopening. Stop if existing ancestry checks reject sibling or restart recovers safely. No broad fuzzing.
