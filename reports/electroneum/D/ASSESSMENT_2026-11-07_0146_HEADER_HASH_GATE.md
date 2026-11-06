# Class D internal assessment — 2026-11-07 01:46 NPT

**Lead:** HYP-D-005. **Decision:** DEFERRED/BLOCKED after repeated source-only invocations. **Evidence:** E1 only. **Conditional priority:** P3 if peer-controlled persistent sync stall is demonstrated; no CVSS or reportable vulnerability.

## Exact source and new check
Read immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` through GitHub connector, without a fresh bootstrap. Historical certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.

New cross-component inspection: `eth/downloader/downloader.go:692-735` obtains advertised peer head hash and calls `fetchHeadersByHash` with reverse traversal; it validates length, checkpoint and pivot height but has no explicit comparison `headers[0].Hash() == latest` in that function. `eth/downloader/fetchers.go:30-69` delivers peer headers and their metadata without semantic binding locally. `eth/protocols/eth/handlers.go:403-423` computes metadata hashes from the received header objects, not independently from requested head hash. This is a **source-level missing local comparison**, not evidence of acceptance by the full downloader or of any security impact. The comment claiming the first header is validated is not a substitute for runtime proof.

## Expected vs observed and falsification
Expected: a peer returning a sibling-chain head or wrong-head response to a head-hash request cannot cause invalid canonical writes, pivot-induced persistent stall or finalized rewrite. Observed: only source-level component behavior above; **no network-to-canonical execution**. Strongest counterexample: downstream header ancestry/seal verification and request-tracking may reject inconsistent responses; a missing-state rewind to genesis may be legitimate recovery. No claim that a peer can bypass these defenses.

Honest chain A, same-height valid sibling B, wrong advertised-head hash, offset -1/+1, interruption, restart, independent oracle and three fresh reproductions: **NOT EXECUTED**. No Go command or exit code, no current-run CI dispatch, no measured availability/correctness impact. Historical receipt-only CI run 42172102719 is not evidence for this lead.

## Decision and next discriminating action
HYP-D-005 **DEFERRED/BLOCKED**, not disproven and not reportable. Stop repeating static inspection. Only reopen on a certified-runner <=10-minute test that drives real `fetchHead`/request dispatcher with honest A, sibling B and wrong-head response and proves whether wrong hash reaches persisted pivot. If rejected, mark this specific ingress route DISPROVEN. If accepted, verify actual restart and canonical integrity before severity or report creation. Rotate now to a genuinely distinct highest-score lead if the certified runner cannot be used.
