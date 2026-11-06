# Class D internal evidence assessment — 2026-11-07 03:44 NPT

**Lead:** HYP-D-006 — internally contiguous stale sibling skeleton segment. **Decision:** DISPROVEN within the narrow source-level assumption that internal parent continuity alone suffices for storage; broader restart impact remains BLOCKED (E1). **Reportability:** NO CONFIRMED FINDING IN TESTED SCOPE. Hypothetical P3 availability impact only; no CVSS because no E2.

## Identity and scope
Read the immutable certified source object at `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` using GitHub fetch_file. Historical certified subtree `de7f3c75a2db7e87a89918f1257820703d5b731e`; pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive SHA-256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Certificate read from `reports/electroneum/`. No fresh bootstrap or certified-runtime execution; historical provenance is not fresh execution proof.

## One completed source-level falsification
`eth/downloader/skeleton.go:770-825` checks response count, requested height, and adjacent parent-hash progression. Crucially `eth/downloader/skeleton.go:910-929` then checks `s.progress.Subchains[0].Next != s.scratchSpace[0].Hash()` **before** the batch is stored. On mismatch, it clears scratch space, drops the responding peer and exits the batch loop. Therefore an internally contiguous sibling B whose first delivered hash differs from the expected chain-A `Next` does not satisfy the actual storage gate. This falsifies the specific proposed bypass by merely satisfying internal parent continuity, as a source-code implication, not an executed test.

`skeleton.go:592-625` additionally restarts when a new head is forked/gapped; `:939-956` checks local body/receipt existence for linking. A stale sibling with a matching boundary hash is not the distinct sibling hypothesized at that boundary; any later divergence would need a different, proven mechanism. Local body/receipt existence alone is not proof of canonical adoption.

## Controls, reachability, uncertainty
Expected honest A: contiguous reverse headers and first hash equal to `Next` can proceed to storage. Expected stale B: internal parent continuity but first hash unequal to `Next` is rejected and peer dropped. Expected invalid-parent B: rejected by adjacent progression. These are source-derived expected outcomes, **not observed runtime outcomes**. No honest/malicious/boundary Go controls, independent oracle, three repetitions, restart, or quantified availability impact executed. No command exit codes exist (connector fetches succeeded). Peer-sourced headers are plausible ingress, but production attacker control over the beacon head and finality remains unverified.

**Strongest counterexample to vulnerability:** the exact `Next`-hash gate prevents the stale-sibling batch from being stored even if its internal chain is valid. Rejected peer and safe restart do not imply permanent sync stall. No canonical rewrite observed.

## Decision and next discriminator
Close the narrow internally-contiguous-only bypass as **DISPROVEN at source level**. Keep any distinct interruption/restart hypothesis BLOCKED, not promoted. If runtime capacity is available, run one <=10-minute certified fixture with honest A, stale sibling B, bad-parent boundary, interrupted restart and independent reopened canonical/head oracle. Otherwise rotate to a distinct higher-EV externally reachable lead. No external report; no peer handoff justified.
