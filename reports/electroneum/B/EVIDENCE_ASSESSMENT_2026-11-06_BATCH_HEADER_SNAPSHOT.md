# B-BATCH-PARENT-SNAPSHOT — 2026-11-06 16:18 NPT

**Decision: DISPROVEN within the specific hypothesis that batched Backend.VerifyHeaders bypasses parent-snapshot error handling.** No confirmed vulnerability. Hypothetical P1 only for a real invalid-finality outcome; no CVSS assigned.

## New source evidence this invocation
Read immutable certified object `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` via GitHub connector (inspection, not bootstrap):
- `vendor/electroneum-sc/consensus/istanbul/backend/engine.go:65-82`: single `VerifyHeader` delegates to `verifyHeader`, which obtains the parent-height/parent-hash snapshot and **returns the snapshot error** before invoking `EngineForBlockNumber(...).VerifyHeader(..., snap.ValSet)`.
- `backend/engine.go:89-113`: **batch** `VerifyHeaders` iterates `headers`, calling the **same** `sb.verifyHeader(chain, header, headers[:i])`. On first error, it marks `errored=true`, and subsequent results are `consensus.ErrUnknownAncestor`. This directly falsifies a distinct batch-only skip of the parent-snapshot verifier in this entry point.
- `backend/backend.go:262-275`: preliminary `verifyCommitted` returns nil on snapshot retrieval error; it is a different path, not the header verifier.
- `engine/engine.go:386-443`: committed-seal verifier enforces validator membership, signer uniqueness and quorum when invoked.

## Honest / malicious / boundary oracle
Expected in N=4 F=1: 3 distinct current-set signatures pass; 2 current plus 1 removed validator fail; duplicate or outsider fail. If a parent snapshot fails, both single-header and batch-header verification must return an error. **Observed this run:** control-flow proof of error propagation in both entry points; no runtime accept/reject result. Boundary cases: first batch header snapshot error -> error; later batch headers -> ErrUnknownAncestor (source-only). No actual synthetic fixture executed.

## Attacker reachability and strongest counterexample
X1 is an authenticated faulty validator proposing a header after a validator transition. Batch verification's reuse of `sb.verifyHeader` and its error propagation is the strongest counterexample to a batch-specific snapshot bypass. Other import paths remain untested; do not generalize the disproof. The preliminary `verifyCommitted` skip is not sufficient to demonstrate an accepted invalid block.

## Provenance and execution
Documentary certified tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; upstream pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. No fresh immutable WINDEEP_ETN_SOURCE bootstrap. `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git refs/heads/electroneum-sc-master-audit` exit 128: DNS unavailable. GitHub connector immutable source reads succeeded. No Go tests executed; E1 source, E2/E3/E4 absent for this batch-specific question. Root contract/certificate paths at repository root returned 404; do not assert reread. No CI dispatched, rerun or cancelled. Historical Actions 41739785577 is not evidence for batch transition.

## Narrow next action
When a certified source-enabled runner is available, execute `go test -count=1 -v` for a synthetic N=4 F=1 **production block import** transition (current A+B+C vs current A+B+removed E), including missing-snapshot negative control and two boundary variants. Do not repeat this batch-only bypass hypothesis absent new source changes.
