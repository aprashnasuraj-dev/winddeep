# Class D assessment — 2026-11-07 05:44 NPT — HYP-D-008

**Decision: BLOCKED (E1 source observation only); NO CONFIRMED FINDING.** Conditional P3 if a remote peer can force a durable incorrect canonical-header mapping or persistent sync stall; no CVSS without E2. Do not submit.

## Source identity and scope
Immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`; provenance archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Identity read from certificate and immutable Git file; fresh bootstrap **NOT executed**.

## Investigation: header reorganization write boundary
Read `vendor/electroneum-sc/core/headerchain.go:130-224` from immutable source. `HeaderChain.Reorg` constructs a batch, deletes canonical-number assignments above a new head, walks backward over a sibling branch until a canonical cross-link, requires each missing parent via `GetHeader`, writes new canonical mappings and head-header hash, commits the batch, then updates the in-memory header head. `WriteHeaders` requires known parent total difficulty and explicitly assumes input headers were validated and contiguous before invocation. These are trusted internal methods; neither is a direct peer ingress.

**Candidate invariant:** an untrusted peer must not cause `Reorg` to receive unvalidated sibling headers or leave persisted canonical mappings inconsistent after interruption/restart. The source excerpt shows a database-batch atomicity guard and missing-parent rejection, but cannot prove upstream caller validation or crash behavior.

**Honest control (expected, NOT EXECUTED):** valid sibling B with validated ancestry and permitted fork choice updates canonical mapping consistently. **Malicious control (expected, NOT EXECUTED):** same-height sibling B lacking a required parent or failing header validation is rejected without head change. **Boundaries (NOT EXECUTED):** sibling at genesis-adjacent height; sibling whose last height is below the current head. **Independent oracle (NOT EXECUTED):** reopen DB and independently walk canonical hashes and ParentHash links, compare head header and state/ancient boundaries.

**Strongest counterexample:** callers validate and order headers before `Reorg`, missing parents abort before batch write, and the database batch prevents partial canonical-number updates. A legitimate fork-choice reorg is not an attacker-driven finalized rewrite.

## Execution record and decision
GitHub connector `fetch_file` for four contract/certificate files under `reports/electroneum/`, D LATEST and register, and immutable `core/headerchain.go` succeeded; root-level contract paths returned 404 (actual paths nested). GitHub Actions runs API read succeeded; no Class D run appeared among latest 40 returned (not exhaustive). No shell command, Go test, runtime bootstrap, adversarial fixture, three-run proof, independent oracle or local process exit code. No CI dispatched/cancelled. No duplicate conclusion asserted. No evidence of a remote actor controlling `Reorg` inputs past validation. Evidence grade E1 only; status BLOCKED, not DISPROVEN globally.

**Next discriminating test:** in one certified-source scratch runtime, execute a single `HeaderChain.Reorg` fixture with valid A/B headers and a missing-parent B variant; verify unchanged canonical mappings on error and reopen DB. This only establishes an internal control, not reportability. Do not return to source-only analysis of this lead after two unproductive invocations; prioritize a peer-to-caller validation trace or another externally reachable candidate.

No external vulnerability report created.