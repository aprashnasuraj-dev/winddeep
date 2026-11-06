# C-003 evidence assessment — 2026-11-06 07:27 NPT

**Decision: SUSPECTED / NOT REPORTABLE; E1 source-only. SIMULATION_NOT_EXECUTED.** Hypothesis: signer-context cache or priority-signature hash disagreement could permit an unauthorized sender or priority-key substitution. Actor Y0 (submitted signed transaction); invariant W1/W2/W10. No victim loss, signature substitution or unauthorized transfer observed.

## Actual source observation
Pinned immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, expected tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; upstream identity `3aeb14db0d6384243302f3a025bdff904dc28bf6`; archive provenance `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. These are certificate values, NOT freshly bootstrap-verified in this invocation.

`core/types/transaction_signing.go:187-207`: `Sender` reuses cache only when cached signer `Equal` current signer, otherwise recalculates. `:209-225`: `PrioritySender` likewise keys cached public key to signer. `:48-63`: `MakeSigner` selects future-fork signer based on block configuration. `:342-347`: London `PriorityHash` intentionally equals body hash. `:352-426`: future-fork `PriorityHash` includes sender V/R/S and future-fork `PrioritySender` recovers using this hash. `:285-307`: London `PrioritySender` uses body hash. This is a fork-dependent intentional distinction, not a demonstrated inconsistent verifier.

## Competing explanations and counterexample
H1: cache equivalence or fork transition permits wrong sender to be reused. H2: signer equality separates fork contexts and cache invalidation is correct. H3: priority key signed under one fork hash is incorrectly accepted under the other. Strongest source counterexample: `futureForkSigner.Equal` only accepts the future-fork type, `londonSigner.Equal` only accepts London type; sender and priority caches rederive when signer differs. PriorityHash and PrioritySender pair consistently within each signer. No confirmed breach.

## Observed versus expected and execution limits
Expected: no unauthorized sender/priority key under a fork transition; wrong chain and changed sender signature rejected. Observed this run: only source reads; no transactions submitted to pool, no state transition, no balances, no independent oracle, no mutation sensitivity. Local `git -C /mnt/data rev-parse --show-toplevel` exited 128 (not a Git repository). `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` exited 128 (DNS failure). Certified bootstrap NOT RUN; Go tests NOT RUN; executed target tests 0. Historical CI results are not current execution. No CI dispatched or interrupted.

**Missing E2/E3/E4:** certified scratch test with two synthetic signers, before/after future-fork block, same transaction queried under both signers, wrong-chain and modified priority signature; independently calculate expected sender and priority key, assert pool and execution agreement; weaken cache-key equality in scratch and show detection. Trace actual production fork height before asserting reachability. If all guards hold, DISPROVE only this scoped cache-crossing hypothesis.

**Reportability:** NO CONFIRMED FINDING. External confirmed-only report unchanged.


## 2026-11-06 08:29 NPT — focused follow-up decision (no new runtime test)

**Decision: BLOCKED for certified-runtime confirmation; C-003 remains SUSPECTED only as an untested hypothesis, E1.** This is the second consecutive C-003 invocation without a certified executable test; defer further source-only cache analysis. Do not interpret BLOCKED as evidence of vulnerability.

**New source-grounded distinction:** pinned `core/types/transaction_signing.go:343-346` makes pre-fork `londonSigner.PriorityHash` body-only; `:352-426` makes future-fork `PriorityHash` sender-signature-bound, and `:428-431` makes future-fork signer equality type-sensitive. The pre-fork signature is therefore not cryptographically bound to sender V/R/S by its priority-signing hash; whether any attacker can reuse it to cause a victim-funded transfer or unauthorized priority privilege depends on production priority authorization/fee semantics, which were not established. In particular, changing sender V/R/S still requires a separately valid sender signature; this is the strongest defeating control against *unauthorized sender* theft. This is a narrowly scoped protocol design observation, **not** a confirmed vulnerability.

**Competing explanations:** H1 pre-fork priority-signature portability is an intentional permitted mechanism without victim loss; H2 a priority signer can be reused with an independently authorized sender, but only with their own funds; H3 a reachable authorization/fee path wrongly attributes victim costs or privileges to the priority key. Cheapest discriminating experiment: certified synthetic PriorityTx signed by two distinct sender accounts, one priority key; replay identical priority signature across sender signatures before and after configured FutureForkBlock; inspect actual fee payer/balance transition and reject/accept reasons, independently assert ledger and signer identities. Include altered chain ID, invalid priority signature, and a scratch-only weakened check. Do not infer monetary harm from cryptographic portability alone.

**Actual current-run operations:** GitHub connector immutable-source `fetch_file` success; original trigger SHAs `af08182474bcdba4dc1406009e3147b432aa4d56` and `6d3d1f0f2e57e1735cb064773f4792daf3b0feaa` still report historical `security-audit/C:success` for runs 42096715181 / 42096702516. Local `git rev-parse --show-toplevel` exit 128 (no checkout); `git ls-remote https://github.com/aprashnasuraj-dev/winddeep.git HEAD` exit 128 (DNS). Bootstrap NOT RUN, no `WINDEEP_ETN_SOURCE` path, Go tests 0, oracle/mutation 0, no new CI dispatched. Full active-run enumeration unavailable. No source mutation or peer-file writes.

**Required certificate identities, not freshly validated:** commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`; tree `de7f3c75a2db7e87a89918f1257820703d5b731e`; pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`; provenance archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`.

**Reportability:** NO CONFIRMED FINDING. E2/E3/E4 missing. C-003 DEFERRED pending a verified runtime. Next distinct lead: C-004, trace whether pre-fork priority signatures have any independently exploitable authorization or fee-payer consequence; otherwise close as expected cryptographic scheme. No external report change.
