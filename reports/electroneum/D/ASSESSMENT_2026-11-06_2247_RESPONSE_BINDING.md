# Class D assessment — 2026-11-06 22:47 NPT — HYP-D-005 response binding boundary

**Decision:** SUSPECTED E1 / NOT REPORTABLE. Conditional P3 only if a remote-triggered persistent sync stall is later reproduced; no CVSS without certified runtime. This is a distinct narrow question about the blocking response helper, not a claim of history rewrite.

## Source identity and executed work
Immutable certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, provenance archive SHA256 `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. These are certificate/immutable Git read identities, **not a freshly executed bootstrap**.

GitHub connector `fetch_file` succeeded for immutable `eth/downloader/fetchers.go` and `downloader.go`. Root-level contract paths failed 404; correct `reports/electroneum/` paths succeeded. Actions list query succeeded; latest four D runs among 40 most recent were completed (42172102719 success, 42165917465 failure, 42159794013 failure, 42147841161 success); no active D run in that limited listing. No shell or Go test executed; test exit codes N/A; no CI dispatch/cancellation.

## One production-boundary investigation
`eth/downloader/downloader.go:698-732` invokes `fetchHeadersByHash(p, latest, 2, fsMinFullBlocks-1, true)`, checks header count and pivot number offset. `eth/downloader/fetchers.go:30-69` requests peer headers and returns the response headers and metadata; its comment at :63-65 explicitly says it does not reject a bad packet at that layer. It does **not locally verify** the second returned header's ancestry to the first. `downloader.go:513-545` performs ancestor search before persisting the numeric pivot. **Observed:** local helper does not perform an ancestry proof. **Not observed:** whether the dispatcher, request tracker, header importer, or consensus layer rejects a sibling header. Therefore this is a missing check in one helper, **not a proven missing system check**.

Hypothesized attacker: remote sync peer controls returned header bytes and may time an interrupted import. A sibling pivot B with the correct height but wrong ancestor could only matter if earlier response binding and downstream header validation allow it. Security invariant: no attacker-controlled response may produce unauthorized canonical/finalized history or damaging persistent recovery state.

**Controls:** Honest chain A and sibling B, invalid distance, head hash mismatch, and restart were **not executed**. Expected: authenticated request binding rejects unrelated sibling; actual end-to-end outcome unknown. Strongest counterexample: request tracking and subsequent authenticated header/ancestor validation may reject B; a genesis rewind on missing state may be legitimate safe recovery. No E2/E3/E4, no three fresh reproductions, no quantified impact.

**Score before work:** hypothetical P3 × external-peer reachability (unproven) / low source-inspection effort. Deprioritize repeated HYP-D-004, already DEFERRED. Duplicate advisory search not completed, so duplicate status unknown.

**Next single discriminator:** trace `eth/protocols/eth` request tracker/dispatcher for `RequestHeadersByHash` response validation, then one <=10-minute certified-runner A/B peer-response fixture with independent parent-hash oracle. Stop if the tracker rejects B. No external report.
