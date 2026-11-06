# Class D bounded decision — 2026-11-06 18:44 NPT

Lead: HYP-D-003, typed receipt normalization / post-restart association. Decision: DEFERRED/BLOCKED, E1 plus historical queue-only E2, not E3/E4; conditional P3 investigation priority, no CVSS. This is an INTERNAL assessment, not a disclosure.

## New verified observations
- Queried GitHub Actions branch run collection (50 most recent). Most recent class D run 42172102719, original trigger f1673f314c9210e0d6df80f0fe555e29b06cf9bd, status completed, conclusion success. No active D run among returned 50. This is a bounded listing, not proof none exists outside the page.
- Fetched D/LATEST and D/CANDIDATE from audit branch successfully; contract/manifest/certificate/provenance at repository root all returned HTTP 404 (may live elsewhere); immutable certified eth/downloader/downloader.go and core/blockchain.go fetches returned 404. Do not substitute branch/master source for immutable certified bytes.
- Historical certified CI 42172102719 exercised queue-level receipt swap controls; it did not test eth/66 ingress, typed receipt semantic normalization, database persistence or restart. No new target runtime tests were executed, no shell exit codes, no CI dispatched.

## Expected versus observed
Expected: independent trie-root oracle binds honest typed receipt bytes to authenticated header; malformed, swapped or differently normalized receipt bytes cannot persist as canonical receipts, and reopened rawdb preserves the same binding. Observed this invocation: no execution of this scenario. Prior E1 source evidence shows handleReceipts66 locally derives response metadata from same decoded bytes and queue compares against header root. Thus the narrow independently forged metadata route is source-falsified, not a broader E3 proof.

## Strongest counterexample
Production ingress computes metadata from actual packet payload, dispatcher pairs metadata and payload, and queue compares metadata with requested authenticated header ReceiptHash; therefore independently supplied forged queue metadata cannot cross the actual eth/66 boundary. Previous certified queue controls rejected distinct-root swaps. This may entirely prevent the proposed exploit; untested typed normalization does not establish a breach.

## Reachability and impact
A remote sync peer may supply receipt packet bytes, but cannot independently supply derived metadata through normal eth/66 path. No successful malicious packet, canonical divergence, stall, restart inconsistency, quantified affected blocks or funds demonstrated. E4 missing. No CVSS assigned.

## Decision and narrow next action
After repeated unproductive invocations, defer HYP-D-003. Rotate to a distinct highest-value lead only after verified immutable source access or runner execution is available. Single discriminator: certified eth/66 typed-receipt packet fixture, independently computed ordered root, clean control, two boundaries, persistence/reopen, and guard mutation; no broad fuzz. Do not create an external report without three fresh E3 reproductions and E4 remote reachability. Historical source identities from certificate (not verified this invocation): certified commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0, tree de7f3c75a2db7e87a89918f1257820703d5b731e, pinned 3aeb14db0d6384243302f3a025bdff904dc28bf6, archive 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b.
