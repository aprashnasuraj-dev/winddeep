# Class D — 2026-11-06 23:44 NPT — HYP-D-005 request-binding boundary

**Decision:** SUSPECTED (E1), not reportable. Conditional P3 if a remotely induced persistent stall is ever demonstrated; no CVSS assigned. No new target-runtime execution.

## Source and observed behavior
Immutable certified source object `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0` inspected by GitHub connector (not freshly bootstrapped). Historical certificate tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Files: `vendor/electroneum-sc/eth/protocols/eth/dispatcher.go`, `eth/downloader/fetchers.go` and `eth/downloader/downloader.go`.

The dispatcher matches a response to a pending request ID and expected packet type, decodes and delivers it; these checks alone do **not** bind header payload hashes to the originally requested head hash. The downloader's `fetchHeadersByHash` acknowledges delivery without local header ancestry validation, explicitly deferring bad-packet handling to the caller. `fetchHead` requests two reverse headers starting at the advertised head hash and checks response length and pivot-number offset, but the inspected `fetchHead` lines do not explicitly compare returned first header hash to the advertised hash, nor prove second header is its ancestor. **This is a cross-component validation question, not a demonstrated bypass.** The actual peer metadata construction and downstream import/ancestor verification remain unresolved.

## Controls and threat boundary
Expected honest control: A head and its genuine 64-block ancestor pass, with canonical history unchanged. Expected adversarial control: same-height sibling B, or unrelated first header with correct request ID and response type, must be rejected before any harmful persisted effect. Boundaries: head height 64 versus 65, and pivot at offset 63 versus 64. **None executed.** No Go command or exit code; no independent oracle, fresh-state triplicate, database reopen, or measured impact. Prior CI 42172102719 is receipt-queue-only, not applicable. Recent branch Actions first 50 contained no active D run; historical last D run 42172102719 completed.

Strongest counterexample: request-tracker metadata may detect mismatched header hashes; the downloader's subsequent header chain, ancestor, seal and import checks may reject malicious siblings before security-relevant mutation. Even a persisted pivot followed by missing-state rewind may be safe recovery. There is no evidence of canonical or finalized rewrite, persistent stall or financial harm.

## Next discriminating test
First inspect `eth/protocols/eth/handlers.go` header-response metadata producer and downloader `findAncestor`/header import; then run one <=10-minute certified scratch Go test through the real response dispatch path with honest A, same-height sibling B, incorrect-first-hash, and the two height boundaries. Assert actual header/pivot acceptance and independent hash oracle. Only if an adversarial response survives proceed to interrupted import/restart. No broad fuzz, no external report.
