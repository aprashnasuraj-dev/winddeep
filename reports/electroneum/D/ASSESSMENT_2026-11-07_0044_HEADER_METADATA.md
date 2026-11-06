# Class D internal assessment — 2026-11-07 00:44 NPT — HYP-D-005

**Decision:** SUSPECTED E1 / conditional P3 only; NOT REPORTABLE. No E2/E3/E4, no CVSS. This is a source-only investigation, not a certified runtime test.

## New immutable-source observation
At certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, `eth/protocols/eth/handlers.go:403-423` computes response metadata hashes directly from decoded headers, not from the original request. `eth/downloader/fetchers.go:30-69` returns that header list and metadata to `fetchHead`. `eth/downloader/downloader.go:704-733` requests by the advertised head hash and checks response length, checkpoint and pivot height, but the inspected caller segment does not explicitly compare `hashes[0]` against the advertised head hash, or verify pivot ancestry against the head. This does **not** prove a remotely exploitable chain rewrite: the actual dispatcher and subsequent header importer may reject malicious data, and the downloader may merely retry or safely resync.

## Expected versus observed / controls
Expected secure behavior: an honest chain-A head/pivot response accepted, sibling-B or wrong-head response rejected before a harmful persistent state change; restart retains oracle-consistent canonical mappings, roots and ancient length. Observed: source-only local comparison absence in the inspected function, **no runtime acceptance or state effect observed**. Honest, malicious, strongest-defense, two boundary variants, independent oracle and three fresh reproductions: NOT EXECUTED. No test command or exit code. No active CI was dispatched or cancelled.

## Source identity and blocker
Immutable source file blobs: handlers.go `31551ed59ac4fceb12c81fe1c74951b6773fa7f5`; fetchers.go (fetched); downloader.go `cca35ccae68806bab377022c48045b4e048d0072`. Certificate metadata supplied previously: tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6`, archive `3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b`. Fresh bootstrap not executed. Root-level contract paths returned 404; earlier class history indicates contracts may reside under `reports/electroneum/`, not yet revalidated in this invocation. No duplicate/CVE conclusion.

## Attacker route and strongest counterexample
Provisional route: a malicious authenticated P2P sync peer returns structurally valid, same-height headers not bound to the advertised head. **Unproven** that response crosses the full header/skeleton/seal validation or changes canonical history. Strongest counterexample: downstream import and ancestor verification detect inconsistent headers; intentional missing-state rewind is not an integrity violation. An isolated absence of a check in `fetchHead` is not E4.

## Next discriminating test
After verifying active D CI and fresh certified bootstrap, run one <=10-minute real eth/66 peer-response test: honest A, same-height sibling B, wrong-head hash, two height boundaries; assert fetchHead response and post-abort/restart canonical hash/root/ancient oracle. If all malicious responses are rejected or safe recovery occurs, mark narrow hypothesis DISPROVEN. Do not dispatch long fuzz.
