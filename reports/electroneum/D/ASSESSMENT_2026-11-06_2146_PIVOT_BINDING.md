# Class D internal assessment — 2026-11-06 21:46 NPT

Lead: HYP-D-004 (height-correct sibling pivot versus head-hash-anchored reverse header request). Decision: BLOCKED for runtime confirmation; provisional P3 *only if* external reachability and material sync disruption are later proven. Evidence E1 only; no CVSS or external report.

## Source and observations
Immutable certified source commit 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0, vendor/electroneum-sc/eth/downloader/downloader.go:692-735, blob cca35ccae68806bab377022c48045b4e048d0072, was freshly fetched through GitHub connector. Historical certificate identity: tree de7f3c75a2db7e87a89918f1257820703d5b731e; pinned upstream 3aeb14db0d6384243302f3a025bdff904dc28bf6; archive SHA256 3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b. Fresh bootstrap NOT executed, so runtime equivalence NOT newly established.

Actual source: fetchHead requests head and pivot with fetchHeadersByHash(p, latest, 2, fsMinFullBlocks-1, true); it checks response count, checkpoint, and pivot height difference. The source-level call does not by itself show whether the helper validates each returned header's hash/ancestry against its requested skip traversal. This is the remaining precise trust boundary. The preceding assessment's height-only characterization was incomplete.

Expected malicious control: a height-correct sibling B pivot must be rejected by hash-anchored traversal or subsequent authenticated ancestry/header import, leaving canonical A untouched. Observed: source inspection only; no malicious peer response executed. Honest A, sibling B, two height boundaries, interrupted import, restart, independent oracle and three fresh reproductions NOT executed. No observed canonical map/root/freezer violation and no measured availability impact.

## Strongest counterexample
Hash-anchored reverse traversal and later header/ancestor validation can bind the pivot to the advertised head. A legitimate pivot-number write followed by genesis rewind on missing state may be intentional recovery, not attacker-induced finalized history rewrite. No counterexample has been defeated by runtime evidence.

## Environment and decision
GitHub connector fetch_file succeeded for immutable source; root-level contract paths MASTER_AUDIT_CONTRACT.md, TARGET_MANIFEST.md, TARGET_CERTIFICATE.json, SOURCE_PROVENANCE.json each returned HTTP 404 on the audit branch, so their actual locations/content were not verified in this invocation. Class LATEST and candidate register were readable. No shell/Go test, bootstrap, new CI, test exit code, duplicate search or active CI audit executed; prior run 42172102719 is unrelated receipt-queue evidence. This is the second source-only invocation on HYP-D-004: mark DEFERRED/BLOCKED rather than repeat unsupported claims.

Next single discriminator: locate and inspect actual fetchHeadersByHash response verifier in immutable certified source, then run one <=10-minute certified-runner sibling-pivot response rejection test with honest control; only if sibling passes, proceed to restart oracle. Do not dispatch while class CI active.
