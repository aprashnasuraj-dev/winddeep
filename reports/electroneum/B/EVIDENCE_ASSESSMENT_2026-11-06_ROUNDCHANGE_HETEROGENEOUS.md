# 2026-11-06 — B-ROUNDCHANGE-HETEROGENEOUS-QUORUM

Decision: DISPROVEN for the specific hypothesis that one Byzantine validator can aggregate distinct far-future ROUND-CHANGE rounds to trigger F+1 round advancement. Hypothetical P1/P2 only if an actual safety/liveness breach; none observed. Evidence E1 only.

Certified immutable source read: 7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0 (declared tree de7f3c75a2db7e87a89918f1257820703d5b731e; no fresh bootstrap verification). Files: vendor/electroneum-sc/consensus/istanbul/core/roundchange.go and core/backlog.go.

New executed checks this invocation: seven JavaScript assertions against returned exact-revision source text, 7/7 true (source checks, NOT Go tests). Direct handleRoundChange rejects round > current+15; backlog admission also rejects same-sequence ROUND_CHANGE above current+15. MinRoundAboveWithAtLeast counts each distinct round's message set separately, requiring F+1 for one round; sorting chooses the minimum qualifying higher round. Under N=4,F=1, F+1=2; one Byzantine signer across many distinct rounds cannot independently reach 2 signatures for any one round. This falsifies the distinct-round aggregation mechanism in this source path, not every liveness attack.

Expected honest control: 2 distinct authorized signers supporting the same next round may advance, subject to message authentication and other protocol guards. Negative input: one authorized signer across rounds current+1/current+2/current+15 cannot satisfy the per-round F+1 threshold. Boundary: current+16 rejected by direct and backlog checks. These are SOURCE-DERIVED expectations, not executed signed-message observations. No actual runtime output or Go exit code. No certified runtime E2, three reproductions E3 or external reachability impact E4.

Strongest counterexample to a broader safety claim: the 64-bit map key and big.NewInt(int64(k)) narrowing remain possible at extreme round values; proving those values reachable through authenticated bounded progress is outstanding. Another separate avenue is same-sequence future PREPARE/COMMIT admission. No CVSS assigned.

Next discriminating test: certified Go N=4/F=1 signed event-loop fixture with two distinct honest ROUND_CHANGE messages at r+1 (positive), one Byzantine at r+1/r+2/r+15 (negative), and r+16 rejection (boundary); verify finalization and recovery after timeouts. No external report.
