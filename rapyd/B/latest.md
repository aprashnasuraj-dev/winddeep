# Rapyd / Lane B — Auth, merchant isolation and signing

**Initial status (2026-11-09):** READY FOR PASSIVE/OFFLINE TRIAGE; POLICY_UNVERIFIED FOR LIVE TARGET TESTING. No vulnerability confirmed. No target-facing scans or transactions authorized by this branch.

**Specialization:** Assess documented authorization, merchant-to-merchant isolation, session state and request-signature invariants using public materials and synthetic test credentials only.

**First falsifiable objective:** Find a falsifiable merchant or session authorization trust-boundary hypothesis with an explicitly defined positive/negative owned-fixture contrast.

**First run:** Read shared policy, own ledger and other sanitized lane summaries. Rank THREE non-overlapping objectives, select best, collect source/reachability evidence without active live probing, execute ONLY local positive+negative fixtures, and record the strongest counterexample. If no objective passes G0/G1, retire it rather than claim a bug. Use exact status `NOT_EXECUTED` for target tests, and record one concrete future unblocking step. No private finding ZIP exists at initialization.
