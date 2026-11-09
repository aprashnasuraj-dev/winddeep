# Rapyd / Lane D — Checkout, hosted pages and browser trust

**Initial status (2026-11-09):** READY FOR PASSIVE/OFFLINE TRIAGE; POLICY_UNVERIFIED FOR LIVE TARGET TESTING. No vulnerability confirmed. No target-facing scans or transactions authorized by this branch.

**Specialization:** Reason about checkout/verify return URLs, merchant-bound sessions, iframe/origin and authorization flows; no live purchase, verification or other people's identity data.

**First falsifiable objective:** Isolate a hosted-page or browser session binding invariant with local demo positive and negative controls.

**First run:** Read shared policy, own ledger and other sanitized lane summaries. Rank THREE non-overlapping objectives, select best, collect source/reachability evidence without active live probing, execute ONLY local positive+negative fixtures, and record the strongest counterexample. If no objective passes G0/G1, retire it rather than claim a bug. Use exact status `NOT_EXECUTED` for target tests, and record one concrete future unblocking step. No private finding ZIP exists at initialization.
