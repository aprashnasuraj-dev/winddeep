# Rapyd / Lane E — Webhooks, state machines and payment invariants

**Initial status (2026-11-09):** READY FOR PASSIVE/OFFLINE TRIAGE; POLICY_UNVERIFIED FOR LIVE TARGET TESTING. No vulnerability confirmed. No target-facing scans or transactions authorized by this branch.

**Specialization:** Study webhook authentication, idempotency, event ordering, ledger/payment status on synthetic payloads and offline implementations; no live financial transactions.

**First falsifiable objective:** Develop one state-transition invariant whose failure could affect an unauthorized balance or status; do not assume Rapyd's production implementation.

**First run:** Read shared policy, own ledger and other sanitized lane summaries. Rank THREE non-overlapping objectives, select best, collect source/reachability evidence without active live probing, execute ONLY local positive+negative fixtures, and record the strongest counterexample. If no objective passes G0/G1, retire it rather than claim a bug. Use exact status `NOT_EXECUTED` for target tests, and record one concrete future unblocking step. No private finding ZIP exists at initialization.
