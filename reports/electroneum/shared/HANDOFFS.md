# Electroneum A–E Cross-Worker Handoffs

Use this file for concise, evidence-linked mechanisms that require another worker's follow-up. Preserve prior entries; append or update status rather than deleting another worker's work.

## 2026-11-07 — B -> D (and B -> E if proven): unverified sync-start miner pause

**Owner B / official upstream security-relevant patch gap; E2 component behavior verified, E3/E4 NOT verified.**

- Official public diff: `electroneum/electroneum-sc` pinned `3aeb14db0d6384243302f3a025bdff904dc28bf6` -> Nov 5 public `db0eb8792dd57304fbc66a60377c7663e1bd44d2`, PR #94. Pinned downloader broadcasts `StartEvent` before verifying remote head and real miner stops; upstream patch waits for `ProgressEvent`. Synthetic real-Go miner and independent pre/post patched oracle passed in [certified Actions 42317769502](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/42317769502), B job `128234543061`.
- **D handoff:** independently verify default actual connected peer/handshake claim of higher TD -> `eth/sync.go:nextSyncOp` (peer minimum, merger/TTD gate) -> `LegacySync` -> actual downloader `StartEvent` vs `fetchHead`, under bounded synthetic ETH66 peers that provide/do not provide the head. Beware that direct event injection alone does not prove network admission. Strong counterexamples: peer handshake validity, minimum peers, fast fail/peer disconnect, TTDReached.
- **B follow-up:** real signed N=4/F=1 IBFT validator network, one and two simulated unavailable validators, time to next finalized block, safe recovery, honest controls. One paused validator does NOT necessarily remove quorum; two unavailable may, depending on actual config and validator count. No claims of P2/P3 without observed external route and availability.
- **E handoff only if B/D prove E3/E4:** check whether affected public default RPC provides incorrect canonical state during a proven availability event. Do not re-run historical E-004 synthetic fee tests.
- INTERNAL detailed evidence: `reports/electroneum/B/ASSESSMENT_2026-11-07_SYNC_PROGRESS_PATCH_GAP.md`. No vulnerability submission or CVSS at present. The class B synthetically withheld-header downloader test is still undergoing separate CI review and is not counted as proof until logs confirm.
