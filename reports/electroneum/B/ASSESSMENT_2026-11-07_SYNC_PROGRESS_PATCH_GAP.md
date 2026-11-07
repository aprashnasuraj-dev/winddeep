# B-SYNC-PROGRESS-20261105 — certified component patch differential (INTERNAL)

Date: 2026-11-07 UTC / NPT. Owner: B. **Status: E2 COMPONENT BEHAVIOR PROVEN; E3/E4 NOT PROVEN. No P1–P3 submission or CVSS is justified yet.**

## 1. Mechanism, official patch source and concrete version comparison

- Audited public source: `electroneum/electroneum-sc@3aeb14db0d6384243302f3a025bdff904dc28bf6`, byte-parity certified at audit-source tree `de7f3c75a2db7e87a89918f1257820703d5b731e`.
- Official upstream master after **2026-11-05**: `db0eb8792dd57304fbc66a60377c7663e1bd44d2`, PR #94, *miner: pause consensus on verified sync progress, not a bare TD claim*.
- Exact 2-commit diff from pinned upstream -> public master: four files, `eth/downloader/downloader.go`, `eth/downloader/events.go`, `miner/miner.go`, `miner/miner_test.go`.
- Official code browser: https://github.com/electroneum/electroneum-sc/commit/db0eb8792dd57304fbc66a60377c7663e1bd44d2 .
- Pinned `eth/sync.go:156-206`: select highest TD peer; if advertised TD exceeds local TD then queue sync (subject to peer-count, merge-state and other gates). `eth/sync.go:258` calls `downloader.LegacySync`.
- Pinned `eth/downloader/downloader.go` `syncWithPeer`: posts `StartEvent{}` BEFORE `fetchHead` returns any verified peer header.
- Pinned `miner/miner.go:94-122`: `StartEvent` enters `miner.update`, calls `miner.worker.stop()`, sets `canStart=false`.
- Official upstream fix defers miner stop until a new `ProgressEvent` posted AFTER valid head acquisition, not on the bare StartEvent.

**Threat model hypothesis:** an externally connected unauthenticated ETH peer can present misleading high TD, trigger an attempted sync without serving headers, and pause a validating/mining node until fetch failure or timeout. Repeating this across enough validators might prevent quorum. This is explicitly a hypothesis until peer->event reachability and quorum effects are reproduced under shipped configs.

## 2. Actual independently checkable certified test evidence

Shared, real Go certified-source run: https://github.com/aprashnasuraj-dev/winddeep/actions/runs/42317769502

- Job Class B: `128234543061`, completed SUCCESS; source bootstrap validated immutable commit/tree.
- Class probe `B-sync-progress-prepatch`: `go test -count=3` on actual `./miner` implementation with synthetic `createMiner`, 3 bare StartEvent/FailedEvent sequences per test. **Three test repetitions PASS**, with `B_BARE_START_PAUSED_MINER` and `B_FAILURE_RECOVERED_MINER` controls. Registered in `B/PROBES.json`. This establishes the event-to-miner component behavior, not malicious peer ingress.
- Separate `B/verify_sync_patch.py` executes `TestWorkerBUnverifiedSyncMustKeepMinerRunning` on **the pinned certified behavior**. It must fail ONLY with precise `B_UNVERIFIED_START_INVARIANT_BROKEN` marker; this occurred. Compile errors/timeout are rejected as proof.
- Then isolated scratch-only patch injects the official new ProgressEvent semantics into downloader and miner; does not modify immutable source, repo vendor bytes or public nodes.
- On patched scratch: `TestWorkerBUnverifiedSyncMustKeepMinerRunning` and `TestWorkerBVerifiedProgressStopsAndResumes` both **PASS for `-count=3`**. Positive control proves miner still pauses after verified progress and resumes after sync DoneEvent. CI marker `B_UPSTREAM_SYNC_PROGRESS_DIFFERENTIAL_PASS baseline_invariant_fail=expected patched_controls=3x`.
- Actual standard B QBFT committed seals regression also PASS 3x. This is independent, but it **does not** link the miner event to N=4/F=1 finality.
- Certified job emits raw logs `B-sync-prefixed-invariant.log`, `B-sync-patched-controls.log`, `B-sync-patch-differential.json` with log SHA-256 checksums in the CI artifact (14-day retention). No synthetic log is represented as a public network test.

## 3. Strongest counterexamples and exact remaining proof

- **P2 not established:** existing peer minimums, eth handshake checks, post-TTD/merger gate, miner/consensus startup role, and the ability of the remaining honest validator set to retain quorum can prevent the alleged availability impact.
- Pinned `chainSyncer.nextSyncOp` requires sufficient peer count and selects highest TD, and `merger.TDDReached()` disables legacy sync; these are specific first-order counters, not to be dismissed.
- A malicious peer might only pause ONE validator; in N=4/F=1 the other three can form 3-of-4 quorum. A **network halt** requires evidence that two or more validators can be simultaneously affected, for a measured nontrivial duration with no alternative recoveries.
- An in-process event injection alone does NOT prove an unauthenticated peer can trigger it via the live handshake. No actual peer-driven sync, no validator network, no measured lost finalizations, no production node configuration or deployed version cross-check.
- The upstream master fix may not yet be released or deployed; the old certified source's behavior is a component fact, not proof that real validators run it today.

## 4. One next discriminating system test

Build an isolated authentic `eth` peer fixture with: honest valid higher-TD peer that delivers a real header, malicious high-TD peer that times out without a header, and the patched-counterfactual source. Trace exactly `peerToSyncOp` -> `LegacySync` -> `syncWithPeer` -> `StartEvent` -> miner pause under normal peer minimum/default configuration. Then run a separate **signed** N=4/F=1 IBFT validator case to quantify whether 1 versus 2 paused miners prevents canonical blocks from finalizing; measure stall and recovery. Publish external report ONLY if E3 repeatability and E4 public attacker reachability/impact are proven. Do not send public-node packets or DoS traffic.

