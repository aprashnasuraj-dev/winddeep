# B-PEER-WITHHELD-HEAD — certified CI failure triage (2026-11-07)

Decision: **DISPROVEN as a target vulnerability by this failed run; fixture setup failure**, not evidence that the suspected peer-induced miner pause is secure or exploitable. E2 exists only for the separate B-sync-progress-prepatch component regression; the withheld-head path did not execute beyond test setup. No P-band or CVSS assigned.

## Immutable execution evidence
- Historical workflow run 42318128454, class B job 128235830799, checkout trigger SHA `ecfe35731c4d1cbbb0ebc94985d9bec46b78f61f` (job checkout log), Go 1.24.0.
- Bootstrap verified certified source commit `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, tree `de7f3c75a2db7e87a89918f1257820703d5b731e`, pinned upstream `3aeb14db0d6384243302f3a025bdff904dc28bf6`.
- Matrix: B-qbft-quorum PASS_REGRESSION_ONLY 3/3 exit 0 log SHA `e4aeeefe7938fc84c859e65797e21f5d2b24ce3fa0740b3d6cc2330b857d1163`; B-sync-progress-prepatch PASS_REGRESSION_ONLY 3/3 exit 0 log SHA `c1a0353cfdb086247f6d895337b01468a927af22173330c2bf1ec989c4c697b7`.
- B-peer-withheld-head-lifecycle **FAIL_OR_INCOMPLETE, 0 successful top-level repetitions, exit 1**, log SHA `eec2da02742a59db3da4fb5646e3016275a0a04b332a63ff1e668997fd82e3ab`; job exit 1. Artifact ID 13551149635 contains exact probe log and result.json.

## Root cause demonstrated by actual traceback and immutable source
- Test panic: `Requested chain generation outside of init` at `eth/downloader/testchain_test.go:212`, from `newTestBlockchain` via `downloadTester.newPeer` (`downloader_test.go:122`).
- At run-trigger SHA `ecfe3573`, fixture `reports/electroneum/B/test_peer_withheld_head_test.go` called `testChainBase.shorten(8)`, yielding 7 blocks after excluding genesis. The source's init pre-generates specified chain lengths, including `800/8 = 100`, **not 8**. After `pregenerated=true`, an unregistered chain length triggers the explicit test-only panic. This occurs before `tester.sync`, StartEvent, or any malicious downloader response; it cannot demonstrate a target vulnerability.
- Current branch fixture already uses `testChainBase.shorten(800/8)` and retains both honest and withheld-head cases. This is a source-level correction **not yet established as passed in a matched completed run**. Do not reapply the same fix or rerun an already active job.

## Threat and controls
- Hypothesis: remote peer advertises high total difficulty but withholds its advertised head, causing downloader StartEvent before validation, potentially pausing a QBFT validator's miner.
- Actual attacker control in the test: synthetic downloader peer response/claimed TD. Real default peer handshake, validator duty, 3-of-4 honest block progress and miner recovery were not tested.
- Honest control and malicious control **both unexecuted beyond fixture setup** in this failed job. Strongest defense remains downloader error/timeout recovery and honest quorum continuing; no measured outage, invalid finality, or economic harm.
- Independent oracle for a future experiment: accepted canonical block heights and finalization timestamps of three honest validators, compared to clean baseline; StartEvent alone is not an outage oracle.

## Next discriminating action
Inspect a **newer completed workflow run** whose head SHA includes the `shorten(800/8)` correction, and read its B probe log, exit, control markers and timeout recovery. If no such run exists, classify the corrected fixture PENDING_EXECUTION; do not claim PASS or dispatch a duplicate. Only after the component passes should a signed N=4/F=1 network fixture test whether an authenticated peer's withholding causes material honest-quorum outage.
