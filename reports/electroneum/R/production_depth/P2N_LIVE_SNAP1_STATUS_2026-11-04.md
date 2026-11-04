# P2n status — 2026-11-04 (INCOMPLETE; no confirmed vulnerability)

**Passing gate:** Certified Electroneum source SHA `7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0`, QBFT block #1 hash `0x4aafdc63b0d50cff6f463d2c318001cc608a19731beb27e96e7344140523bec1`, state root `0x5575ef1d7b14a9c6570a00636fcb9e3c3aae473f87aca79d1677ed447524e7e6`, 3/4 committed seals, 101 accounts, one contract storage trie. Log marker: `R_P2N_QBFT_FINALIZED_ROOT_VERIFIED`.

**Failing runtime:** [Actions #41817818119](https://github.com/aprashnasuraj-dev/winddeep/actions/runs/41817818119). All seven scenarios failed at `R_P2N_LOOPBACK_SNAP1_HANDSHAKE_FAILED`, before any live Snap requests, state ingestion, or attacker writes. Both test servers currently set `NoDial:true`; the receiver invokes `AddPeer` but cannot dial. Subsequent test result aggregation panicked on absent scenario results. These are harness failures, **not** vulnerabilities.

**Test:** `reports/electroneum/R/production_depth/qbft_live_snap1_finalized_state_root_test.go`. Selector `23-live-etn-snap-qbft-root`. Workflow syntax guard passed. Test compiled and fixture verified. Certified source untouched.

**Pending:** repair localhost dialing and failed-subtest aggregation; prove real snap/1 negotiation; exercise actual AccountRange, StorageRanges, ByteCodes, TrieNodes requests into shipped SnapSyncer, positive root recovery, hostile payload rejection, disk allocation with honest control. Standalone snap/1 backend glue will not prove production's combined ETH+Snap peer registration even after success.

**Disposition:** OPEN, NOT VERIFIED, NOT BOUNTY READY. No excess persistent disk growth or healthy-reserve crash was established.
