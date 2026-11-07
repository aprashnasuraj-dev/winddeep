// New patch-differential candidate from public Electroneum fix 2026-11-05.
// Executes shipped Miner + event mux in a disposable synthetic chain.
// NO public peer, consensus network, or remote exploit is demonstrated.
package miner

import (
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/eth/downloader"
)

func TestWorkerBUnverifiedSyncPauseCharacterization(t *testing.T) {
    m, mux, cleanup := createMiner(t)
    defer cleanup(false)
    m.Start(common.HexToAddress("0x12345"))
    waitForMiningState(t, m, true)
    for cycle := 0; cycle < 3; cycle++ {
        // Control: a bare downloader StartEvent does NOT contain a verified head.
        mux.Post(downloader.StartEvent{})
        waitForMiningState(t, m, false)
        t.Logf("B_BARE_START_PAUSED_MINER cycle=%d mining=false verified_head=false", cycle)
        // Recovery control: failure must resume miner.
        mux.Post(downloader.FailedEvent{})
        waitForMiningState(t, m, true)
        t.Logf("B_FAILURE_RECOVERED_MINER cycle=%d mining=true", cycle)
    }
}

// Secure invariant. Expected to FAIL on the certified pre-fix implementation,
// and PASS on an isolated scratch tree with the exact public upstream repair.
// It is deliberately not a vulnerability finding until peer reachability,
// validator role and measurable chain-level availability are also demonstrated.
func TestWorkerBUnverifiedSyncMustKeepMinerRunning(t *testing.T) {
    m, mux, cleanup := createMiner(t)
    defer cleanup(false)
    m.Start(common.HexToAddress("0x12345"))
    waitForMiningState(t, m, true)
    mux.Post(downloader.StartEvent{})
    deadline := time.Now().Add(250*time.Millisecond)
    for time.Now().Before(deadline) {
        if !m.Mining() {
            t.Fatal("B_UNVERIFIED_START_INVARIANT_BROKEN miner paused without a fetched/verified head")
        }
        time.Sleep(5*time.Millisecond)
    }
    mux.Post(downloader.FailedEvent{})
    waitForMiningState(t, m, true)
    t.Log("B_BARE_START_NO_PAUSE_PATCHED_PASS")
}
