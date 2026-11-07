// Independent real-miner observable effect on the official patched upstream.
// The peer->ProgressEvent causality is demonstrated by the downloader companion test.
package miner

import (
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/eth/downloader"
)

func TestPatchedMinerPausesForHeadOnlyUnverifiedProgress(t *testing.T) {
    miner, mux, cleanup := createMiner(t)
    defer cleanup(false)
    miner.Start(common.HexToAddress("0x12345"))
    waitForMiningState(t, miner, true)
    mux.Post(downloader.StartEvent{})
    assertMiningStays(t, miner, true)
    t.Log("PATCH_HEAD_ONLY_MINER_BASELINE start_unverified_no_pause=true")

    // An unverified ProgressEvent, as observed in the companion downloader
    // test, is sufficient to halt actual miner work before ancestor validation.
    mux.Post(downloader.ProgressEvent{})
    waitForMiningState(t, miner, false)
    started := time.Now()
    for time.Since(started)<800*time.Millisecond {
        if miner.Mining() {
            t.Fatal("miner resumed without downloader completion/failure")
        }
        time.Sleep(10*time.Millisecond)
    }
    t.Logf("PATCH_HEAD_ONLY_MINER_SUSPENDED blocked_ms=%d", time.Since(started).Milliseconds())

    mux.Post(downloader.FailedEvent{})
    waitForMiningState(t, miner, true)
    t.Log("PATCH_HEAD_ONLY_MINER_RECOVERED after_failed_event=true")
}
