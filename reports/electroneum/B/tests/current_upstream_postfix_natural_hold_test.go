// Independent bounded liveness characterization on official upstream db0eb879.
// This is a single-node downloader/miner experiment; not QBFT quorum impact.
package miner

import (
    "math/big"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
)

// The existing independentHeadOnlyDownloaderPeer type is compiled from the
// earlier integrated PoC in the same scratch miner package. Do NOT change
// production source, remotely open sockets, or directly post miner events.
func TestIndependentPostFixNaturalMinerPauseDuration(t *testing.T) {
    miner, mux, cleanup := createMiner(t)
    defer cleanup(false)
    miner.Start(common.HexToAddress("0x12345"))
    waitForMiningState(t, miner, true)

    bc := miner.eth.BlockChain()
    original := bc.CurrentBlock().Hash()
    head := &types.Header{
        ParentHash: original,
        Number: big.NewInt(1),
        GasLimit: 11500000,
        Difficulty: big.NewInt(1),
        Time: uint64(time.Now().Unix()),
        Extra: []byte{0x4e, 0x41, 0x54, 0x55, 0x52, 0x41, 0x4c},
    }
    peer := &independentHeadOnlyDownloaderPeer{
        head: head, silentHead: false, byNumberCalled: make(chan struct{}, 1),
    }
    dl := downloader.New(0, rawdb.NewMemoryDatabase(), mux, bc, nil, nil, nil)
    defer dl.Terminate()
    const id = "independent-headonly-natural-timeout"
    if err := dl.RegisterPeer(id, ethproto.ETH66, peer); err != nil {
        t.Fatal(err)
    }

    result := make(chan error, 1)
    go func() {
        result <- dl.LegacySync(id, head.Hash(), big.NewInt(1000000000), nil, downloader.FullSync)
    }()
    select {
    case <-peer.byNumberCalled:
        // The actual downloader has progressed past the HEAD response,
        // and has requested ancestry. No reply is forthcoming.
    case err := <-result:
        t.Fatalf("sync unexpectedly terminated before ancestor request: %v", err)
    case <-time.After(12 * time.Second):
        dl.Cancel()
        t.Fatal("did not reach ancestor lookup")
    }
    waitForMiningState(t, miner, false)
    start := time.Now()
    if bc.CurrentBlock().Hash() != original {
        dl.Cancel()
        t.Fatal("unverified peer changed canonical head")
    }
    t.Logf("NATURAL_HOLD_START height=%d peer_head=%s miner_running=false", bc.CurrentBlock().NumberU64(), head.Hash())

    timer := time.NewTimer(12 * time.Second)
    defer timer.Stop()
    select {
    case err := <-result:
        elapsed := time.Since(start)
        if err == nil {
            t.Fatalf("head-only source falsely completed sync after %v", elapsed)
        }
        if bc.CurrentBlock().Hash() != original {
            t.Fatal("head-only source altered canonical chain before timeout")
        }
        waitForMiningState(t, miner, true)
        t.Logf("NATURAL_HOLD_EARLY_RECOVERY duration_ms=%d error=%v", elapsed.Milliseconds(), err)
        // A natural recovery before 12 seconds is a strong duration limit.
    case <-timer.C:
        elapsed := time.Since(start)
        if miner.Mining() {
            dl.Cancel()
            t.Fatal("miner resumed while ancestry remains unverifiable")
        }
        if bc.CurrentBlock().Hash() != original {
            dl.Cancel()
            t.Fatal("canonical chain changed while ancestor was missing")
        }
        t.Logf("NATURAL_HOLD_12S miner_running=false canonical_unchanged=true duration_ms=%d", elapsed.Milliseconds())
        dl.Cancel()
        select {
        case err := <-result:
            if err == nil {
                t.Fatal("cancelled sync returned success")
            }
        case <-time.After(10 * time.Second):
            t.Fatal("downloader failed to exit after bounded cancellation")
        }
        waitForMiningState(t, miner, true)
        t.Log("NATURAL_HOLD_RECOVERY_AFTER_CANCEL")
    }
}
