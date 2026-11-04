//go:build linux

// Worker R P2i: production-path disk-growth oracle. A real lower-trust ETH66
// retrieval peer serves one already QBFT-quorum-valid block. Compare the
// receiver's physical LevelDB allocation against a local InsertChain baseline,
// then repeat the peer synchronization request without a new canonical block.
// This tests whether replay creates storage growth beyond unavoidable chain
// persistence; it does NOT grant the peer validator signing authority.
package eth

import (
    "fmt"
    "os"
    "path/filepath"
    "syscall"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul"
    istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/forkid"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/p2p"
)

// rG6PhysicalBytes counts allocated filesystem blocks, not apparent file size.
// It excludes allocations elsewhere on the mounted filesystem. LevelDB's own
// asynchronous compaction/WAL behavior still limits cross-run comparability.
func rG6PhysicalBytes(t *testing.T, root string) int64 {
    t.Helper()
    var total int64
    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if info.Mode().IsRegular() {
            st, ok := info.Sys().(*syscall.Stat_t)
            if !ok {
                return fmt.Errorf("R_G6_NOT_LINUX_STAT path=%s", path)
            }
            total += st.Blocks * 512
        }
        return nil
    })
    if err != nil {
        t.Fatalf("R_G6_DISK_WALK_FAILED root=%s err=%v", root, err)
    }
    return total
}

func TestRQBFTWireDiskGrowthBaseline(t *testing.T) {
    root := os.Getenv("R_G6_DISK_GROWTH_ROOT")
    if root == "" {
        t.Skip("R_G6_DISK_GROWTH_ROOT not configured")
    }
    if err := os.MkdirAll(root, 0700); err != nil {
        t.Fatal(err)
    }

    // Both cases have the same DB/consensus initialization. The small-block
    // case measures fixed persistence overhead, not attacker amplification.
    for _, profile := range []struct {
        name  string
        large bool
    }{
        {"small-valid", false},
        {"large-valid-256k", true},
    } {
        t.Run(profile.name, func(t *testing.T) {
            base := filepath.Join(root, profile.name)
            if err := os.RemoveAll(base); err != nil {
                t.Fatal(err)
            }
            if err := os.MkdirAll(base, 0700); err != nil {
                t.Fatal(err)
            }
            defer os.RemoveAll(base)

            f, senderKey := rP1HBaseFixture(t)
            defer f.close()
            var tx *types.Transaction
            if profile.large {
                tx = rG6LargeSignedTx(t, f.remoteChain, senderKey)
            } else {
                tx = rP1HSignedTx(t, f.remoteChain, senderKey, 0xA7)
            }
            block := rQBFTBuildAndImport(t, f.remoteChain, f.remoteQBFT,
                f.remoteDB, f.validatorKeys, f.validators, tx)
            if block == nil || block.NumberU64() != 1 {
                t.Fatal("R_G6_GROWTH_REMOTE_QUORUM_BLOCK_INVALID")
            }
            sender := crypto.PubkeyToAddress(senderKey.PublicKey)
            genesis := rQBFTNetworkGenesis(t, f.validatorKeys, sender)
            makeReceiver := func(path string) (ethdb.Database, *core.BlockChain, *istanbulbackend.Backend, *rQBFTObservedDB) {
                if err := os.MkdirAll(path, 0700); err != nil {
                    t.Fatal(err)
                }
                db := rQBFTOpenDisk(t, path)
                g := genesis.MustCommit(db)
                if g.Hash() != block.ParentHash() {
                    t.Fatalf("R_G6_GROWTH_GENESIS_MISMATCH got=%s want=%s", g.Hash(), block.ParentHash())
                }
                traced := &rQBFTObservedDB{Database: db}
                backend := istanbulbackend.New(*istanbul.DefaultConfig, f.validatorKeys[0], traced)
                chain, err := core.NewBlockChain(traced, nil, genesis.Config,
                    backend, vm.Config{}, nil, nil)
                if err != nil {
                    t.Fatal(err)
                }
                if err := backend.Start(chain, chain.CurrentBlock, rawdb.HasBadBlock); err != nil {
                    t.Fatal(err)
                }
                if err := backend.VerifyHeader(chain, block.Header(), true); err != nil {
                    t.Fatalf("R_G6_GROWTH_BLOCK_SEAL_VERIFICATION_FAIL: %v", err)
                }
                return db, chain, backend, traced
            }

            wirePath := filepath.Join(base, "eth66")
            directPath := filepath.Join(base, "direct")
            wireDB, wireChain, wireBE, observed := makeReceiver(wirePath)
            defer func() {
                _ = wireBE.Stop()
                wireChain.Stop()
                _ = wireDB.Close()
            }()
            directDB, directChain, directBE, _ := makeReceiver(directPath)
            defer func() {
                _ = directBE.Stop()
                directChain.Stop()
                _ = directDB.Close()
            }()

            // Independent control: import the IDENTICAL already-valid block
            // through canonical core.InsertChain, absent any peer transport.
            directBefore := rG6PhysicalBytes(t, directPath)
            if n, err := directChain.InsertChain(types.Blocks{block}); err != nil {
                t.Fatalf("R_G6_DIRECT_IMPORT_FAILED index=%d err=%v", n, err)
            }
            directAfter := rG6PhysicalBytes(t, directPath)
            directDelta := directAfter - directBefore
            if directDelta <= 0 {
                t.Fatalf("R_G6_DIRECT_BASELINE_NO_PERSISTENCE delta=%d", directDelta)
            }
            directReceipt, _, _, _ := rawdb.ReadReceipt(directDB, tx.Hash(), directChain.Config())
            if directChain.CurrentBlock().Hash() != block.Hash() ||
                directReceipt == nil || directReceipt.Status != types.ReceiptStatusSuccessful {
                t.Fatal("R_G6_DIRECT_BASELINE_INVALID_CANONICAL_STATE")
            }

            localHandler := rDevP2PHandler(t, observed, wireChain)
            defer localHandler.Stop()
            localServer := rDevP2PServer(t, "r-g6-growth-local", localHandler, false)
            defer localServer.Stop()
            wire := new(rP1HWireState)
            td := f.remoteChain.GetTd(block.Hash(), 1)
            if td == nil {
                t.Fatal("R_G6_GROWTH_REMOTE_TD_MISSING")
            }
            proto := rP1HRemoteProtocol(t, wireChain.Genesis(), block, td,
                forkid.NewID(wireChain.Config(), wireChain.Genesis().Hash(), block.NumberU64()), wire)
            original := proto.Run
            proto.Run = func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
                return original(peer, &rG6WireSpy{MsgReadWriter: rw})
            }
            remoteServer := rP1HRemoteServer(t, "r-g6-growth-remote", proto)
            defer remoteServer.Stop()
            localServer.AddPeer(remoteServer.Self())
            peer := rP1HWaitRegisteredPeer(t, localHandler, remoteServer)
            headHash, headTD := peer.Head()
            if wire.handshakes.Load() == 0 || headHash != block.Hash() {
                t.Fatalf("R_G6_GROWTH_REAL_ETH66_HANDSHAKE_FAIL count=%d head=%s",
                    wire.handshakes.Load(), headHash)
            }

            wireBefore := rG6PhysicalBytes(t, wirePath)
            if err := localHandler.downloader.LegacySync(peer.ID(), headHash,
                headTD, wireChain.Config().TerminalTotalDifficulty, downloader.FullSync); err != nil {
                t.Fatalf("R_G6_GROWTH_REAL_ETH66_SYNC_FAILED: %v", err)
            }
            wireAfter := rG6PhysicalBytes(t, wirePath)
            wireDelta := wireAfter - wireBefore
            if wireDelta <= 0 || wire.bodyResponses.Load() == 0 {
                t.Fatalf("R_G6_GROWTH_REAL_WIRE_NOT_EXERCISED delta=%d body_responses=%d",
                    wireDelta, wire.bodyResponses.Load())
            }
            receipt, _, _, _ := rawdb.ReadReceipt(wireDB, tx.Hash(), wireChain.Config())
            if wireChain.CurrentBlock().Hash() != block.Hash() || receipt == nil ||
                receipt.Status != types.ReceiptStatusSuccessful || receipt.TxHash != tx.Hash() {
                t.Fatal("R_G6_GROWTH_WIRE_CANONICAL_OR_RECEIPT_FAIL")
            }

            // Re-sync attempts cannot create new valid chain data here: the
            // peer advertises the SAME single block. Record whether the
            // downloader actually issues new body requests; a no-op cannot
            // be misreported as a tested repeated-body import vulnerability.
            beforeReplay := rG6PhysicalBytes(t, wirePath)
            beforeBodies := wire.bodyResponses.Load()
            accepted := 0
            rejected := 0
            for retry := 0; retry < 3; retry++ {
                err := localHandler.downloader.LegacySync(peer.ID(), headHash,
                    headTD, wireChain.Config().TerminalTotalDifficulty, downloader.FullSync)
                if err == nil {
                    accepted++
                } else {
                    rejected++
                    t.Logf("R_G6_DISK_REPLAY_REJECTED attempt=%d err=%v", retry+1, err)
                }
                if wireChain.CurrentBlock().Hash() != block.Hash() {
                    t.Fatal("R_G6_GROWTH_REPLAY_MUTATED_CANONICAL_HEAD")
                }
            }
            replayDelta := rG6PhysicalBytes(t, wirePath) - beforeReplay
            bodiesReplayed := wire.bodyResponses.Load() - beforeBodies
            if replayDelta < 0 {
                t.Logf("R_G6_REPLAY_COMPACTION_OBSERVED freed_bytes=%d", -replayDelta)
            }
            // Measured ratios are observations, not arbitrary pass/fail
            // vulnerability thresholds. An excess needs independent rerun,
            // block-body evidence and non-validator attacker control.
            blockBytes := int64(block.Size())
            t.Logf("R_G6_DISK_GROWTH_PROFILE profile=%s block_bytes=%d eth66_db_delta=%d direct_db_delta=%d eth66_to_direct=%.3f eth66_to_block=%.3f replay_db_delta=%d replay_body_responses=%d replay_calls_ok=%d replay_calls_error=%d",
                profile.name, blockBytes, wireDelta, directDelta,
                float64(wireDelta)/float64(directDelta), float64(wireDelta)/float64(blockBytes),
                replayDelta, bodiesReplayed, accepted, rejected)
        })
    }
    t.Log("R_G6_DISK_GROWTH_BASELINE_PASS positive=real_ETH66_QBFT_block control=identical_direct_InsertChain no_claim=remote_ENOSPC_until_attacker_amplification_proved")
}
