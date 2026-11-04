//go:build linux

// Worker R P2j: multi-height valid QBFT ETH/66 synchronization, duplicate
// responses to repeated sync requests, a quorum-authorized abandoned fork,
// full LevelDB compaction, and persistent restart.
// IMPORTANT: both divergent forks were signed by 3 of 4 fixture validators.
// This does not grant an unauthenticated peer the ability to manufacture forks.
package eth

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "encoding/binary"
    "math/big"
    "os"
    "path/filepath"
    "sync/atomic"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul"
    istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/p2p"
)

const rP2JPayload = 128 << 10

// Deterministic, noncompressible-ish calldata prevents artificial disk savings
// from using identical all-zero 128 KiB payloads. Only ordinary signed,
// consensus-valid transactions are imported. The peer has no signing control.
func rP2JTransaction(t *testing.T, chain *core.BlockChain, senderKey *ecdsa.PrivateKey, fork byte, height byte) *types.Transaction {
    t.Helper()
    st, err := chain.State()
    if err != nil {
        t.Fatal(err)
    }
    sender := crypto.PubkeyToAddress(senderKey.PublicKey)
    buf := make([]byte, rP2JPayload)
    for off := 0; off < len(buf); off += sha256.Size {
        var seed [8]byte
        seed[0], seed[1] = fork, height
        binary.BigEndian.PutUint32(seed[4:], uint32(off))
        digest := sha256.Sum256(seed[:])
        copy(buf[off:], digest[:])
    }
    tx, err := types.SignTx(types.NewTransaction(
        st.GetNonce(sender),
        common.HexToAddress("0x0000000000000000000000000000000000000043"),
        big.NewInt(1), 6_000_000, big.NewInt(10_000_000_000), buf,
    ), types.LatestSigner(chain.Config()), senderKey)
    if err != nil {
        t.Fatal(err)
    }
    return tx
}

type rP2JMeter struct {
    bodyResponses atomic.Int64
    bodyBytes atomic.Int64
}
type rP2JMeteredWriter struct {
    p2p.MsgReadWriter
    meter *rP2JMeter
}
func (w *rP2JMeteredWriter) WriteMsg(msg p2p.Msg) error {
    err := w.MsgReadWriter.WriteMsg(msg)
    if err == nil && msg.Code == ethproto.BlockBodiesMsg {
        w.meter.bodyResponses.Add(1)
        w.meter.bodyBytes.Add(int64(msg.Size))
    }
    return err
}

func rP2JServer(t *testing.T, name string, h *handler, meter *rP2JMeter) *p2p.Server {
    t.Helper()
    key, err := crypto.GenerateKey()
    if err != nil {
        t.Fatal(err)
    }
    protocols := ethproto.MakeProtocols((*ethHandler)(h), 1, nil)
    for i := range protocols {
        original := protocols[i].Run
        protocols[i].Run = func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
            return original(peer, &rP2JMeteredWriter{MsgReadWriter: rw, meter: meter})
        }
    }
    srv := &p2p.Server{Config: p2p.Config{
        Name: name, PrivateKey: key, MaxPeers: 2,
        NoDiscovery: true, NoDial: true, ListenAddr: "127.0.0.1:0",
        Protocols: protocols,
    }}
    if err := srv.Start(); err != nil {
        t.Fatalf("R_P2J_SERVER_START_FAILED name=%s err=%v", name, err)
    }
    return srv
}

func rP2JDiskChain(t *testing.T, path string, genesis *core.Genesis, signer *ecdsa.PrivateKey) (ethdb.Database, *core.BlockChain, *istanbulbackend.Backend) {
    t.Helper()
    if err := os.MkdirAll(path, 0700); err != nil {
        t.Fatal(err)
    }
    db := rQBFTOpenDisk(t, path)
    genesis.MustCommit(db)
    backend := istanbulbackend.New(*istanbul.DefaultConfig, signer, db)
    chain, err := core.NewBlockChain(db, nil, genesis.Config, backend, vm.Config{}, nil, nil)
    if err != nil {
        _ = db.Close()
        t.Fatal(err)
    }
    if err := backend.Start(chain, chain.CurrentBlock, rawdb.HasBadBlock); err != nil {
        chain.Stop()
        _ = db.Close()
        t.Fatal(err)
    }
    return db, chain, backend
}

func rP2JValidateCanonical(t *testing.T, db ethdb.Database, chain *core.BlockChain, head *types.Block, canonical *types.Transaction, orphan *types.Transaction) {
    t.Helper()
    h := chain.CurrentBlock()
    if h == nil || h.Hash() != head.Hash() {
        t.Fatalf("R_P2J_HEAD_MISMATCH got=%v want=%s", h, head.Hash())
    }
    got, _, _, _ := rawdb.ReadReceipt(db, canonical.Hash(), chain.Config())
    if got == nil || got.TxHash != canonical.Hash() || got.Status != types.ReceiptStatusSuccessful {
        t.Fatalf("R_P2J_CANONICAL_RECEIPT_MISSING tx=%s got=%v", canonical.Hash(), got)
    }
    if orphan != nil {
        dead, _, _, _ := rawdb.ReadReceipt(db, orphan.Hash(), chain.Config())
        if dead != nil {
            t.Fatalf("R_P2J_ORPHAN_RECEIPT_VISIBLE tx=%s", orphan.Hash())
        }
    }
}

func rP2JStopChain(be *istanbulbackend.Backend, chain *core.BlockChain, db ethdb.Database) error {
    if err := be.Stop(); err != nil { return err }
    chain.Stop()
    return db.Close()
}

func TestRQBFTMultiHeightDiskGrowthAndRestart(t *testing.T) {
    root := os.Getenv("R_P2J_DISK_ROOT")
    if root == "" {
        t.Skip("R_P2J_DISK_ROOT not configured")
    }
    if err := os.MkdirAll(root, 0700); err != nil { t.Fatal(err) }

    healthyStart := rG6AvailBytes(t, root)
    if healthyStart < 64<<20 {
        t.Fatalf("R_P2J_HEALTHY_RESERVE_PRECONDITION_FAIL free=%d", healthyStart)
    }
    // Independent remote chains, with the same genesis and distinct signed
    // transaction histories. Their QBFT signatures are produced by the
    // fixture, NOT a malicious unprivileged devp2p peer.
    f, senderKey := rP1HBaseFixture(t)
    defer f.close()
    remoteA := make(types.Blocks, 0, 3)
    remoteB := make(types.Blocks, 0, 4)
    var aTx, bTx *types.Transaction
    for i := 0; i < 3; i++ {
        tx := rP2JTransaction(t, f.remoteChain, senderKey, 'A', byte(i+1))
        if i == 0 { aTx = tx }
        remoteA = append(remoteA, rQBFTBuildAndImport(t,
            f.remoteChain, f.remoteQBFT, f.remoteDB, f.validatorKeys, f.validators, tx))
    }
    for i := 0; i < 4; i++ {
        tx := rP2JTransaction(t, f.localChain, senderKey, 'B', byte(i+1))
        if i == 0 { bTx = tx }
        remoteB = append(remoteB, rQBFTBuildAndImport(t,
            f.localChain, f.localQBFT, f.localDB, f.validatorKeys, f.validators, tx))
    }
    if remoteA[0].Hash() == remoteB[0].Hash() ||
        remoteA[2].NumberU64() != 3 || remoteB[3].NumberU64() != 4 {
        t.Fatal("R_P2J_FORK_FIXTURE_INVALID")
    }
    // Observe shipped future-block-time acceptance; do not relax it in
    // receiving nodes or start network delivery too early.
    for remoteB[3].Time() > uint64(time.Now().Unix()) + 5 {
        time.Sleep(100 * time.Millisecond)
    }
    t.Logf("R_P2J_PRODUCTION_TIME_GATE_PASS now=%d remote_tip=%d",
        time.Now().Unix(), remoteB[3].Time())

    genesis := rQBFTNetworkGenesis(t, f.validatorKeys, crypto.PubkeyToAddress(senderKey.PublicKey))
    wirePath := filepath.Join(root, "wire-leveldb")
    directPath := filepath.Join(root, "direct-leveldb")
    wireDB, wireChain, wireBE := rP2JDiskChain(t, wirePath, genesis, f.validatorKeys[0])
    directDB, directChain, directBE := rP2JDiskChain(t, directPath, genesis, f.validatorKeys[0])
    // Test intentionally stops network handlers before opening persisted data.
    // A failure in a stage still uses independent t.Cleanup closures below.
    wireClosed, directClosed := false, false
    t.Cleanup(func() {
        if !wireClosed { _ = rP2JStopChain(wireBE, wireChain, wireDB) }
        if !directClosed { _ = rP2JStopChain(directBE, directChain, directDB) }
    })
    noPeerStart := rG6PhysicalBytes(t, wirePath)
    time.Sleep(100 * time.Millisecond)
    idleDelta := rG6PhysicalBytes(t, wirePath) - noPeerStart
    t.Logf("R_P2J_NO_PEER_IDLE_CONTROL allocated_delta=%d", idleDelta)

    // Direct path contains the same byte-for-byte blocks in the same import
    // order. This is the baseline for unavoidable canonical+orphan retention.
    directBeforeA := rG6PhysicalBytes(t, directPath)
    if n, err := directChain.InsertChain(remoteA); err != nil {
        t.Fatalf("R_P2J_DIRECT_A_IMPORT_FAIL index=%d err=%v", n, err)
    }
    directAfterA := rG6PhysicalBytes(t, directPath)
    rP2JValidateCanonical(t, directDB, directChain, remoteA[2], aTx, nil)

    localHandler := rDevP2PHandler(t, wireDB, wireChain)
    remoteHandlerA := rDevP2PHandler(t, f.remoteDB, f.remoteChain)
    remoteHandlerB := rDevP2PHandler(t, f.localDB, f.localChain)
    localServer := rDevP2PServer(t, "r-p2j-receiver", localHandler, false)
    meterA, meterB := new(rP2JMeter), new(rP2JMeter)
    peerServerA := rP2JServer(t, "r-p2j-valid-A", remoteHandlerA, meterA)
    peerServerB := rP2JServer(t, "r-p2j-valid-B", remoteHandlerB, meterB)
    // Explicit teardown, not t.Cleanup, so restart reads a closed database.
    serversStopped := false
    t.Cleanup(func() {
        if !serversStopped {
            peerServerB.Stop()
            peerServerA.Stop()
            localServer.Stop()
            remoteHandlerB.Stop()
            remoteHandlerA.Stop()
            localHandler.Stop()
        }
    })

    wireBeforeA := rG6PhysicalBytes(t, wirePath)
    localServer.AddPeer(peerServerA.Self())
    peerA := rP1HWaitRegisteredPeer(t, localHandler, peerServerA)
    aHead, aTD := peerA.Head()
    if aHead != remoteA[2].Hash() {
        t.Fatalf("R_P2J_A_ADVERTISED_HEAD_INVALID got=%s want=%s", aHead, remoteA[2].Hash())
    }
    if err := localHandler.downloader.LegacySync(peerA.ID(), aHead, aTD,
        wireChain.Config().TerminalTotalDifficulty, downloader.FullSync); err != nil {
        t.Fatalf("R_P2J_MULTIHEIGHT_WIRE_A_IMPORT_FAIL: %v", err)
    }
    rP2JValidateCanonical(t, wireDB, wireChain, remoteA[2], aTx, nil)
    if meterA.bodyResponses.Load() == 0 {
        t.Fatal("R_P2J_MULTIHEIGHT_BODY_RESPONSES_MISSING")
    }
    wireAfterA := rG6PhysicalBytes(t, wirePath)
    t.Logf("R_P2J_MULTIHEIGHT_A_BASELINE blocks=3 wire_growth=%d direct_growth=%d body_responses=%d body_msg_bytes=%d",
        wireAfterA-wireBeforeA, directAfterA-directBeforeA,
        meterA.bodyResponses.Load(), meterA.bodyBytes.Load())

    // No new canonical blocks are created. Measure actual additional
    // response count separately from accepted durable allocation.
    replayBefore := rG6PhysicalBytes(t, wirePath)
    replayResponses := meterA.bodyResponses.Load()
    replayBytes := meterA.bodyBytes.Load()
    for i := 0; i < 3; i++ {
        err := localHandler.downloader.LegacySync(peerA.ID(), aHead, aTD,
            wireChain.Config().TerminalTotalDifficulty, downloader.FullSync)
        if err != nil {
            t.Logf("R_P2J_DUPLICATE_REQUEST_REJECTED iteration=%d err=%v", i+1, err)
        }
    }
    rP2JValidateCanonical(t, wireDB, wireChain, remoteA[2], aTx, nil)
    replayDelta := rG6PhysicalBytes(t, wirePath) - replayBefore
    replayBodies := meterA.bodyResponses.Load() - replayResponses
    t.Logf("R_P2J_DUPLICATE_REPLAY_OBSERVATION requests=3 extra_body_responses=%d extra_body_msg_bytes=%d physical_growth=%d head=3",
        replayBodies, meterA.bodyBytes.Load()-replayBytes, replayDelta)
    if replayBodies == 0 {
        t.Log("R_P2J_REPLAY_LIMITATION peer_was_not_asked_to_resend_bodies; repeated downloader calls alone do_not_prove_untrusted_replay")
    }

    // Competing branch B has a different transaction at block 1 and is
    // strictly longer. Validator-quorum signatures are fixture-provided.
    directBeforeB := rG6PhysicalBytes(t, directPath)
    if n, err := directChain.InsertChain(remoteB); err != nil {
        t.Fatalf("R_P2J_DIRECT_FORK_IMPORT_FAILED index=%d err=%v", n, err)
    }
    directAfterB := rG6PhysicalBytes(t, directPath)
    rP2JValidateCanonical(t, directDB, directChain, remoteB[3], bTx, aTx)

    // The existing fixture's p2p.Server limits active peers. Explicitly
    // detach A before dialing B, so a connection-capacity failure cannot be
    // mistaken for QBFT/downloader behavior.
    localServer.RemovePeer(peerServerA.Self())
    rWaitFor(t, 5*time.Second, "R_P2J_A_PEER_NOT_REMOVED", func() bool {
        return localHandler.peers.peer(peerServerA.Self().ID().String()) == nil
    })
    wireBeforeB := rG6PhysicalBytes(t, wirePath)
    localServer.AddPeer(peerServerB.Self())
    peerB := rP1HWaitRegisteredPeer(t, localHandler, peerServerB)
    bHead, bTD := peerB.Head()
    if bHead != remoteB[3].Hash() {
        t.Fatalf("R_P2J_B_ADVERTISED_HEAD_INVALID got=%s want=%s", bHead, remoteB[3].Hash())
    }
    if err := localHandler.downloader.LegacySync(peerB.ID(), bHead, bTD,
        wireChain.Config().TerminalTotalDifficulty, downloader.FullSync); err != nil {
        t.Fatalf("R_P2J_LONGER_QUORUM_FORK_IMPORT_FAILED: %v", err)
    }
    rP2JValidateCanonical(t, wireDB, wireChain, remoteB[3], bTx, aTx)
    wireAfterB := rG6PhysicalBytes(t, wirePath)
    if meterB.bodyResponses.Load() == 0 {
        t.Fatal("R_P2J_FORK_WIRE_BODIES_MISSING")
    }
    t.Logf("R_P2J_ABANDONED_FORK_BASELINE branch_A=3 branch_B=4 wire_growth=%d direct_growth=%d B_body_responses=%d B_body_msg_bytes=%d source=quorum_signed_not_unprivileged_mint",
        wireAfterB-wireBeforeB, directAfterB-directBeforeB,
        meterB.bodyResponses.Load(), meterB.bodyBytes.Load())

    // A well-behaved full-node peer serving the old, shorter chain cannot
    // simply roll canonical state back. If the downloaded old body is replayed
    // despite a smaller TD, this stage measures its disk side-effects.
    localServer.RemovePeer(peerServerB.Self())
    rWaitFor(t, 5*time.Second, "R_P2J_B_PEER_NOT_REMOVED", func() bool {
        return localHandler.peers.peer(peerServerB.Self().ID().String()) == nil
    })
    localServer.AddPeer(peerServerA.Self())
    peerA = rP1HWaitRegisteredPeer(t, localHandler, peerServerA)
    aHead, aTD = peerA.Head()
    oldForkBefore := rG6PhysicalBytes(t, wirePath)
    oldForkResponses := meterA.bodyResponses.Load()
    for i := 0; i < 3; i++ {
        if err := localHandler.downloader.LegacySync(peerA.ID(), aHead, aTD,
            wireChain.Config().TerminalTotalDifficulty, downloader.FullSync); err != nil {
            t.Logf("R_P2J_ABANDONED_FORK_RETRY_REJECTED attempt=%d err=%v", i+1, err)
        }
    }
    rP2JValidateCanonical(t, wireDB, wireChain, remoteB[3], bTx, aTx)
    t.Logf("R_P2J_OLD_FORK_REPLAY_CONTROL extra_body_responses=%d physical_growth=%d canonical_head=4",
        meterA.bodyResponses.Load()-oldForkResponses, rG6PhysicalBytes(t, wirePath)-oldForkBefore)

    // Compaction might reclaim stale values or amplify temporary allocation.
    // Compare after mandatory successful full compaction on both databases.
    preCompactW, preCompactD := rG6PhysicalBytes(t, wirePath), rG6PhysicalBytes(t, directPath)
    if err := wireDB.Compact(nil, nil); err != nil {
        t.Fatalf("R_P2J_WIRE_COMPACTION_FAILED: %v", err)
    }
    if err := directDB.Compact(nil, nil); err != nil {
        t.Fatalf("R_P2J_DIRECT_COMPACTION_FAILED: %v", err)
    }
    postCompactW, postCompactD := rG6PhysicalBytes(t, wirePath), rG6PhysicalBytes(t, directPath)
    rP2JValidateCanonical(t, wireDB, wireChain, remoteB[3], bTx, aTx)
    rP2JValidateCanonical(t, directDB, directChain, remoteB[3], bTx, aTx)
    t.Logf("R_P2J_COMPACTION_MATRIX wire_pre=%d wire_post=%d direct_pre=%d direct_post=%d wire_compact_delta=%d direct_compact_delta=%d ratio_post=%.3f",
        preCompactW, postCompactW, preCompactD, postCompactD,
        postCompactW-preCompactW, postCompactD-preCompactD,
        float64(postCompactW)/float64(postCompactD))

    peerServerB.Stop()
    peerServerA.Stop()
    localServer.Stop()
    remoteHandlerB.Stop()
    remoteHandlerA.Stop()
    localHandler.Stop()
    serversStopped = true

    if err := rP2JStopChain(wireBE, wireChain, wireDB); err != nil {
        t.Fatalf("R_P2J_WIRE_CLOSE_FAILED: %v", err)
    }
    wireClosed = true
    if err := rP2JStopChain(directBE, directChain, directDB); err != nil {
        t.Fatalf("R_P2J_DIRECT_CLOSE_FAILED: %v", err)
    }
    directClosed = true

    // Reopen *the same* physical persistent DBs with shipped QBFT defaults.
    // This verifies that both the B canonical receipt and A orphan rejection
    // survived LevelDB WAL replay and the earlier compaction.
    reopenedW := rQBFTOpenDisk(t, wirePath)
    chainW, beW := rQBFTEngine(t, reopenedW, f.validatorKeys[0])
    rP2JValidateCanonical(t, reopenedW, chainW, remoteB[3], bTx, aTx)
    if err := rP2JStopChain(beW, chainW, reopenedW); err != nil {
        t.Fatal(err)
    }
    reopenedD := rQBFTOpenDisk(t, directPath)
    chainD, beD := rQBFTEngine(t, reopenedD, f.validatorKeys[0])
    rP2JValidateCanonical(t, reopenedD, chainD, remoteB[3], bTx, aTx)
    if err := rP2JStopChain(beD, chainD, reopenedD); err != nil {
        t.Fatal(err)
    }
    finalW, finalD := rG6PhysicalBytes(t, wirePath), rG6PhysicalBytes(t, directPath)
    finalFree := rG6AvailBytes(t, root)
    t.Logf("R_P2J_RESTART_PERSISTENCE_PASS head=4 canonical_receipt=B1 orphan_receipt_A1=absent physical_wire=%d physical_direct=%d final_to_direct_ratio=%.3f free_start=%d free_after=%d",
        finalW, finalD, float64(finalW)/float64(finalD), healthyStart, finalFree)
    if finalFree == 0 {
        t.Fatal("R_P2J_HEALTHY_RESERVE_EXHAUSTED")
    }
    t.Log("R_P2J_P2J_VALIDATED scope=3_and_4_block_quorum_signed_forks real_ETH66=true replay_observed=true compaction=true restart=true ordinary_peer_fork_creation=NOT_PROVEN")
}
