//go:build linux

// Worker R P2k: unprivileged ETH66 replay, unsolicited request-ID probes and
// long-chain storage-churn oracle. All seals are prepared before network
// transport. The adversarial peer receives ZERO validator keys.
package eth

import (
    "bytes"
    "fmt"
    "io"
    "math"
    "os"
    "path/filepath"
    "sync"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
    "github.com/electroneum/electroneum-sc/p2p"
    "github.com/electroneum/electroneum-sc/rlp"
)

const rP2KHeights = 8

// Only the remote devp2p transport is modified. This wrapper copies a
// genuine, once-requested BlockBodiesPacket66, preserves it unmodified for the
// normal downloader import, and later sends it with its old or an unrelated
// RequestId. There is no new block, state or signed consensus packet.
type rP2KMaliciousWriter struct {
    p2p.MsgReadWriter
    mu sync.Mutex
    lastBody []byte
    legitimate int64
    legitimateBytes int64
    injected int64
    injectedBytes int64
}

func (w *rP2KMaliciousWriter) WriteMsg(msg p2p.Msg) error {
    if msg.Code != ethproto.BlockBodiesMsg {
        w.mu.Lock()
        defer w.mu.Unlock()
        return w.MsgReadWriter.WriteMsg(msg)
    }
    raw, err := io.ReadAll(msg.Payload)
    if err != nil { return err }
    msg.Payload = bytes.NewReader(raw)
    msg.Size = uint32(len(raw))
    w.mu.Lock()
    defer w.mu.Unlock()
    if err := w.MsgReadWriter.WriteMsg(msg); err != nil { return err }
    w.lastBody = append(w.lastBody[:0], raw...)
    w.legitimate++
    w.legitimateBytes += int64(len(raw))
    return nil
}

// Inject has two strictly lower-authority modes: "stale-id" reuses an ID from
// a completed block download, and "unrequested-id" creates an unrelated ID.
// Neither mode controls signed block headers, quorum, or request creation.
func (w *rP2KMaliciousWriter) Inject(mode string) (int, uint64, error) {
    w.mu.Lock()
    defer w.mu.Unlock()
    if len(w.lastBody) == 0 { return 0, 0, fmt.Errorf("R_P2K_NO_CAPTURED_BODY") }
    var reply struct {
        RequestId uint64
        Payload rlp.RawValue
    }
    if err := rlp.DecodeBytes(w.lastBody, &reply); err != nil {
        return 0, 0, fmt.Errorf("R_P2K_CAPTURED_RLP_INVALID: %w", err)
    }
    raw := w.lastBody
    id := reply.RequestId
    switch mode {
    case "stale-id":
        // Replay the same serialized body response and old request ID.
    case "unrequested-id":
        id ^= uint64(1) << 63
        reply.RequestId = id
        forged, err := rlp.EncodeToBytes(&reply)
        if err != nil { return 0, id, err }
        raw = forged
    default:
        return 0, 0, fmt.Errorf("R_P2K_BAD_ATTACK_MODE %s", mode)
    }
    if len(raw) >= 10<<20 { return 0, id, fmt.Errorf("R_P2K_PACKET_TOO_BIG %d", len(raw)) }
    msg := p2p.Msg{Code:ethproto.BlockBodiesMsg, Size:uint32(len(raw)), Payload:bytes.NewReader(raw)}
    if err := w.MsgReadWriter.WriteMsg(msg); err != nil { return 0, id, err }
    w.injected++
    w.injectedBytes += int64(len(raw))
    return len(raw), id, nil
}

type rP2KRemoteState struct {
    mu sync.Mutex
    writer *rP2KMaliciousWriter
}
func (s *rP2KRemoteState) current() *rP2KMaliciousWriter {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.writer
}
func rP2KRemoteServer(t *testing.T, name string, remote *handler) (*p2p.Server, *rP2KRemoteState) {
    t.Helper()
    key, err := crypto.GenerateKey()
    if err != nil { t.Fatal(err) }
    state := new(rP2KRemoteState)
    protocols := ethproto.MakeProtocols((*ethHandler)(remote), 1, nil)
    for i := range protocols {
        original := protocols[i].Run
        protocols[i].Run = func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
            observed := &rP2KMaliciousWriter{MsgReadWriter:rw}
            state.mu.Lock()
            state.writer = observed
            state.mu.Unlock()
            return original(peer, observed)
        }
    }
    server := &p2p.Server{Config:p2p.Config{
        Name:name, PrivateKey:key, MaxPeers:1, NoDiscovery:true, NoDial:true,
        ListenAddr:"127.0.0.1:0", Protocols:protocols,
    }}
    if err := server.Start(); err != nil { t.Fatalf("R_P2K_REMOTE_START_FAIL: %v", err) }
    return server, state
}

func rP2KHealthyDisk(t *testing.T, root string) {
    t.Helper()
    free := rG6AvailBytes(t, root)
    if free < 128<<20 {
        t.Fatalf("R_P2K_HEALTHY_DISK_PRECONDITION_FAILED free=%d", free)
    }
}

func TestRQBFTUnprivilegedETH66ReplayAndLongChainDisk(t *testing.T) {
    root := os.Getenv("R_P2K_DISK_ROOT")
    if root == "" { t.Skip("R_P2K_DISK_ROOT not configured") }
    if err := os.MkdirAll(root, 0700); err != nil { t.Fatal(err) }
    rP2KHealthyDisk(t, root)
    reserveStart := rG6AvailBytes(t, root)

    f, senderKey := rP1HBaseFixture(t)
    defer f.close()
    // 8 independently signed QBFT-finalized blocks with distinct, 128 KiB
    // realistic noncompressible calldata each (>= 1 MiB total chain bodies).
    // The test fixture, not the peer, has validators' signing credentials.
    blocks := make(types.Blocks, 0, rP2KHeights)
    var firstTx *types.Transaction
    for i:=0; i<rP2KHeights; i++ {
        tx := rP2JTransaction(t, f.remoteChain, senderKey, 'K', byte(i+1))
        if i==0 { firstTx = tx }
        blocks = append(blocks, rQBFTBuildAndImport(t,
            f.remoteChain, f.remoteQBFT, f.remoteDB, f.validatorKeys, f.validators, tx))
    }
    if blocks[len(blocks)-1].NumberU64() != rP2KHeights { t.Fatal("R_P2K_BAD_HEIGHT") }
    for blocks[len(blocks)-1].Time() > uint64(time.Now().Unix())+5 {
        time.Sleep(100*time.Millisecond)
    }
    t.Logf("R_P2K_VALID_QUORUM_FIXTURE_PASS blocks=%d payload_bytes_min=%d heads_sealed_with=3of4 time_now=%d time_tip=%d peer_validator_keys=0",
        len(blocks), len(blocks)*rP2JPayload, time.Now().Unix(), blocks[len(blocks)-1].Time())

    genesis := rQBFTNetworkGenesis(t, f.validatorKeys, crypto.PubkeyToAddress(senderKey.PublicKey))
    wirePath := filepath.Join(root, "wire")
    directPath := filepath.Join(root, "direct")
    wireDB, wireChain, wireBE := rP2JDiskChain(t, wirePath, genesis, f.validatorKeys[0])
    directDB, directChain, directBE := rP2JDiskChain(t, directPath, genesis, f.validatorKeys[0])
    wireClosed, directClosed := false,false
    t.Cleanup(func() {
        if !wireClosed { _ = rP2JStopChain(wireBE,wireChain,wireDB) }
        if !directClosed { _ = rP2JStopChain(directBE,directChain,directDB) }
    })
    directBefore := rG6PhysicalBytes(t, directPath)
    if index,err:=directChain.InsertChain(blocks);err!=nil {
        t.Fatalf("R_P2K_DIRECT_CHAIN_FAILED index=%d err=%v",index,err)
    }
    directAfter := rG6PhysicalBytes(t, directPath)
    rP2JValidateCanonical(t,directDB,directChain,blocks[len(blocks)-1],firstTx,nil)

    localHandler := rDevP2PHandler(t, wireDB, wireChain)
    remoteHandler := rDevP2PHandler(t, f.remoteDB, f.remoteChain)
    localServer := rDevP2PServer(t,"r-p2k-local",localHandler,false)
    handlersStopped := false
    t.Cleanup(func() {
        if !handlersStopped {
            localServer.Stop()
            localHandler.Stop()
            remoteHandler.Stop()
        }
    })
    remote1, state1 := rP2KRemoteServer(t,"r-p2k-remote-stale",remoteHandler)
    remote1Stopped:=false
    t.Cleanup(func(){if !remote1Stopped {remote1.Stop()}})

    wireBefore := rG6PhysicalBytes(t,wirePath)
    localServer.AddPeer(remote1.Self())
    peer1 := rP1HWaitRegisteredPeer(t,localHandler,remote1)
    firstHash, firstTD:=peer1.Head()
    if firstHash!=blocks[len(blocks)-1].Hash() {
        t.Fatalf("R_P2K_BAD_ADVERTISED_TIP got=%s want=%s",firstHash,blocks[len(blocks)-1].Hash())
    }
    if err:=localHandler.downloader.LegacySync(peer1.ID(),firstHash,firstTD,
        wireChain.Config().TerminalTotalDifficulty,downloader.FullSync);err!=nil {
        t.Fatalf("R_P2K_LONGCHAIN_ETH66_SYNC_FAIL: %v",err)
    }
    rP2JValidateCanonical(t,wireDB,wireChain,blocks[len(blocks)-1],firstTx,nil)
    wireAfter:=rG6PhysicalBytes(t,wirePath)
    writer1:=state1.current()
    if writer1==nil || writer1.legitimate==0 { t.Fatal("R_P2K_NO_ACTUAL_ETH66_BODIES") }
    t.Logf("R_P2K_LONGCHAIN_BASELINE blocks=%d wire_growth=%d direct_growth=%d wire_to_direct=%.3f eth66_body_packets=%d bytes=%d",
        rP2KHeights,wireAfter-wireBefore,directAfter-directBefore,
        float64(wireAfter-wireBefore)/math.Max(1,float64(directAfter-directBefore)),
        writer1.legitimate,writer1.legitimateBytes)

    // First exercise standard duplicate downloader requests while the head
    // is unchanged, then explicitly inject an unsolicited stale-ID packet.
    duplicateBefore:=rG6PhysicalBytes(t,wirePath)
    duplicateBodiesBefore:=writer1.legitimate
    for i:=0;i<4;i++ {
        if err:=localHandler.downloader.LegacySync(peer1.ID(),firstHash,firstTD,
            wireChain.Config().TerminalTotalDifficulty,downloader.FullSync); err!=nil {
            t.Logf("R_P2K_REPEAT_SYNC_REJECTED attempt=%d err=%v",i+1,err)
        }
    }
    t.Logf("R_P2K_DUPLICATE_DOWNLOADER_RESULT requests=4 extra_body_packets=%d physical_growth=%d",
        writer1.legitimate-duplicateBodiesBefore,rG6PhysicalBytes(t,wirePath)-duplicateBefore)
    rP2JValidateCanonical(t,wireDB,wireChain,blocks[len(blocks)-1],firstTx,nil)

    staleBefore:=rG6PhysicalBytes(t,wirePath)
    staleLength,staleID,err:=writer1.Inject("stale-id")
    if err!=nil { t.Fatalf("R_P2K_STALE_INJECTION_NOT_SENT: %v",err) }
    // A dangling ID is a protocol error; measure when the peer detaches.
    rWaitFor(t,5*time.Second,"R_P2K_STALE_PEER_NOT_DISCONNECTED",func()bool{
        return localHandler.peers.peer(remote1.Self().ID().String())==nil
    })
    staleGrowth:=rG6PhysicalBytes(t,wirePath)-staleBefore
    rP2JValidateCanonical(t,wireDB,wireChain,blocks[len(blocks)-1],firstTx,nil)
    t.Logf("R_P2K_STALE_ID_REPLAY_RESULT wire_packet_bytes=%d old_request_id=%d peer_disconnected=true physical_growth=%d canonical_head=%d",
        staleLength,staleID,staleGrowth,wireChain.CurrentBlock().NumberU64())

    // Separate *fresh p2p identity* from the first disconnected peer. The
    // attacker can send completely unknown request IDs, but still has no
    // validator signing keys or any way to make a new valid canonical block.
    localServer.RemovePeer(remote1.Self())
    remote1.Stop()
    remote1Stopped=true
    remote2,state2:=rP2KRemoteServer(t,"r-p2k-remote-unrequested",remoteHandler)
    remote2Stopped:=false
    t.Cleanup(func(){if !remote2Stopped {remote2.Stop()}})
    localServer.AddPeer(remote2.Self())
    _=rP1HWaitRegisteredPeer(t,localHandler,remote2)
    writer2:=state2.current()
    if writer2==nil {t.Fatal("R_P2K_UNKNOWN_REMOTE_WRITER_MISSING")}
    // Because this node has already synchronized, no new block-body request
    // is expected. Seed a genuine observed payload from the earlier signed
    // chain, but alter its request ID. This is a body the peer can read, not
    // a header or receipt forged with validator authority.
    writer1.mu.Lock()
    historical:=append([]byte(nil),writer1.lastBody...)
    writer1.mu.Unlock()
    writer2.mu.Lock()
    writer2.lastBody=historical
    writer2.mu.Unlock()
    unknownBefore:=rG6PhysicalBytes(t,wirePath)
    size,unknownID,err:=writer2.Inject("unrequested-id")
    if err!=nil {t.Fatalf("R_P2K_UNKNOWN_INJECTION_NOT_SENT: %v",err)}
    rWaitFor(t,5*time.Second,"R_P2K_UNKNOWN_PEER_NOT_DISCONNECTED",func()bool{
        return localHandler.peers.peer(remote2.Self().ID().String())==nil
    })
    unknownGrowth:=rG6PhysicalBytes(t,wirePath)-unknownBefore
    rP2JValidateCanonical(t,wireDB,wireChain,blocks[len(blocks)-1],firstTx,nil)
    t.Logf("R_P2K_UNKNOWN_ID_REPLAY_RESULT wire_packet_bytes=%d unknown_request_id=%d peer_disconnected=true physical_growth=%d canonical_head=%d",
        size,unknownID,unknownGrowth,wireChain.CurrentBlock().NumberU64())

    remote2.Stop()
    remote2Stopped=true
    localServer.Stop()
    remoteHandler.Stop()
    localHandler.Stop()
    handlersStopped=true

    compactBeforeW,compactBeforeD:=rG6PhysicalBytes(t,wirePath),rG6PhysicalBytes(t,directPath)
    if err:=wireDB.Compact(nil,nil);err!=nil {t.Fatalf("R_P2K_WIRE_COMPACT_ERROR: %v",err)}
    if err:=directDB.Compact(nil,nil);err!=nil {t.Fatalf("R_P2K_DIRECT_COMPACT_ERROR: %v",err)}
    compactAfterW,compactAfterD:=rG6PhysicalBytes(t,wirePath),rG6PhysicalBytes(t,directPath)
    t.Logf("R_P2K_COMPACTION_CONTROL wire_pre=%d direct_pre=%d wire_post=%d direct_post=%d",
        compactBeforeW,compactBeforeD,compactAfterW,compactAfterD)
    rP2JValidateCanonical(t,wireDB,wireChain,blocks[len(blocks)-1],firstTx,nil)

    if err:=rP2JStopChain(wireBE,wireChain,wireDB);err!=nil {t.Fatal(err)}
    wireClosed=true
    if err:=rP2JStopChain(directBE,directChain,directDB);err!=nil {t.Fatal(err)}
    directClosed=true
    reopenW:=rQBFTOpenDisk(t,wirePath)
    chainW,beW:=rQBFTEngine(t,reopenW,f.validatorKeys[0])
    rP2JValidateCanonical(t,reopenW,chainW,blocks[len(blocks)-1],firstTx,nil)
    if err:=rP2JStopChain(beW,chainW,reopenW);err!=nil {t.Fatal(err)}
    reopenD:=rQBFTOpenDisk(t,directPath)
    chainD,beD:=rQBFTEngine(t,reopenD,f.validatorKeys[0])
    rP2JValidateCanonical(t,reopenD,chainD,blocks[len(blocks)-1],firstTx,nil)
    if err:=rP2JStopChain(beD,chainD,reopenD);err!=nil {t.Fatal(err)}
    finalW,finalD:=rG6PhysicalBytes(t,wirePath),rG6PhysicalBytes(t,directPath)
    available:=rG6AvailBytes(t,root)
    ratio:=float64(finalW)/math.Max(1,float64(finalD))
    t.Logf("R_P2K_RESTART_DISK_ORACLE_PASS blocks=%d final_wire=%d final_direct=%d ratio=%.3f healthy_free_before=%d healthy_free_after=%d stale_replay_delta=%d unknown_replay_delta=%d",
        rP2KHeights,finalW,finalD,ratio,reserveStart,available,staleGrowth,unknownGrowth)
    if finalW>finalD+64*1024 {
        t.Fatalf("R_P2K_UNEXPECTED_PERSISTENT_EXCESS wire=%d direct=%d excess=%d; investigate before classifying",finalW,finalD,finalW-finalD)
    }
    if available<100<<20 {
        t.Fatalf("R_P2K_HEALTHY_RESERVE_EXHAUSTED bytes_remaining=%d",available)
    }
    t.Log("R_P2K_P2K_VALIDATED 8block_quorum_signed_history_only_by_fixture=true unprivileged_replayed_bodies=true old_and_unknown_request_ids=true no_peer_validator_signing=true canonical_integrity=true longchain_direct_control=true compaction_and_restart=true")
}
