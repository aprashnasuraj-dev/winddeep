// Isolated ETH66 wire-protocol reachability test for the post-#94 early
// ProgressEvent: a genuine two-ended etn/66 message pipe, with correct status,
// network and genesis handshake. NOT a TCP/devp2p encrypted transport test,
// NOT a QBFT validator-network halt, and never connect to public peers.
package eth

import (
    "fmt"
    "sync/atomic"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
    "github.com/electroneum/electroneum-sc/p2p"
    "github.com/electroneum/electroneum-sc/p2p/enode"
)

// The honest full node and empty node still perform a real eth/66 status
// handshake and request/response encoding. Only the remote node's outbound
// BlockHeaders responses are filtered after its first response.
type independentWireHeadOnlyResponse struct {
    p2p.MsgReadWriter
    headerResponses atomic.Int32
    blockedReplies chan struct{}
}
func (rw *independentWireHeadOnlyResponse) WriteMsg(msg p2p.Msg) error {
    if msg.Code == ethproto.BlockHeadersMsg {
        n := rw.headerResponses.Add(1)
        if n > 1 {
            _ = msg.Discard()
            select { case rw.blockedReplies <- struct{}{}: default: }
            return nil
        }
    }
    return rw.MsgReadWriter.WriteMsg(msg)
}

func TestIndependentPostFixRealEth66HeadOnlyProtocol(t *testing.T) {
    empty := newTestHandler()
    defer empty.close()
    full := newTestHandlerWithBlocks(256)
    defer full.close()

    sub := empty.handler.eventMux.Subscribe(
        downloader.StartEvent{}, downloader.ProgressEvent{},
        downloader.DoneEvent{}, downloader.FailedEvent{},
    )
    defer sub.Unsubscribe()

    emptyRW, fullRW := p2p.MsgPipe()
    defer emptyRW.Close()
    defer fullRW.Close()
    caps := []p2p.Cap{{Name:"etn",Version:ethproto.ETH66}}
    peerOnEmpty := ethproto.NewPeer(ethproto.ETH66,
        p2p.NewPeer(enode.ID{1},"connected-full-peer",caps), emptyRW,empty.txpool)
    filtered := &independentWireHeadOnlyResponse{
        MsgReadWriter:fullRW, blockedReplies:make(chan struct{},4),
    }
    peerOnFull := ethproto.NewPeer(ethproto.ETH66,
        p2p.NewPeer(enode.ID{2},"connected-empty-peer",caps), filtered,full.txpool)
    defer peerOnEmpty.Close()
    defer peerOnFull.Close()
    errors := make(chan error,2)
    go func(){errors <- empty.handler.runEthPeer(peerOnEmpty,func(p *ethproto.Peer) error {
        return ethproto.Handle((*ethHandler)(empty.handler),p)
    })}()
    go func(){errors <- full.handler.runEthPeer(peerOnFull,func(p *ethproto.Peer) error {
        return ethproto.Handle((*ethHandler)(full.handler),p)
    })}()
    deadline := time.Now().Add(7*time.Second)
    for empty.handler.peers.len() < 1 || full.handler.peers.len() < 1 {
        if time.Now().After(deadline) {
            t.Fatal("ordinary eth/66 status handshake did not register both peers")
        }
        select {
        case err := <-errors:
            t.Fatalf("protocol handshake rejected peer: %v",err)
        default:
        }
        time.Sleep(10*time.Millisecond)
    }
    p := empty.handler.peers.peerWithHighestTD()
    if p == nil {t.Fatal("no successfully handshaken peer selected")}
    op := peerToSyncOp(downloader.FullSync,p)
    if op.td.Sign() <= 0 {t.Fatal("peer advertised empty total difficulty")}
    before := empty.chain.CurrentBlock()
    t.Logf("WIRE_ETN66_STATUS_HANDSHAKE_OK peer_id=%s advertised_head=%s advertised_td=%s",p.ID(),op.head,op.td)

    result := make(chan error,1)
    go func(){result <- empty.handler.doSync(op)}()
    hasProgress, hasBlockedAncestor := false,false
    limit := time.NewTimer(16*time.Second)
    defer limit.Stop()
    for !hasProgress || !hasBlockedAncestor {
        select {
        case ev := <-sub.Chan():
            if ev == nil {t.Fatal("event subscription closed")}
            switch ev.Data.(type) {
            case downloader.ProgressEvent: hasProgress=true
            case downloader.DoneEvent:
                t.Fatal("head-only peer reached successful synchronization")
            case downloader.FailedEvent:
                t.Fatal("head-only peer failed before ancestor withholding was observed")
            }
        case <-filtered.blockedReplies:
            hasBlockedAncestor=true
        case err := <-result:
            t.Fatalf("head-only wire peer synchronization ended before expected boundary: %v",err)
        case <-limit.C:
            empty.handler.downloader.Cancel()
            t.Fatalf("wire protocol boundary incomplete: progress=%v blocked_ancestor=%v sent_headers=%d",hasProgress,hasBlockedAncestor,filtered.headerResponses.Load())
        }
    }
    if empty.chain.CurrentBlock().Hash()!=before.Hash() {
        empty.handler.downloader.Cancel()
        t.Fatal("wire protocol peer unexpectedly altered canonical head")
    }
    select {
    case err:=<-result:
        t.Fatalf("sync exited while the network peer was withholding headers: %v",err)
    case <-time.After(350*time.Millisecond):
    }
    t.Logf("WIRE_ETN66_HEADONLY_PROGRESS_WITH_UNVERIFIED_ANCESTRY header_messages=%d canonical_height=%d progress_before_ancestor_valid=true",
        filtered.headerResponses.Load(),empty.chain.CurrentBlock().NumberU64())
    // Model a remote peer disconnect after the withheld reply. Closing the
    // actual protocol pipes is necessary to release outstanding request
    // tracking; merely canceling the downloader is not always enough.
    _ = emptyRW.Close()
    _ = fullRW.Close()
    empty.handler.downloader.Cancel()
    select {
    case err:=<-result:
        if err==nil{t.Fatal("cancelled downloader returned success")}
        t.Logf("WIRE_ETN66_PEER_DISCONNECT_RECOVERED error=%v",err)
    case <-time.After(10*time.Second):
        t.Fatal("wire downloader failed to terminate after real message pipes closed")
    }
    select {
    case err:=<-errors:
        t.Logf("WIRE_ETN66_PROTOCOL_TERMINAL_EVENT err=%v",err)
    default:
        _=fmt.Sprintf("protocol still registered prior to cleanup")
    }
}
