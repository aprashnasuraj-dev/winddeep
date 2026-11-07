// Test the untrusted header->ancestor boundary of the November 2026 ProgressEvent fix.
// Bounded offline downloader fixture, no network and no real validators.
package downloader

import (
    "math/big"
    "sync/atomic"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/eth/protocols/eth"
)

// The peer supplies its advertised head, but defers ancestor replies.
// This is a minimal protocol mock: it does NOT prove production network ingress.
type proofGapPeer struct {
    *downloadTesterPeer
    ancestorRequests atomic.Int32
    replyDelay time.Duration
}

func (p *proofGapPeer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool, sink chan *eth.Response) (*eth.Request, error) {
    p.ancestorRequests.Add(1)
    req := &eth.Request{Peer:p.id}
    go func() {
        time.Sleep(p.replyDelay)
        empty := []*types.Header{}
        select {
        case sink <- &eth.Response{
            Req: req, Res: (*eth.BlockHeadersPacket)(&empty),
            Meta: []common.Hash{}, Time: 1, Done: make(chan error, 1),
        }:
        case <-time.After(time.Second):
        }
    }()
    return req,nil
}

func TestPatchedProgressIsBeforeAncestorValidation(t *testing.T) {
    tester := newTester(t)
    defer tester.terminate()
    blocks := testChainBase.shorten(800 / 8)
    rawPeer := tester.newPeer("head-only-untrusted-peer", eth.ETH66, blocks.blocks[1:])
    // Replace the downloader's peer interface with a head-only peer. It still
    // responds to the first hash query, but delays all number-based queries.
    tester.downloader.UnregisterPeer(rawPeer.id)
    adversary := &proofGapPeer{downloadTesterPeer: rawPeer, replyDelay: 800 * time.Millisecond}
    if err := tester.downloader.RegisterPeer(rawPeer.id, eth.ETH66, adversary); err != nil {
        t.Fatal(err)
    }
    head, realTD := rawPeer.Head()
    if head == (common.Hash{}) { t.Fatal("missing advertised head") }
    claimedTD := new(big.Int).Set(realTD)
    claimedTD.Add(claimedTD, big.NewInt(1000000))

    sub := tester.downloader.mux.Subscribe(StartEvent{}, ProgressEvent{}, FailedEvent{}, DoneEvent{})
    defer sub.Unsubscribe()
    result := make(chan error,1)
    go func() { result <- tester.sync(rawPeer.id, claimedTD, FullSync) }()

    var sawStart, sawProgress, sawFailed, sawDone bool
    var progressAt time.Time
    deadline := time.NewTimer(5*time.Second)
    defer deadline.Stop()
    for !sawFailed && !sawDone {
        select {
        case ev := <-sub.Chan():
            if ev == nil { t.Fatal("event channel closed") }
            switch ev.Data.(type) {
            case StartEvent:
                sawStart=true
            case ProgressEvent:
                sawProgress=true
                progressAt=time.Now()
                t.Log("PATCH_PROOF_GAP_EVENT progress_before_ancestor=true")
            case FailedEvent:
                sawFailed=true
            case DoneEvent:
                sawDone=true
            }
        case <-deadline.C:
            tester.downloader.Cancel()
            t.Fatalf("bounded downloader did not stop start=%t progress=%t",sawStart,sawProgress)
        }
    }
    var err error
    select {
    case err=<-result:
    case <-time.After(3*time.Second):
        tester.downloader.Cancel()
        t.Fatal("sync goroutine stuck")
    }
    if !sawStart || !sawProgress || !sawFailed || sawDone || err==nil {
        t.Fatalf("unexpected lifecycle start=%t progress=%t failed=%t done=%t err=%v",
            sawStart,sawProgress,sawFailed,sawDone,err)
    }
    if adversary.ancestorRequests.Load()==0 {
        t.Fatal("the test did not reach the ancestor verification stage")
    }
    delay:=time.Since(progressAt)
    if delay < 400*time.Millisecond {
        t.Fatalf("progress did not precede delayed ancestor validation: elapsed=%s",delay)
    }
    if tester.chain.CurrentBlock().NumberU64()!=0 {
        t.Fatal("malicious head-only peer modified canonical chain")
    }
    t.Logf("PATCH_PROOF_GAP_CONFIRMED progress_before_ancestor=true ancestor_queries=%d hold_ms=%d final_error=%v local_height=0",
        adversary.ancestorRequests.Load(),delay.Milliseconds(),err)
}
