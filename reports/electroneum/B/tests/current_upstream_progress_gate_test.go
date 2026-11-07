// Independent 2026-11-08 experiment against upstream db0eb8792dd57304fbc66a60377c7663e1bd44d2.
// An ETH66 peer serves a head by hash, then never answers ancestor requests.
// This demonstrates event ordering, NOT network-wide consensus liveness or P2.
package downloader

import (
    "math/big"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/eth/protocols/eth"
)

// The original built-in peer serves honest head and numbered headers.
// Override ONLY ancestor-number requests, preserving the actual HEAD response.
type adversarialHeadOnlyPeer struct {
    *downloadTesterPeer
    ancestorRequestSeen chan struct{}
}
func (p *adversarialHeadOnlyPeer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool, sink chan *eth.Response) (*eth.Request, error) {
    select { case p.ancestorRequestSeen <- struct{}{}: default: }
    // No response: the unauthenticated source has provided a head but not
    // proven any common ancestry, usable block body, or canonical state.
    return &eth.Request{Peer: p.id}, nil
}

func TestIndependentPostFixHeadOnlyPrematureProgress(t *testing.T) {
    tester := newTester(t)
    defer tester.terminate()
    chain := testChainBase.shorten(800 / 8)
    peer := tester.newPeer("etn-postfix-headonly-peer", eth.ETH66, chain.blocks[1:])
    head, realTD := peer.Head()
    original := tester.chain.CurrentBlock()
    // Exercise precisely the same ETH66 head-response implementation as the
    // honest peer, while suppressing every subsequent numbered ancestor reply.
    tester.downloader.UnregisterPeer(peer.id)
    blocked := &adversarialHeadOnlyPeer{downloadTesterPeer: peer, ancestorRequestSeen: make(chan struct{}, 1)}
    if err := tester.downloader.RegisterPeer(peer.id, eth.ETH66, blocked); err != nil {
        t.Fatalf("unable to register adversarial head-only peer: %v", err)
    }

    sub := tester.downloader.mux.Subscribe(StartEvent{}, ProgressEvent{}, DoneEvent{}, FailedEvent{})
    defer sub.Unsubscribe()
    result := make(chan error, 1)
    start := time.Now()
    // An advertised high TD is permitted in the ETH peer handshake; the
    // source is still untrusted and does not have validator signing keys.
    claimedTD := new(big.Int).Set(realTD)
    claimedTD.Add(claimedTD, big.NewInt(1000000000))
    go func() { result <- tester.sync(peer.id, claimedTD, FullSync) }()
    seenStart, seenProgress := false, false
    deadline := time.NewTimer(20 * time.Second)
    defer deadline.Stop()
    for !seenProgress {
        select {
        case ev := <-sub.Chan():
            if ev == nil { tester.downloader.Cancel(); t.Fatal("subscription terminated") }
            switch ev.Data.(type) {
            case StartEvent:
                seenStart = true
                t.Log("POSTFIX_HEADONLY_START")
            case ProgressEvent:
                if !seenStart { tester.downloader.Cancel(); t.Fatal("ProgressEvent preceded StartEvent") }
                seenProgress = true
            case DoneEvent:
                tester.downloader.Cancel()
                t.Fatal("download completed despite withheld ancestor responses")
            case FailedEvent:
                tester.downloader.Cancel()
                t.Fatal("download failed before head-only ProgressEvent")
            }
        case <-deadline.C:
            tester.downloader.Cancel()
            t.Fatal("no head-only ProgressEvent observed")
        }
    }
    select {
    case <-blocked.ancestorRequestSeen:
    case <-time.After(3 * time.Second):
        tester.downloader.Cancel()
        t.Fatal("downloader did not request an ancestor after ProgressEvent")
    }
    // The miner listens for ProgressEvent and pauses its worker. At this
    // instant the downloader is blocked before common-ancestor verification.
    if got := tester.chain.CurrentBlock(); got.NumberU64() != original.NumberU64() || got.Hash() != original.Hash() {
        tester.downloader.Cancel()
        t.Fatalf("unexpected canonical progress before ancestor verification: height=%d hash=%s", got.NumberU64(), got.Hash())
    }
    select {
    case err := <-result:
        tester.downloader.Cancel()
        t.Fatalf("blocked ancestor sync returned prematurely: %v", err)
    case <-time.After(400 * time.Millisecond):
    }
    t.Logf("POSTFIX_HEADONLY_PROGRESS_BEFORE_ANCESTOR head=%s canonical_height=%d duration_ms=%d no_validator_seal_checked=true",head,original.NumberU64(),time.Since(start).Milliseconds())
    tester.downloader.Cancel()
    var failed bool
    timeout := time.NewTimer(12*time.Second)
    defer timeout.Stop()
    for !failed {
        select {
        case ev := <-sub.Chan():
            if ev == nil { t.Fatal("subscriber closed before FailedEvent") }
            switch ev.Data.(type) {
            case FailedEvent: failed = true
            case DoneEvent: t.Fatal("unexpected successful sync after deliberate cancellation")
            }
        case <-timeout.C: t.Fatal("no terminal failed event after cancellation")
        }
    }
    select {
    case err := <-result:
        if err == nil { t.Fatal("cancelled head-only sync reported success") }
        t.Logf("POSTFIX_HEADONLY_RECOVERY_CONTROL_FAILED_EVENT err=%v",err)
    case <-time.After(12*time.Second):
        t.Fatal("sync did not terminate after cancellation")
    }
}

// Both strongest counterexamples are required: honest progress reaches the
// chain and withholding the head entirely does not trigger ProgressEvent.
func TestIndependentPostFixProgressHonestAndSilentControls(t *testing.T) {
    for _, tc := range []struct{name string;silent bool}{
        {"honest_full_chain",false},{"completely_silent_head",true},
    } {
        t.Run(tc.name,func(t *testing.T) {
            tester:=newTester(t)
            defer tester.terminate()
            chain:=testChainBase.shorten(800/8)
            peer:=tester.newPeer("etn-postfix-control-peer",eth.ETH66,chain.blocks[1:])
            head,td:=peer.Head()
            if tc.silent {peer.withholdHeaders[head]=struct{}{}}
            sub:=tester.downloader.mux.Subscribe(StartEvent{}, ProgressEvent{}, DoneEvent{}, FailedEvent{})
            defer sub.Unsubscribe()
            result:=make(chan error,1)
            go func(){result<-tester.sync(peer.id,td,FullSync)}()
            gotStart,gotProgress,terminal:=false,false,false
            deadline:=time.NewTimer(30*time.Second)
            defer deadline.Stop()
            for !terminal {
                select {
                case ev:=<-sub.Chan():
                    if ev==nil {tester.downloader.Cancel(); t.Fatal("subscriber ended")}
                    switch ev.Data.(type) {
                    case StartEvent:gotStart=true
                    case ProgressEvent:gotProgress=true
                    case DoneEvent:
                        if tc.silent {t.Fatal("silent peer completed")}
                        terminal=true
                    case FailedEvent:
                        if !tc.silent {t.Fatal("honest peer failed")}
                        terminal=true
                    }
                case <-deadline.C:
                    tester.downloader.Cancel()
                    t.Fatal("control sync timed out")
                }
            }
            var err error
            select {case err=<-result:case <-time.After(10*time.Second):t.Fatal("control sync did not return")}
            if !gotStart {t.Fatal("missing StartEvent")}
            if tc.silent {
                if err==nil || gotProgress || tester.chain.CurrentBlock().NumberU64()!=0 {
                    t.Fatalf("headless control bypassed guard: err=%v progressed=%v height=%d",err,gotProgress,tester.chain.CurrentBlock().NumberU64())
                }
                t.Log("POSTFIX_HEADLESS_GUARD_PASSED no_progress_event=true")
            } else {
                if err!=nil || !gotProgress || tester.chain.CurrentBlock().Hash()!=head {
                    t.Fatalf("honest control invalid: err=%v progress=%v head=%s expected=%s",err,gotProgress,tester.chain.CurrentBlock().Hash(),head)
                }
                t.Logf("POSTFIX_HONEST_CONTROL_CANONICAL_COMPLETE height=%d",tester.chain.CurrentBlock().NumberU64())
            }
        })
    }
}

// A true remote peer does not need a validator key to return a head by hash.
// This compile-time type check prevents silently replacing the peer with a
// synthetic event publisher that skips the actual downloader request logic.
var _ Peer = (*adversarialHeadOnlyPeer)(nil)
var _ = common.Hash{}
