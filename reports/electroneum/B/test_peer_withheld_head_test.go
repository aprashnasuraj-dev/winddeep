// Synthetic peer/dowloader event-path characterization; no public networking.
// This uses the actual downloader and existing eth.ETH66 response handlers.
// It does NOT establish real p2p handshake authentication or validator outage.
package downloader

import (
    "math/big"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/eth/protocols/eth"
)

func TestWorkerBWithheldPeerHeadTriggersUnverifiedSyncStart(t *testing.T) {
    for _,tc:=range []struct{
        name string
        withhold bool
    }{
        {"honest_peer_control", false},
        {"nonserving_head_peer", true},
    }{
        t.Run(tc.name,func(t *testing.T){
            tester:=newTester(t)
            defer tester.terminate()
            chain:=testChainBase.shorten(8)
            peer:=tester.newPeer("worker-b-synthetic-eth66",eth.ETH66,chain.blocks[1:])
            head,realTD:=peer.Head()
            claimedTD:=new(big.Int).Set(realTD)
            if tc.withhold {
                peer.withholdHeaders[head] = struct{}{}
                claimedTD.SetInt64(999999999)
            }
            sub:=tester.downloader.mux.Subscribe(StartEvent{},DoneEvent{},FailedEvent{})
            defer sub.Unsubscribe()
            started:=time.Now()
            // The caller supplies a claimed remote TD through the same
            // downloader API invoked by eth/chainSyncer. Here the connection
            // itself is an existing test peer, not a real p2p handshake.
            err:=tester.sync(peer.id,claimedTD,FullSync)
            observed:=make([]string,0,2)
            for len(observed)<2 {
                select {
                case ev:=<-sub.Chan():
                    if ev==nil {t.Fatal("downloader subscription terminated")}
                    switch ev.Data.(type){
                    case StartEvent: observed=append(observed,"START")
                    case DoneEvent: observed=append(observed,"DONE")
                    case FailedEvent: observed=append(observed,"FAILED")
                    }
                case <-time.After(3*time.Second):
                    t.Fatalf("did not observe two downloader sync lifecycle events; seen=%v err=%v",observed,err)
                }
            }
            if observed[0]!="START" {
                t.Fatalf("unverified sync start event missing: %v",observed)
            }
            if tc.withhold {
                if err==nil || observed[1]!="FAILED" {
                    t.Fatalf("nonserving peer unexpectedly succeeded err=%v events=%v",err,observed)
                }
                t.Logf("B_WITHHELD_HEAD_TRIGGERED_START_BEFORE_FAILURE delay_ms=%d err=%v",
                    time.Since(started).Milliseconds(),err)
            }else{
                if err!=nil || observed[1]!="DONE" {
                    t.Fatalf("honest peer failed err=%v events=%v",err,observed)
                }
                t.Log("B_HONEST_PEER_COMPLETED_SYNC")
            }
        })
    }
}
