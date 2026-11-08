package backend

import (
 "bytes"
 "fmt"
 "math/big"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/p2p"
 "github.com/electroneum/electroneum-sc/rlp"
)

// Isolated backend ingress discriminator: an ordinary non-validator relay
// sends a legitimate validator-signed PREPARE before the validator sends it.
// A network-level finality or default P2P reachability claim is NOT made.
func TestLiveBOutsiderRelayPreemption(t *testing.T) {
 for _,tag:=range []byte{101,103,107} {
  t.Run(fmt.Sprintf("fresh_state_%d",tag),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(4)
   outsider,e:=crypto.GenerateKey();if e!=nil{t.Fatal(e)}
   honest:=crypto.PubkeyToAddress(keys[1].PublicKey)
   relay:=crypto.PubkeyToAddress(outsider.PublicKey)
   msg:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),crypto.Keccak256Hash([]byte{tag,0xc3}))
   unsigned,e:=msg.EncodePayloadForSigning();if e!=nil{t.Fatal(e)}
   sig,e:=crypto.Sign(crypto.Keccak256(unsigned),keys[1]);if e!=nil{t.Fatal(e)}
   msg.SetSignature(sig)
   wire,e:=rlp.EncodeToBytes(msg);if e!=nil{t.Fatal(e)}
   run:=func(preempt bool)(int,error){
    chain,b:=newBlockchainFromConfig(genesis,keys,*istanbul.DefaultConfig)
    defer b.Stop()
    sub:=b.EventMux().Subscribe(istanbul.MessageEvent{})
    defer sub.Unsubscribe()
    deliver:=func(from [20]byte)(bool,error){
     done:=make(chan error,1)
     go func(){
      handled,err:=b.HandleMsg(from,p2p.Msg{Code:qbfttypes.PrepareCode,Size:uint32(len(wire)),Payload:bytes.NewReader(wire)})
      if !handled||err!=nil {done<-fmt.Errorf("handled=%v err=%v",handled,err)}else{done<-nil}
     }()
     seen:=false
     select{
     case ev:=<-sub.Chan():
      m,ok:=ev.Data.(istanbul.MessageEvent)
      seen=ok&&m.Code==qbfttypes.PrepareCode
     case <-time.After(400*time.Millisecond):
     }
     select{
     case err:=<-done:return seen,err
     case <-time.After(2*time.Second):return seen,fmt.Errorf("HandleMsg timeout")
     }
    }
    count:=0
    if preempt {
     seen,err:=deliver(relay);if err!=nil{return count,err};if seen{count++}
    }
    seen,err:=deliver(honest);if err!=nil{return count,err};if seen{count++}
    if chain.CurrentBlock().NumberU64()!=0{return count,fmt.Errorf("unexpected canonical advancement")}
    return count,nil
   }
   clean,e:=run(false);if e!=nil{t.Fatal(e)}
   attack,e:=run(true);if e!=nil{t.Fatal(e)}
   t.Logf("B_OUTSIDER_RELAY_PREEMPTION state=%d baseline_events=%d replay_then_honest_events=%d expected_honest_delivery=true canonical_advanced=false",tag,clean,attack)
   if clean!=1{t.Fatalf("invalid honest baseline: %d",clean)}
   // A relay event alone is not an accepted QBFT vote or finality impact.
  })
 }
}
