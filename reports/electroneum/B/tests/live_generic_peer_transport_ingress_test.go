package backend

import (
 "fmt"
 "math/big"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

// Discriminator: an ordinary nonvalidator transport sender sends a correctly
// validator-signed PREPARE through the generic Peer.SendConsensus path.
// Backend event delivery is NOT evidence of QBFT vote acceptance or P2P
// handshake reachability. This probes a previously silent transport adapter.
func TestLiveBGenericPeerTransportIngress(t *testing.T) {
 for _,tag:=range []byte{131,137,139} {
  t.Run(fmt.Sprintf("independent_genesis_%d",tag),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(4)
   outsider,err:=crypto.GenerateKey();if err!=nil{t.Fatal(err)}
   signed:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),crypto.Keccak256Hash([]byte{tag,0x8e}))
   payload,err:=signed.EncodePayloadForSigning();if err!=nil{t.Fatal(err)}
   sig,err:=crypto.Sign(crypto.Keccak256(payload),keys[1]);if err!=nil{t.Fatal(err)}
   signed.SetSignature(sig)
   run:=func(senderIsOutsider bool)(bool,uint64,error){
    chain,b:=newBlockchainFromConfig(genesis,keys,*istanbul.DefaultConfig)
    defer b.Stop()
    dest:=crypto.PubkeyToAddress(keys[0].PublicKey)
    sender:=crypto.PubkeyToAddress(keys[1].PublicKey)
    if senderIsOutsider {sender=crypto.PubkeyToAddress(outsider.PublicKey)}
    net:=&liveBNet{nodes:map[common.Address]*liveBNetNode{}}
    net.nodes[dest]=&liveBNetNode{b:b,chain:chain,addr:dest}
    sub:=b.EventMux().Subscribe(istanbul.MessageEvent{})
    defer sub.Unsubscribe()
    done:=make(chan error,1)
    go func(){done<-(&liveBNetPeer{net:net,source:sender,destination:dest}).SendConsensus(qbfttypes.PrepareCode,signed)}()
    seen:=false
    select{
    case event:=<-sub.Chan():
     msg,ok:=event.Data.(istanbul.MessageEvent)
     seen=ok&&msg.Code==qbfttypes.PrepareCode
    case <-time.After(600*time.Millisecond):
    }
    select{
    case err:=<-done:return seen,chain.CurrentBlock().NumberU64(),err
    case <-time.After(2*time.Second):return seen,chain.CurrentBlock().NumberU64(),fmt.Errorf("transport blocked")
    }
   }
   honest,height,err:=run(false);if err!=nil{t.Fatal(err)}
   outsiderSeen,outsiderHeight,err:=run(true);if err!=nil{t.Fatal(err)}
   t.Logf("B_GENERIC_PEER_TRANSPORT_ORACLE genesis_tag=%d honest_dispatch=%v outsider_dispatch=%v honest_height=%d outsider_height=%d accepted_vote=NOT_MEASURED",tag,honest,outsiderSeen,height,outsiderHeight)
   if !honest {t.Fatal("honest transport baseline failed")}
   if height!=0||outsiderHeight!=0 {t.Fatal("unexpected canonical advancement")}
  })
 }
}

 
// TestLiveBFutureHeightOutsiderSequence checks whether a non-validator
// transport sender can inject a validator-signed future-height message
// before a current-height honest message. It does not claim P2P admission.
func TestLiveBFutureHeightOutsiderSequence(t *testing.T) {
 for _,tag:=range []byte{151,157,163} {
  t.Run(fmt.Sprintf("state_%d",tag),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(4)
   outsider,err:=crypto.GenerateKey();if err!=nil{t.Fatal(err)}
   chain,b:=newBlockchainFromConfig(genesis,keys,*istanbul.DefaultConfig)
   defer b.Stop()
   dest:=crypto.PubkeyToAddress(keys[0].PublicKey)
   honest:=crypto.PubkeyToAddress(keys[1].PublicKey)
   relay:=crypto.PubkeyToAddress(outsider.PublicKey)
   net:=&liveBNet{nodes:map[common.Address]*liveBNetNode{}}
   net.nodes[dest]=&liveBNetNode{b:b,chain:chain,addr:dest}
   sub:=b.EventMux().Subscribe(istanbul.MessageEvent{})
   defer sub.Unsubscribe()
   send:=func(height int64,sender common.Address) {
    msg:=qbfttypes.NewPrepare(big.NewInt(height),big.NewInt(0),crypto.Keccak256Hash([]byte{tag,byte(height)}))
    unsigned,e:=msg.EncodePayloadForSigning();if e!=nil{t.Fatal(e)}
    sig,e:=crypto.Sign(crypto.Keccak256(unsigned),keys[1]);if e!=nil{t.Fatal(e)}
    msg.SetSignature(sig)
    if e:=(&liveBNetPeer{net:net,source:sender,destination:dest}).SendConsensus(qbfttypes.PrepareCode,msg);e!=nil{t.Fatal(e)}
   }
   send(2,relay)
   send(1,honest)
   observed:=0
   deadline:=time.After(800*time.Millisecond)
  events:
   for observed<2 {
    select {
    case ev:=<-sub.Chan():
     if m,ok:=ev.Data.(istanbul.MessageEvent);ok&&m.Code==qbfttypes.PrepareCode {observed++}
    case <-deadline:break events
    }
   }
   height:=chain.CurrentBlock().NumberU64()
   t.Logf("B_FUTURE_HEIGHT_OUTSIDER_ORACLE state=%d delivered=%d canonical_height=%d accepted_votes=NOT_MEASURED",tag,observed,height)
   if height!=0 {t.Fatal("unexpected canonical advancement")}
   if observed==0 {t.Fatal("transport discriminator inconclusive")}
  })
 }
}
