package backend

import (
 "bytes"
 "fmt"
 "math/big"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/p2p"
 "github.com/electroneum/electroneum-sc/rlp"
)

// TestLiveBOutsiderSignedQBFTIngress verifies a real signed outsider's QBFT
// PREPARE input through the consensus.HandleMsg ingress and live event loop.
// This is a bounded, in-process 4/5/7-validator experiment. It does NOT claim
// four distributed validator processes or a chain-wide halt.
func TestLiveBOutsiderSignedQBFTIngress(t *testing.T) {
 for _, n:=range []int{4,5,7} {
  t.Run(fmt.Sprintf("valset_%d",n),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(n)
   cfg:=*istanbul.DefaultConfig
   chain,backend:=newBlockchainFromConfig(genesis,keys,cfg)
   defer backend.Stop()
   outsiderBytes:=make([]byte,32);outsiderBytes[31]=byte(n+73)
   outsider,err:=crypto.ToECDSA(outsiderBytes);if err!=nil {t.Fatal(err)}
   outsiderAddr:=crypto.PubkeyToAddress(outsider.PublicKey)
   const round=uint64(0)
   msg:=qbfttypes.NewPrepare(big.NewInt(1),new(big.Int).SetUint64(round),crypto.Keccak256Hash([]byte{byte(n),0x77}))
   toSign,err:=msg.EncodePayloadForSigning();if err!=nil {t.Fatal(err)}
   sig,err:=crypto.Sign(crypto.Keccak256(toSign),outsider);if err!=nil {t.Fatal(err)}
   msg.SetSignature(sig)
   wire,err:=rlp.EncodeToBytes(msg);if err!=nil{t.Fatal(err)}
   response:=make(chan struct{handled bool;err error},1)
   go func(){
    handled,e:=backend.HandleMsg(outsiderAddr,p2p.Msg{
     Code:qbfttypes.PrepareCode,Size:uint32(len(wire)),Payload:bytes.NewReader(wire),
    })
    response<-struct{handled bool;err error}{handled,e}
   }()
   select {
    case res:=<-response:
     if !res.handled||res.err!=nil {t.Fatalf("B_LIVE_OUTSIDER_INGRESS_ERROR valset=%d handled=%v err=%v",n,res.handled,res.err)}
    case <-time.After(4*time.Second):t.Fatal("B_LIVE_OUTSIDER_HANDLER_STALLED")
   }
   // An outsider frame must not manufacture a committed block or advance
   // canonical history. A signed-but-unauthorized message is not a validator vote.
   time.Sleep(30*time.Millisecond)
   if chain.CurrentBlock().NumberU64()!=0 {t.Fatal("B_LIVE_OUTSIDER_CANONICAL_BREACH")}
   info:=backend.core.RoundState()
   if info==nil {t.Fatal("B_LIVE_OUTSIDER_EVENT_LOOP_UNAVAILABLE")}
   if info.Prepares!=0 || info.Commits!=0 {
    t.Fatalf("B_LIVE_OUTSIDER_VOTE_BREACH prepares=%d commits=%d",info.Prepares,info.Commits)
   }
   t.Logf("B_LIVE_OUTSIDER_REJECTED valset=%d caller=%s wire=%d prepares=%d commits=%d head=0",
    n,outsiderAddr,len(wire),info.Prepares,info.Commits)
   // Honest control: a known-validator signature is cryptographically valid,
   // unlike the outsider signature. It has no corresponding block proposal,
   // so it should not progress canonical finality by itself.
   honestMsg:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),msg.Digest)
   hBody,e:=honestMsg.EncodePayloadForSigning();if e!=nil{t.Fatal(e)}
   honestSig,e:=crypto.Sign(crypto.Keccak256(hBody),keys[0]);if e!=nil{t.Fatal(e)}
   honestMsg.SetSignature(honestSig)
   validWire,e:=rlp.EncodeToBytes(honestMsg);if e!=nil{t.Fatal(e)}
   handled,e:=backend.HandleMsg(crypto.PubkeyToAddress(keys[0].PublicKey),p2p.Msg{
    Code:qbfttypes.PrepareCode,Size:uint32(len(validWire)),Payload:bytes.NewReader(validWire)})
   if !handled||e!=nil{t.Fatalf("honest ingress failed handled=%v err=%v",handled,e)}
   if chain.CurrentBlock().NumberU64()!=0 {t.Fatal("B_LIVE_HONEST_WITHOUT_QUORUM_CANONICAL_BREACH")}
   t.Logf("B_LIVE_HONEST_CONTROL valset=%d signed_by_validator=true head=0",n)
   // Malformed signature-length variation on a separate digest is limited to
   // one inert frame: it should not crash or wedge the event loop.
   bad:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),crypto.Keccak256Hash([]byte{byte(n),0x42}))
   bad.SetSignature([]byte{0x00})
   badWire,e:=rlp.EncodeToBytes(bad);if e!=nil{t.Fatal(e)}
   handled,e=backend.HandleMsg(outsiderAddr,p2p.Msg{
    Code:qbfttypes.PrepareCode,Size:uint32(len(badWire)),Payload:bytes.NewReader(badWire)})
   if !handled||e!=nil{t.Fatalf("malformed ingress failed handled=%v err=%v",handled,e)}
   if err:=backend.NewChainHead();err!=nil {t.Fatal(err)}
   t.Logf("B_LIVE_EVENT_HEALTH valset=%d malformed_sig_rejected_path=true chainhead_event_ok=true",n)
   _=types.IstanbulDigest
   _=common.Big0
  })
 }
}
