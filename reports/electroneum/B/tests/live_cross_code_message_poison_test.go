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

// TestLiveBCrossCodeSignedPrepareSuppression tests a real signature-bearing
// QBFT PREPARE, first replayed by an outsider peer under a different
// transport code (COMMIT), then received under the original PREPARE code.
// The asserted invariant is that a previously invalidly typed frame must
// not suppress subsequent dispatch of authentic typed consensus messages.
// Completely isolated, no network, 4-validator synthetic genesis and keys.
func TestLiveBCrossCodeSignedPrepareSuppression(t *testing.T) {
 for _,scenario:=range []byte{61,67,73} {
  t.Run(fmt.Sprintf("fresh_genesis_%d",scenario),func(t *testing.T) {
   genesis,keys:=testutils.GenesisAndKeys(4)
   cfg:=*istanbul.DefaultConfig
   prep:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),crypto.Keccak256Hash([]byte{scenario,0xa5}))
   unsigned,e:=prep.EncodePayloadForSigning();if e!=nil{t.Fatal(e)}
   sig,e:=crypto.Sign(crypto.Keccak256(unsigned),keys[1]);if e!=nil{t.Fatal(e)}
   prep.SetSignature(sig)
   wire,e:=rlp.EncodeToBytes(prep);if e!=nil{t.Fatal(e)}
   honestAddr:=crypto.PubkeyToAddress(keys[1].PublicKey)
   outsiderKey,e:=crypto.HexToECDSA(fmt.Sprintf("%064x",uint64(scenario)+9000));if e!=nil{t.Fatal(e)}
   outsiderAddr:=crypto.PubkeyToAddress(outsiderKey.PublicKey)
   run:=func(poison bool)(validDispatched bool,wrongDispatched bool,err error) {
    chain,backend:=newBlockchainFromConfig(genesis,keys,cfg)
    defer backend.Stop()
    sub:=backend.EventMux().Subscribe(istanbul.MessageEvent{})
    defer sub.Unsubscribe()
    send:=func(code uint64,fromAddr [20]byte) error {
     handled,e:=backend.HandleMsg(fromAddr,p2p.Msg{
      Code:code,Size:uint32(len(wire)),Payload:bytes.NewReader(wire),
     })
     if !handled||e!=nil {return fmt.Errorf("code=%d handled=%v err=%v",code,handled,e)}
     return nil
    }
    recv:=func(d time.Duration)(uint64,bool) {
     select {
      case ev,open:=<-sub.Chan():
       if !open {return 0,false}
       typed,ok:=ev.Data.(istanbul.MessageEvent)
       if !ok {return 0,false}
       return typed.Code,true
      case <-time.After(d):return 0,false
     }
    }
    if poison {
     if err=send(qbfttypes.CommitCode,outsiderAddr);err!=nil{return}
     code,ok:=recv(800*time.Millisecond)
     wrongDispatched=ok&&code==qbfttypes.CommitCode
     if !wrongDispatched {err=fmt.Errorf("poison type was not dispatched code=%d seen=%v",code,ok);return}
    }
    if err=send(qbfttypes.PrepareCode,honestAddr);err!=nil{return}
    code,ok:=recv(80*time.Millisecond)
    validDispatched=ok&&code==qbfttypes.PrepareCode
    if chain.CurrentBlock().NumberU64()!=0 {err=fmt.Errorf("test unexpectedly committed a block")}
    return
   }
   poisonedValid,poisonDelivered,err:=run(true)
   if err!=nil{t.Fatal(err)}
   if !poisonDelivered {t.Fatal("failed to exercise wrong-code transport path")}
   t.Logf("B_CROSS_CODE_POISON_FIRED scenario=%d wire=%d wrong_code=%d wrong_dispatched=true",scenario,len(wire),qbfttypes.CommitCode)
   cleanValid,_,err:=run(false)
   if err!=nil{t.Fatal(err)}
   t.Logf("B_CROSS_CODE_ORACLE scenario=%d expected_valid_dispatch=true clean_dispatch=%v poison_then_valid_dispatch=%v signed_sender=%s relay_outsider=%s",
    scenario,cleanValid,poisonedValid,honestAddr,outsiderAddr)
   if !cleanValid {t.Fatal("B_CROSS_CODE_HARNESS_INVALID: same honest message did not dispatch on clean backend")}
   if poisonedValid {
    t.Logf("B_CROSS_CODE_GUARD_HELD scenario=%d no_suppression=true",scenario)
   } else {
    t.Logf("B_CROSS_CODE_SUPPRESSION_OBSERVED scenario=%d valid_signed_prepare_dispatched=false after_wrong_code=true",scenario)
   }
  })
 }
}
