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

// This is an ingress discrimination test, NOT a network-level finality proof.
// It asks whether a signed message from a nonvalidator reaches the backend
// consensus event bus when supplied by a nonvalidator peer address.
func TestLiveBOutsiderSignedPrepareIngress(t *testing.T) {
 for _, tag := range []byte{81, 83, 89} {
  t.Run(fmt.Sprintf("state_%d",tag),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(4)
   outsider,e:=crypto.GenerateKey();if e!=nil{t.Fatal(e)}
   cfg:=*istanbul.DefaultConfig
   run:=func(keyIndex int, outsiderKey bool)(bool,error){
    chain,backend:=newBlockchainFromConfig(genesis,keys,cfg)
    defer backend.Stop()
    sub:=backend.EventMux().Subscribe(istanbul.MessageEvent{})
    defer sub.Unsubscribe()
    prep:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),crypto.Keccak256Hash([]byte{tag,0x77}))
    unsigned,e:=prep.EncodePayloadForSigning();if e!=nil{return false,e}
    signer:=keys[keyIndex]
    if outsiderKey {signer=outsider}
    sig,e:=crypto.Sign(crypto.Keccak256(unsigned),signer);if e!=nil{return false,e}
    prep.SetSignature(sig)
    wire,e:=rlp.EncodeToBytes(prep);if e!=nil{return false,e}
    from:=crypto.PubkeyToAddress(signer.PublicKey)
    done:=make(chan error,1)
    go func(){
     handled,err:=backend.HandleMsg(from,p2p.Msg{Code:qbfttypes.PrepareCode,Size:uint32(len(wire)),Payload:bytes.NewReader(wire)})
     if !handled||err!=nil {done<-fmt.Errorf("handled=%v err=%v",handled,err);return}
     done<-nil
    }()
    delivered:=false
    select {
    case ev:=<-sub.Chan():
     typed,ok:=ev.Data.(istanbul.MessageEvent)
     delivered=ok&&typed.Code==qbfttypes.PrepareCode
    case <-time.After(300*time.Millisecond):
    }
    select {
    case err:=<-done:
     if err!=nil{return delivered,err}
    case <-time.After(2*time.Second):
     return delivered,fmt.Errorf("HandleMsg blocked")
    }
    if chain.CurrentBlock().NumberU64()!=0 {return delivered,fmt.Errorf("unexpected canonical advancement")}
    return delivered,nil
   }
   honest,err:=run(1,false);if err!=nil{t.Fatal(err)}
   outsiderDelivered,err:=run(0,true);if err!=nil{t.Fatal(err)}
   t.Logf("B_OUTSIDER_PREPARE_INGRESS state=%d honest_event=%v outsider_event=%v canonical_advanced=false",tag,honest,outsiderDelivered)
   if !honest {t.Fatal("invalid baseline: honest signed prepare not dispatched")}
   // Deliberately do not interpret event dispatch as vote acceptance.
  })
 }
}
