package qbftengine

import (
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

// A retired validator's signature must not count toward a new validator-set quorum.
// This is a component authorization test, not a claim that a peer can choose the set.
func TestWorkerBValidatorSetRotationSealAuthorization(t *testing.T) {
 for seed:=uint64(11);seed<=13;seed++ {
  t.Run(fmt.Sprintf("independent_%d",seed),func(t *testing.T){
   engine,keys,oldSet:=workerBEquivocationFixture(t)
   newcomer,err:=crypto.HexToECDSA(fmt.Sprintf("%064x",1000+seed));if err!=nil{t.Fatal(err)}
   newAddresses:=make([]common.Address,4)
   for i:=0;i<3;i++{newAddresses[i]=crypto.PubkeyToAddress(keys[i].PublicKey)}
   newAddresses[3]=crypto.PubkeyToAddress(newcomer.PublicKey)
   newSet:=validator.NewSet(newAddresses,istanbul.NewRoundRobinProposerPolicy())
   sign:=func(h *types.Header,signerIndices ...int)[][]byte {
    t.Helper()
    payload:=PrepareCommittedSeal(h,0)
    seals:=make([][]byte,0,len(signerIndices))
    for _,idx:=range signerIndices{
     key:=newcomer
     if idx<4 {key=keys[idx]}
     sig,e:=crypto.Sign(payload,key);if e!=nil{t.Fatal(e)}
     seals=append(seals,sig)
    }
    return seals
   }
   build:=func(n uint64)*types.Header{
    h:=workerBEquivocationHeader(t,keys,n)
    if h.Hash()==(common.Hash{}){t.Fatal("zero hash oracle")}
    return h
   }
   honest:=build(seed*100+1)
   if err:=engine.CommitHeader(honest,sign(honest,0,1,4),big.NewInt(0));err!=nil{t.Fatal(err)}
   if err:=engine.VerifyCommittedSeals(nil,honest,newSet);err!=nil{t.Fatalf("new set honest quorum rejected: %v",err)}
   t.Logf("B_ROTATION_NEW_SET_HONEST seed=%d",seed)
   stale:=build(seed*100+2)
   if err:=engine.CommitHeader(stale,sign(stale,0,1,3),big.NewInt(0));err!=nil{t.Fatal(err)}
   if err:=engine.VerifyCommittedSeals(nil,stale,newSet);err==nil{t.Fatal("retired validator counted in new quorum")}
   t.Logf("B_ROTATION_RETIRED_REJECTED seed=%d",seed)
   if err:=engine.VerifyCommittedSeals(nil,stale,oldSet);err!=nil{t.Fatalf("old-set boundary unexpectedly rejected: %v",err)}
   t.Logf("B_ROTATION_OLD_SET_BOUNDARY seed=%d",seed)
   insufficient:=build(seed*100+3)
   if err:=engine.CommitHeader(insufficient,sign(insufficient,0,4),big.NewInt(0));err!=nil{t.Fatal(err)}
   if err:=engine.VerifyCommittedSeals(nil,insufficient,newSet);err==nil{t.Fatal("two valid new validators counted as quorum")}
   t.Logf("B_ROTATION_TWO_OF_FOUR_REJECTED seed=%d",seed)
  })
 }
}
