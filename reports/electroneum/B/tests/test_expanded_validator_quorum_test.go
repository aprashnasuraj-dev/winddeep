package qbftengine

import (
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
 "github.com/electroneum/electroneum-sc/crypto"
 "crypto/ecdsa"
)

// Membership expansion must raise the distinct signer threshold from 3/4 to 4/5.
// This is a component-level boundary probe, not a canonical transition or network exploit.
func TestWorkerBExpandedValidatorQuorumBoundary(t *testing.T) {
 for seed:=uint64(501);seed<=503;seed++ {
  t.Run(fmt.Sprintf("membership_%d",seed),func(t *testing.T){
   keys:=make([]*ecdsa.PrivateKey,5)
   addrs:=make([]common.Address,5)
   for i:=range keys {
    k,e:=crypto.HexToECDSA(fmt.Sprintf("%064x",seed*10+uint64(i)+1))
    if e!=nil {t.Fatal(e)}
    keys[i]=k
    addrs[i]=crypto.PubkeyToAddress(k.PublicKey)
   }
   vs:=validator.NewSet(addrs,istanbul.NewRoundRobinProposerPolicy())
   engine:=NewEngine(istanbul.DefaultConfig,common.Address{},nil)
   verify:=func(n uint64,count int) error {
    h:=workerBEquivocationHeader(t,keys,n)
    payload:=PrepareCommittedSeal(h,0)
    votes:=make([][]byte,0,count)
    for i:=0;i<count;i++ {
     sig,e:=crypto.Sign(payload,keys[i]);if e!=nil{return e}
     votes=append(votes,sig)
    }
    if e:=engine.CommitHeader(h,votes,big.NewInt(0));e!=nil{return e}
    return engine.VerifyCommittedSeals(nil,h,vs)
   }
   if e:=verify(seed*10+1,4);e!=nil {t.Fatalf("honest 4/5 rejected: %v",e)}
   t.Logf("B_EXPANDED_FIVE_VALIDATOR_FOUR_ACCEPTED seed=%d",seed)
   if e:=verify(seed*10+2,3);e==nil {t.Fatal("three signatures admitted under five-validator membership")}
   t.Logf("B_EXPANDED_FIVE_VALIDATOR_THREE_REJECTED seed=%d",seed)
   if e:=verify(seed*10+3,2);e==nil {t.Fatal("two signatures admitted under five-validator membership")}
   t.Logf("B_EXPANDED_FIVE_VALIDATOR_TWO_REJECTED seed=%d",seed)
  })
 }
}
