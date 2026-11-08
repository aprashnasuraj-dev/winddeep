package qbftengine

import (
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/crypto"
)

// A peer controlling an ECDSA key outside the four-validator set must not
// contribute the third vote required for QBFT finality.
func TestWorkerBOutsiderCommittedVoteRejected(t *testing.T) {
 for seed:=uint64(81);seed<=83;seed++ {
  t.Run(fmt.Sprintf("outsider_%d",seed),func(t *testing.T) {
   engine,keys,vs:=workerBEquivocationFixture(t)
   outsider,err:=crypto.HexToECDSA(fmt.Sprintf("%064x",seed+900))
   if err!=nil {t.Fatal(err)}
   sign:=func(n uint64, withOutsider bool) error {
    h:=workerBEquivocationHeader(t,keys,n)
    payload:=PrepareCommittedSeal(h,0)
    votes:=make([][]byte,0,3)
    for _,i:=range []int{0,1} {
     sig,e:=crypto.Sign(payload,keys[i]);if e!=nil{return e}
     votes=append(votes,sig)
    }
    signer:=keys[2]
    if withOutsider {signer=outsider}
    sig,e:=crypto.Sign(payload,signer);if e!=nil{return e}
    votes=append(votes,sig)
    if e:=engine.CommitHeader(h,votes,big.NewInt(0));e!=nil{return e}
    return engine.VerifyCommittedSeals(nil,h,vs)
   }
   if e:=sign(seed*100+1,false);e!=nil {t.Fatalf("honest 3/4 rejected: %v",e)}
   t.Logf("B_OUTSIDER_HONEST_QUORUM seed=%d",seed)
   if e:=sign(seed*100+2,true);e==nil {t.Fatal("nonvalidator third signature admitted as 3-of-4 quorum")}
   t.Logf("B_OUTSIDER_THIRD_VOTE_REJECTED seed=%d",seed)
  })
 }
}
