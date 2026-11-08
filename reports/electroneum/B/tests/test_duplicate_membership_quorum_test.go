package qbftengine

import (
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
 "github.com/electroneum/electroneum-sc/crypto"
)

// Membership duplication is distinct from duplicate vote signatures.
// This probes the engine boundary only; no claim that an external peer controls membership.
func TestWorkerBDuplicateMembershipQuorumBoundary(t *testing.T) {
 for seed:=uint64(71);seed<=73;seed++ {
  t.Run(fmt.Sprintf("membership_%d",seed),func(t *testing.T){
   engine,keys,normal:=workerBEquivocationFixture(t)
   addrs:=make([]common.Address,4)
   for i:=0;i<4;i++ {addrs[i]=crypto.PubkeyToAddress(keys[i].PublicKey)}
   malformed:=validator.NewSet([]common.Address{addrs[0],addrs[0],addrs[1],addrs[2]},istanbul.NewRoundRobinProposerPolicy())
   sign:=func(n uint64,indices ...int) error {
    h:=workerBEquivocationHeader(t,keys,n)
    payload:=PrepareCommittedSeal(h,0)
    seals:=make([][]byte,0,len(indices))
    for _,i:=range indices {s,e:=crypto.Sign(payload,keys[i]);if e!=nil{return e};seals=append(seals,s)}
    if e:=engine.CommitHeader(h,seals,big.NewInt(0));e!=nil{return e}
    return engine.VerifyCommittedSeals(nil,h,normal)
   }
   if e:=sign(seed*100+1,0,1,2);e!=nil{t.Fatalf("honest 3-of-4 rejected: %v",e)}
   t.Logf("B_DUPMEM_HONEST_QUORUM seed=%d",seed)
   h:=workerBEquivocationHeader(t,keys,seed*100+2)
   payload:=PrepareCommittedSeal(h,0)
   seals:=make([][]byte,0,2)
   for _,i:=range []int{0,1} {s,e:=crypto.Sign(payload,keys[i]);if e!=nil{t.Fatal(e)};seals=append(seals,s)}
   if e:=engine.CommitHeader(h,seals,big.NewInt(0));e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,h,malformed);e==nil {t.Fatal("two distinct signers admitted under duplicate-address membership")}
   t.Logf("B_DUPMEM_TWO_DISTINCT_REJECTED seed=%d",seed)
  })
 }
}
