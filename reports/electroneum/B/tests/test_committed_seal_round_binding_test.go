package qbftengine

import (
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/crypto"
)

// Distinct from signer duplication and validator rotation: committed seals
// must bind the consensus round. This is an engine-level test, not a network PoC.
func TestWorkerBCommittedSealRoundBinding(t *testing.T) {
 for seed:=uint64(41);seed<=43;seed++ {
  t.Run(fmt.Sprintf("state_%d",seed),func(t *testing.T) {
   engine,keys,vs:=workerBEquivocationFixture(t)
   h:=workerBEquivocationHeader(t,keys,seed*1000+1)
   round:=big.NewInt(1)
   sign:=func(r *big.Int)[][]byte {
    t.Helper()
    payload:=PrepareCommittedSeal(h,r.Uint64())
    out:=make([][]byte,0,3)
    for i:=0;i<3;i++ {s,e:=crypto.Sign(payload,keys[i]);if e!=nil{t.Fatal(e)};out=append(out,s)}
    return out
   }
   if e:=engine.CommitHeader(h,sign(round),round);e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,h,vs);e!=nil{t.Fatalf("round-one honest quorum rejected: %v",e)}
   t.Logf("B_ROUND_BINDING_HONEST seed=%d",seed)
   replay:=workerBEquivocationHeader(t,keys,seed*1000+1)
   if e:=engine.CommitHeader(replay,sign(big.NewInt(0)),round);e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,replay,vs);e==nil{t.Fatal("round-zero votes admitted as round-one quorum")}
   t.Logf("B_ROUND_BINDING_REPLAY_REJECTED seed=%d",seed)
  })
 }
}
