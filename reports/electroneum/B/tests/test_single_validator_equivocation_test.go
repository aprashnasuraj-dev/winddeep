// Certified QBFT engine regression: a single equivocating validator must not
// finalize two different headers at the same height. Synthetic keys only.
package qbftengine

import (
 "crypto/ecdsa"
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

func workerBEquivocationFixture(t *testing.T)(*Engine,[]*ecdsa.PrivateKey,istanbul.ValidatorSet) {
 t.Helper()
 keys:=make([]*ecdsa.PrivateKey,4)
 addrs:=make([]common.Address,4)
 for i:=0;i<4;i++ {
  k,e:=crypto.HexToECDSA(fmt.Sprintf("%064x",i+101))
  if e!=nil {t.Fatal(e)}
  keys[i]=k;addrs[i]=crypto.PubkeyToAddress(k.PublicKey)
 }
 return NewEngine(istanbul.DefaultConfig,common.Address{},nil),keys,validator.NewSet(addrs,istanbul.NewRoundRobinProposerPolicy())
}
func workerBEquivocationHeader(t *testing.T,keys []*ecdsa.PrivateKey,nonce uint64)*types.Header{
 t.Helper()
 addrs:=make([]common.Address,len(keys))
 for i,k:=range keys {addrs[i]=crypto.PubkeyToAddress(k.PublicKey)}
 h:=&types.Header{Number:big.NewInt(1),Time:nonce}
 if e:=ApplyHeaderQBFTExtra(h,WriteValidators(addrs));e!=nil {t.Fatal(e)}
 return h
}
func TestWorkerBSingleValidatorEquivocationIsolation(t *testing.T){
 // Three independently constructed fixtures with distinct header content.
 for seed:=uint64(1);seed<=3;seed++{
  t.Run(fmt.Sprintf("fresh_seed_%d",seed),func(t *testing.T){
   engine,keys,vs:=workerBEquivocationFixture(t)
   a:=workerBEquivocationHeader(t,keys,100+seed)
   b:=workerBEquivocationHeader(t,keys,200+seed)
   if a.Hash()==b.Hash(){t.Fatal("independent header hash oracle collided")}
   // Honest 3/4 finalization of A; B only has Byzantine signer 0.
   sign:=func(h *types.Header,indices ...int)[][]byte{
    t.Helper()
    payload:=PrepareCommittedSeal(h,0)
    out:=make([][]byte,0,len(indices))
    for _,i:=range indices{
     s,e:=crypto.Sign(payload,keys[i]);if e!=nil{t.Fatal(e)}
     out=append(out,s)
    }
    return out
   }
   if e:=engine.CommitHeader(a,sign(a,0,1,2),big.NewInt(0));e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,a,vs);e!=nil{t.Fatalf("honest 3/4 rejected: %v",e)}
   t.Logf("B_EQUIVOCATION_HONEST_QUORUM seed=%d",seed)
   if e:=engine.CommitHeader(b,sign(b,0),big.NewInt(0));e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,b,vs);e==nil{t.Fatal("one Byzantine signer finalized conflicting header")}
   t.Logf("B_EQUIVOCATION_SINGLE_SIGNER_REJECTED seed=%d",seed)
   // Boundary: duplicate the same Byzantine signature three times.
   b2:=workerBEquivocationHeader(t,keys,300+seed)
   one:=sign(b2,0)[0]
   if e:=engine.CommitHeader(b2,[][]byte{one,one,one},big.NewInt(0));e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,b2,vs);e==nil{t.Fatal("duplicate signer counted as 3/4 quorum")}
   t.Logf("B_EQUIVOCATION_DUPLICATE_REJECTED seed=%d",seed)
   // Cross-header replay of 3 honest signatures must not finalize B.
   b3:=workerBEquivocationHeader(t,keys,400+seed)
   if e:=engine.CommitHeader(b3,sign(a,0,1,2),big.NewInt(0));e!=nil{t.Fatal(e)}
   if e:=engine.VerifyCommittedSeals(nil,b3,vs);e==nil{t.Fatal("other-header quorum replay accepted")}
   t.Logf("B_EQUIVOCATION_CROSS_HEADER_REJECTED seed=%d",seed)
  })
 }
}
