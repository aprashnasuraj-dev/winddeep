// Scratch-only Go runtime tests for the certified Electroneum QBFT engine.
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
func workerBFixture(t *testing.T,n int)(*Engine,*types.Header,[]*ecdsa.PrivateKey,istanbul.ValidatorSet){
 t.Helper()
 keys:=make([]*ecdsa.PrivateKey,n+1);addrs:=make([]common.Address,n)
 for i:=range keys {k,e:=crypto.HexToECDSA(fmt.Sprintf("%064x",i+1));if e!=nil{t.Fatal(e)};keys[i]=k;if i<n {addrs[i]=crypto.PubkeyToAddress(k.PublicKey)}}
 h:=&types.Header{Number:big.NewInt(1)}
 if e:=ApplyHeaderQBFTExtra(h,WriteValidators(addrs));e!=nil{t.Fatal(e)}
 return NewEngine(istanbul.DefaultConfig,common.Address{},nil),h,keys,validator.NewSet(addrs,istanbul.NewRoundRobinProposerPolicy())
}
func workerBCase(t *testing.T,n int,mode uint8,round uint32){
 t.Helper()
 engine,h,keys,vs:=workerBFixture(t,n);q:=(2*n+2)/3;indices:=make([]int,q)
 for i:=range indices {indices[i]=i}
 reject:=false
 switch mode%6{
 case 1: indices=indices[:q-1];reject=true
 case 2: if q==1{return};indices[q-1]=indices[0];reject=true
 case 3: indices[q-1]=n;reject=true
 case 4: indices=make([]int,n+1);for i:=range indices{indices[i]=i%n};reject=true
 case 5: reject=true
 }
 signedRound:=round;if mode%6==5{signedRound++}
 payload:=PrepareCommittedSeal(h,signedRound)
 seals:=make([][]byte,0,len(indices))
 for _,i:=range indices{s,e:=crypto.Sign(payload,keys[i]);if e!=nil{t.Fatal(e)};seals=append(seals,s)}
 if len(seals)>0 {
  if e:=engine.CommitHeader(h,seals,new(big.Int).SetUint64(uint64(round)));e!=nil{t.Fatal(e)}
 }else{
  if e:=ApplyHeaderQBFTExtra(h,func(x *types.QBFTExtra)error{x.CommittedSeal=nil;return nil});e!=nil{t.Fatal(e)}
 }
 err:=engine.VerifyCommittedSeals(nil,h,vs)
 if reject && err==nil{t.Fatalf("invalid signer quorum accepted: n=%d mode=%d round=%d",n,mode,round)}
 if !reject && err!=nil{t.Fatalf("valid quorum rejected: n=%d round=%d err=%v",n,round,err)}
}
func TestWorkerBActualCommittedSeals(t *testing.T){
 for n:=1;n<=13;n++{for mode:=uint8(0);mode<6;mode++{workerBCase(t,n,mode,uint32(n))}}
 t.Log("QBFT_RUNTIME completed: 13 validator counts, 6 signing/control modes")
}
func TestWorkerBRoundWidthCharacterization(t *testing.T){
 x:=new(types.QBFTExtra)
 if e:=writeRoundNumber(new(big.Int).SetUint64(1<<32))(x);e!=nil{t.Fatal(e)}
 if x.Round==0{t.Log("SUSPECTED round >= 2^32 wraps to 0; attacker reachability NOT proven")}
}
func FuzzWorkerBActualCommittedSeals(f *testing.F){
 f.Add(uint8(1),uint8(0),uint32(0))
 f.Add(uint8(12),uint8(1),uint32(4294967295))
 f.Add(uint8(8),uint8(2),uint32(17))
 f.Add(uint8(2),uint8(3),uint32(1))
 f.Add(uint8(4),uint8(4),uint32(3))
 f.Add(uint8(9),uint8(5),uint32(7))
 f.Fuzz(func(t *testing.T,n uint8,mode uint8,round uint32){workerBCase(t,int(n%13)+1,mode,round)})
}

// TestWorkerBRoundDomainCollision characterizes the real QBFT signing-domain
// boundary. A digest collision alone is NOT a reachable consensus exploit.
func TestWorkerBRoundDomainCollision(t *testing.T) {
 engine,h,keys,vs:=workerBFixture(t,4)
 round0:=big.NewInt(0)
 roundHigh:=new(big.Int).Lsh(big.NewInt(1),32)
 d0:=PrepareCommittedSeal(h,0)
 dh:=PrepareCommittedSeal(h,uint32(roundHigh.Uint64()))
 if string(d0)!=string(dh) {t.Fatal("expected exact 32-bit domain alias for same header")}
 seals:=make([][]byte,3)
 for i:=0;i<3;i++ {s,e:=crypto.Sign(d0,keys[i]);if e!=nil{t.Fatal(e)};seals[i]=s}
 if e:=engine.CommitHeader(h,seals,roundHigh);e!=nil{t.Fatal(e)}
 extra,e:=types.ExtractQBFTExtra(h);if e!=nil{t.Fatal(e)}
 if extra.Round!=0 {t.Fatalf("2^32 round encoded as %d, expected 0",extra.Round)}
 if e:=engine.VerifyCommittedSeals(nil,h,vs);e!=nil{t.Fatalf("round-zero signatures failed against high-round encoded header: %v",e)}
 if e:=engine.CommitHeader(h,seals,round0);e!=nil{t.Fatal(e)}
 if e:=engine.VerifyCommittedSeals(nil,h,vs);e!=nil{t.Fatal(e)}
 t.Log("SOURCE_RUNTIME_DOMAIN_ALIAS round=0 and 2^32; 3/4 synthetic signers; consensus reachability NOT established")
}
