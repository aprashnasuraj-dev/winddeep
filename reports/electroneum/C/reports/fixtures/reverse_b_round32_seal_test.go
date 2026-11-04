// Reverse Worker R: independent QBFT 32-bit committed-seal domain characterization.
// Copied only into certified scratch consensus/istanbul/engine.
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

func reverseB32Fixture(t *testing.T)(*Engine,*types.Header,[]*ecdsa.PrivateKey,istanbul.ValidatorSet){
 t.Helper()
 const n=4
 keys:=make([]*ecdsa.PrivateKey,n)
 addrs:=make([]common.Address,n)
 for i:=0;i<n;i++ {
  k,err:=crypto.HexToECDSA(fmt.Sprintf("%064x",i+101));if err!=nil{t.Fatal(err)}
  keys[i]=k;addrs[i]=crypto.PubkeyToAddress(k.PublicKey)
 }
 h:=&types.Header{Number:big.NewInt(1)}
 if err:=ApplyHeaderQBFTExtra(h,WriteValidators(addrs));err!=nil{t.Fatal(err)}
 vs:=validator.NewSet(addrs,istanbul.NewRoundRobinProposerPolicy())
 return NewEngine(istanbul.DefaultConfig,common.Address{},nil),h,keys,vs
}
func reverseB32Sign(t *testing.T,payload []byte,keys []*ecdsa.PrivateKey)[][]byte{
 t.Helper();out:=make([][]byte,3)
 for i:=0;i<3;i++{s,err:=crypto.Sign(payload,keys[i]);if err!=nil{t.Fatal(err)};out[i]=s}
 return out
}

func TestReverseB32CommittedSealDomain(t *testing.T){
 t.Run("normal_round_domain_changes",func(t *testing.T){
  _,h,_,_:=reverseB32Fixture(t)
  if string(PrepareCommittedSeal(h,0))==string(PrepareCommittedSeal(h,1)){t.Fatal("round0 and round1 signing domains collided")}
  t.Log("REVERSE_B32_NORMAL_ROUND_DOMAIN_DISTINCT_PASS")
 })
 t.Run("round_0_and_2pow32_alias_in_actual_engine",func(t *testing.T){
  engine,h,keys,vs:=reverseB32Fixture(t)
  seals:=reverseB32Sign(t,PrepareCommittedSeal(h,0),keys)
  high:=new(big.Int).Lsh(big.NewInt(1),32)
  if err:=engine.CommitHeader(h,seals,high);err!=nil{t.Fatal(err)}
  extra,err:=types.ExtractQBFTExtra(h);if err!=nil{t.Fatal(err)}
  if extra.Round!=0{t.Fatalf("high round encoded as %d, expected uint32 alias 0",extra.Round)}
  if err:=engine.VerifyCommittedSeals(nil,h,vs);err!=nil{t.Fatalf("round0 signatures did not verify after CommitHeader(2^32): %v",err)}
  t.Log("REVERSE_B32_SIGNED_SEAL_DOMAIN_ALIAS_CONFIRMED round0_signatures_verify_after_round_2pow32_commit")
 })
 t.Run("wrong_round_signature_negative_control",func(t *testing.T){
  engine,h,keys,vs:=reverseB32Fixture(t)
  seals:=reverseB32Sign(t,PrepareCommittedSeal(h,1),keys)
  high:=new(big.Int).Lsh(big.NewInt(1),32)
  if err:=engine.CommitHeader(h,seals,high);err!=nil{t.Fatal(err)}
  if err:=engine.VerifyCommittedSeals(nil,h,vs);err==nil{t.Fatal("round1 signatures unexpectedly verified against encoded round0 domain")}
  t.Log("REVERSE_B32_WRONG_ROUND_SIGNATURE_REJECTED_PASS")
 })
}
