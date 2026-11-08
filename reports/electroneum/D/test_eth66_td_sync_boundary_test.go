package eth

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
)

// TestLiveDETH66TDClaimBoundary compares untrusted wire total-difficulty
// claims with a locally computed parent+header difficulty oracle.
// It does not assert that a decoded packet is admitted to canonical state.
func TestLiveDETH66TDClaimBoundary(t *testing.T) {
 for _,tc:=range []struct{name string; height int64; parentTD, difficulty, claimed int64}{
  {"honest",1,10,2,12},
  {"inflated",2,10,2,1200000},
  {"understated",3,10,2,1},
 } {
  t.Run(tc.name,func(t *testing.T){
   header:=&types.Header{Number:big.NewInt(tc.height),Difficulty:big.NewInt(tc.difficulty),GasLimit:30000000,Time:100,UncleHash:types.EmptyUncleHash,TxHash:types.EmptyRootHash,ReceiptHash:types.EmptyRootHash}
   wire,err:=rlp.EncodeToBytes([]interface{}{[]interface{}{header,[]interface{}{},[]interface{}{}},big.NewInt(tc.claimed)})
   if err!=nil{t.Fatal(err)}
   var decoded rawNewBlockPacket
   if err=rlp.DecodeBytes(wire,&decoded);err!=nil{t.Fatalf("wire decode: %v",err)}
   if decoded.Block.Header==nil||decoded.TD==nil{t.Fatal("D_TD_WIRE_MISSING")}
   candidate:=&NewBlockPacket{Block:types.NewBlockWithHeader(decoded.Block.Header).WithBody(nil,nil),TD:decoded.TD}
   sanityErr:=candidate.sanityCheck()
   expected:=new(big.Int).Add(big.NewInt(tc.parentTD),decoded.Block.Header.Difficulty)
   mismatch:=decoded.TD.Cmp(expected)!=0
   if mismatch!=(tc.name!="honest"){t.Fatal("D_TD_ORACLE_FIXTURE_INVALID")}
   t.Logf("D_TD_SYNC_BOUNDARY case=%s height=%d wire_claim=%s oracle_parent_plus_header=%s mismatch=%t sanity_err=%v",tc.name,tc.height,decoded.TD,expected,mismatch,sanityErr)
   // A sanityCheck pass on mismatched TD is not a vulnerability:
   // parent TD is unavailable at packet decode and must be checked at admission.
   if tc.name=="honest"&&sanityErr!=nil{t.Fatalf("D_TD_HONEST_REJECTED: %v",sanityErr)}
  })
 }
}
