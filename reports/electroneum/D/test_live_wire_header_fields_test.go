package types

import (
 "fmt"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/rlp"
)

// Live-chat research: prove what an actual RLP-decoded ETH block frame can
// place into Header's required big.Int pointers. Synthetic wire bytes only.
// Do not infer remote impact from direct accessors without ETH66 path proof.
func TestLiveDWireHeaderRequiredFieldBoundary(t *testing.T) {
 recoverPanic := func(fn func()) (didPanic bool) {
  defer func(){if recover()!=nil {didPanic=true}}()
  fn()
  return
 }
 for _,seed:=range []uint64{1,4,7} {
  t.Run(fmt.Sprintf("wire_state_%d",seed),func(t *testing.T){
   cases:=[]struct{name string; nullNumber, nullDifficulty, hugeNumber bool}{
    {"honest",false,false,false},
    {"nil_number",true,false,false},
    {"nil_difficulty",false,true,false},
    {"huge_number",false,false,true},
   }
   for _,tc:=range cases {
    hdr:=&Header{
      Number:new(big.Int).SetUint64(seed),Difficulty:big.NewInt(1),
      GasLimit:30000000,Time:100,UncleHash:EmptyUncleHash,
      TxHash:EmptyRootHash,ReceiptHash:EmptyRootHash,
    }
    if tc.nullNumber {hdr.Number=nil}
    if tc.nullDifficulty {hdr.Difficulty=nil}
    if tc.hugeNumber {hdr.Number=new(big.Int).Lsh(big.NewInt(1),72)}
    // ETH block payload is (header, transactions, uncles); this is an actual
    // RLP wire encoding rather than a synthetic struct passed directly.
    raw,err:=rlp.EncodeToBytes([]interface{}{hdr,[]interface{}{},[]interface{}{}})
    if err!=nil {
     t.Logf("D_WIRE_HEADER_CASE seed=%d case=%s encode_error=%v",seed,tc.name,err)
     continue
    }
    var decoded Block
    if err=rlp.DecodeBytes(raw,&decoded);err!=nil {
     t.Logf("D_WIRE_HEADER_CASE seed=%d case=%s decode_error=%v",seed,tc.name,err)
     continue
    }
    h:=decoded.header
    var sanityErr error
    sanityPanic:=recoverPanic(func(){sanityErr=decoded.SanityCheck()})
    numberPanic:=recoverPanic(func(){_=decoded.NumberU64()})
    difficultyPanic:=recoverPanic(func(){_=decoded.Difficulty()})
    t.Logf("D_WIRE_HEADER_CASE seed=%d case=%s wire_bytes=%d number_nil=%v difficulty_nil=%v sanity_error=%v sanity_panic=%v number_panic=%v difficulty_panic=%v",
     seed,tc.name,len(raw),h.Number==nil,h.Difficulty==nil,sanityErr,sanityPanic,numberPanic,difficultyPanic)
    if tc.name=="honest" {
     if sanityErr!=nil || sanityPanic || numberPanic || difficultyPanic {t.Fatal("honest wire frame failed")}
    }
    if tc.name=="nil_number" {
     t.Logf("D_WIRE_NIL_RESULT seed=%d nil_after_wire=%v sanity_pass=%v accessor_panic=%v",
      seed,h.Number==nil,!sanityPanic&&sanityErr==nil,numberPanic)
    }
    if tc.name=="huge_number" {
     if sanityPanic || sanityErr==nil {t.Fatal("D_WIRE_SANITY_BOUNDARY huge number not rejected")}
     t.Logf("D_WIRE_SANITY_BOUNDARY seed=%d rejected=true",seed)
    }
   }
  })
 }
}
