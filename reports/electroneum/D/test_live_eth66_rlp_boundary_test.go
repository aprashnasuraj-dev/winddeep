package eth

import (
 "fmt"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
)

// TestLiveDETH66RLPOptionalPointerBoundaries uses actual NewBlock ETH66 packet
// layout and the production rawNewBlockPacket decoder. No network is touched.
// Any panic must be tied to an accepted wire packet, NOT an impossible struct.
func TestLiveDETH66RLPOptionalPointerBoundaries(t *testing.T) {
 catchesPanic:=func(fn func()) (didPanic bool) {
  defer func(){if recover()!=nil {didPanic=true}}()
  fn();return
 }
 for _,height:=range []int64{1,2,3} {
  t.Run(fmt.Sprintf("wire_height_%d",height),func(t *testing.T){
   header:=&types.Header{
    Number:big.NewInt(height),Difficulty:big.NewInt(1),GasLimit:30000000,
    GasUsed:0,Time:100,UncleHash:types.EmptyUncleHash,
    TxHash:types.EmptyRootHash,ReceiptHash:types.EmptyRootHash,
   }
   cases:=[]struct{name string;hdr interface{};td interface{}}{
    {"valid",header,big.NewInt(1)},
    {"nil_header",(*types.Header)(nil),big.NewInt(1)},
    {"empty_header_list",[]interface{}{},big.NewInt(1)},
    {"nil_td",header,(*big.Int)(nil)},
    {"zero_td",header,big.NewInt(0)},
   }
   for _,tc:=range cases {
    packet:=[]interface{}{[]interface{}{tc.hdr,[]interface{}{},[]interface{}{}},tc.td}
    wire,err:=rlp.EncodeToBytes(packet)
    if err!=nil {
     t.Logf("D_WIRE_ENVELOPE_GUARD height=%d case=%s stage=encode err=%v",height,tc.name,err)
     continue
    }
    var decoded rawNewBlockPacket
    err=rlp.DecodeBytes(wire,&decoded)
    if err!=nil {
     t.Logf("D_WIRE_ENVELOPE_GUARD height=%d case=%s stage=decode wire_bytes=%d err=%v",height,tc.name,len(wire),err)
     continue
    }
    headerNil:=decoded.Block.Header==nil
    tdNil:=decoded.TD==nil
    var sanityErr error
    sanityPanic:=false
    if !headerNil {
     sanityPanic=catchesPanic(func(){
      candidate:=&NewBlockPacket{
       Block:types.NewBlockWithHeader(decoded.Block.Header).WithBody(nil,nil),
       TD:decoded.TD,
      }
      sanityErr=candidate.sanityCheck()
     })
    }
    t.Logf("D_WIRE_ENVELOPE height=%d case=%s wire_bytes=%d header_nil=%v td_nil=%v sanity_panic=%v sanity_err=%v",
     height,tc.name,len(wire),headerNil,tdNil,sanityPanic,sanityErr)
    if tc.name=="valid" {
     if headerNil||tdNil||sanityPanic||sanityErr!=nil {t.Fatal("valid ETH66 envelope failed")}
     t.Logf("D_WIRE_ENVELOPE_VALID height=%d expected_success=true",height)
    }
    if tc.name=="nil_header" && headerNil {
     t.Logf("D_WIRE_ENVELOPE_GUARD height=%d case=nil_header accepted_nil_header=true reachable_dereference_needs_handler_test",height)
    }
    if tc.name=="nil_td" && (tdNil||sanityPanic) {
     t.Logf("D_WIRE_ENVELOPE_GUARD height=%d case=nil_td accepted_nil_td=%v direct_sanity_panic=%v needs_default_handler_test",height,tdNil,sanityPanic)
    }
   }
  })
 }
}
