package eth

import (
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/rlp"
)

// TestLiveDETH66CrossMessageReplay examines a stateful outsider announcement
// sequence crossing multiple individually well-formed ETH66 wire messages.
// This is a wire-level trust-boundary discriminator, NOT canonical admission.
func TestLiveDETH66CrossMessageReplay(t *testing.T) {
 a:=common.HexToHash("0xa1")
 b:=common.HexToHash("0xb2")
 c:=common.HexToHash("0xc3")
 for _,tc:=range []struct{
  name string
  messages []NewBlockHashesPacket
  wantReplay bool
  wantHeightConflict bool
 }{
  {"honest_progression",[]NewBlockHashesPacket{{{Hash:a,Number:11}},{{Hash:b,Number:12}},{{Hash:c,Number:13}}},false,false},
  {"obsolete_replay",[]NewBlockHashesPacket{{{Hash:a,Number:11}},{{Hash:b,Number:12}},{{Hash:a,Number:11}}},true,false},
  {"cross_message_equivocation",[]NewBlockHashesPacket{{{Hash:a,Number:11}},{{Hash:b,Number:12}},{{Hash:c,Number:11}}},false,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   seen:=map[common.Hash]uint64{}
   heights:=map[uint64]common.Hash{}
   replay:=false
   conflict:=false
   var maxHeight uint64
   for i,message:=range tc.messages {
    wire,err:=rlp.EncodeToBytes(message);if err!=nil{t.Fatal(err)}
    var decoded NewBlockHashesPacket
    if err:=rlp.DecodeBytes(wire,&decoded);err!=nil{t.Fatalf("D_CROSS_MESSAGE_DECODE: %v",err)}
    if len(decoded)!=1{t.Fatalf("D_CROSS_MESSAGE_LENGTH: %d",len(decoded))}
    item:=decoded[0]
    if old,ok:=seen[item.Hash];ok && old==item.Number && item.Number<maxHeight {replay=true}
    if old,ok:=heights[item.Number];ok && old!=item.Hash {conflict=true}
    seen[item.Hash]=item.Number
    heights[item.Number]=item.Hash
    if item.Number>maxHeight{maxHeight=item.Number}
    t.Logf("D_CROSS_MESSAGE_STEP case=%s step=%d height=%d hash=%s bytes=%d",tc.name,i,item.Number,item.Hash,len(wire))
   }
   if replay!=tc.wantReplay || conflict!=tc.wantHeightConflict {
    t.Fatalf("D_CROSS_MESSAGE_ORACLE_FAIL case=%s replay=%t expected_replay=%t conflict=%t expected_conflict=%t",tc.name,replay,tc.wantReplay,conflict,tc.wantHeightConflict)
   }
   t.Logf("D_CROSS_MESSAGE_RESULT case=%s replay=%t conflict=%t",tc.name,replay,conflict)
  })
 }
}
