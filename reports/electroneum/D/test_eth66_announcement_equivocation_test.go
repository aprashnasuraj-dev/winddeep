package eth

import (
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/rlp"
)

// TestLiveDETH66AnnouncementEquivocationWire examines whether a nonvalidator
// can submit conflicting, individually valid hash/height announcements.
// Wire acceptance alone is not canonical admission or a vulnerability.
func TestLiveDETH66AnnouncementEquivocationWire(t *testing.T) {
 a:=common.HexToHash("0x1111")
 b:=common.HexToHash("0x2222")
 for _,tc:=range []struct{name string; entries NewBlockHashesPacket; conflict bool}{
  {"honest",NewBlockHashesPacket{{Hash:a,Number:101},{Hash:b,Number:102}},false},
  {"same_hash_two_heights",NewBlockHashesPacket{{Hash:a,Number:101},{Hash:a,Number:102}},true},
  {"same_height_two_hashes",NewBlockHashesPacket{{Hash:a,Number:101},{Hash:b,Number:101}},true},
 }{
  t.Run(tc.name,func(t *testing.T){
   wire,err:=rlp.EncodeToBytes(tc.entries);if err!=nil{t.Fatal(err)}
   var decoded NewBlockHashesPacket
   if err:=rlp.DecodeBytes(wire,&decoded);err!=nil{t.Fatalf("D_EQUIVOCATION_DECODE_ERROR: %v",err)}
   if len(decoded)!=2{t.Fatalf("D_EQUIVOCATION_BAD_LENGTH: %d",len(decoded))}
   observed:=decoded[0].Hash==decoded[1].Hash && decoded[0].Number!=decoded[1].Number ||
    decoded[0].Hash!=decoded[1].Hash && decoded[0].Number==decoded[1].Number
   if observed!=tc.conflict{t.Fatalf("D_EQUIVOCATION_ORACLE_FAIL case=%s expected=%t observed=%t",tc.name,tc.conflict,observed)}
   t.Logf("D_EQUIVOCATION_WIRE case=%s conflict=%t first=%s/%d second=%s/%d bytes=%d",tc.name,observed,decoded[0].Hash,decoded[0].Number,decoded[1].Hash,decoded[1].Number,len(wire))
  })
 }
}
