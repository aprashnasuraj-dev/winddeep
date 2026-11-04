// Resource-constrained parser fuzz on immutable Electroneum source, copied into
// isolated scratch/accounts/abi so this tests the real ABI implementation.
// Grammar-aware offset/length mutation plus cross-component RLP differential.
// All inputs synthetic; no networks or unbounded memory budgets.
package abi

import (
 "bytes"
 "encoding/binary"
 "testing"

 "github.com/electroneum/electroneum-sc/rlp"
)
func auditRParserScenario(t *testing.T, control []byte) {
 t.Helper()
 if len(control)>2048{return}
 typ,err:=NewType("uint8[]","",nil)
 if err!=nil{t.Fatal(err)}
 args:=Arguments{{Type:typ}}
 valid,err:=args.Pack([]uint8{1,2,3})
 if err!=nil{t.Fatal(err)}
 out,err:=args.Unpack(valid)
 if err!=nil||len(out)!=1{t.Fatalf("R_PARSER_POSITIVE_ARRAY_FAILED err=%v",err)}
 if n:=len(out[0].([]uint8));n!=3{t.Fatalf("R_PARSER_POSITIVE_ARRAY_LENGTH=%d",n)}
 // Reach deep decoding paths while mutating semantic words, not just blind bytes.
 mutated:=append([]byte(nil),valid...)
 if len(control)>0{
  switch control[0]%6{
  case 0: // Valid-length and payload mutation, still bounded by buffer.
   if len(control)>1{mutated[len(mutated)-1]^=control[1]}
  case 1: // Bytes become a giant declared array length.
   if len(control)>1{binary.BigEndian.PutUint64(mutated[56:64],uint64(4)+uint64(control[1])*(1<<20))}
  case 2: // Oversized dynamic offset, no allocation allowed.
   mutated[0]=0xff
  case 3: // Offsets inside/exterior ABI buffer.
   if len(control)>1{binary.BigEndian.PutUint64(mutated[24:32],uint64(control[1])*32)}
  case 4: // Missing data pages while keeping original length.
   if len(control)>1{n:=int(control[1])%len(mutated);mutated=mutated[:n]}
  case 5: // Pathological 256-bit length word.
   mutated[32]=0xff
  }
 }
 decoded,err:=args.Unpack(mutated)
 if err==nil{
  if len(decoded)!=1{t.Fatalf("R_PARSER_ARRAY_OUTPUT_ARITY_FAIL: %d",len(decoded))}
  arr,ok:=decoded[0].([]uint8)
  if !ok{t.Fatalf("R_PARSER_ARRAY_OUTPUT_TYPE_FAIL: %T",decoded[0])}
  if len(arr)>(len(mutated)/32){t.Fatalf("R_PARSER_RESOURCE_EXHAUSTION_ORACLE_FAIL: decoded length=%d input bytes=%d",len(arr),len(mutated))}
 }
 // Cross-component byte-level RLP parser: accepted canonical inputs must
 // encode byte-for-byte identically, invalid input may return a controlled error.
 arbitrary:=control
 if len(arbitrary)>1024{arbitrary=arbitrary[:1024]}
 var rlpOut []byte
 if err:=rlp.DecodeBytes(arbitrary,&rlpOut);err==nil{
  normalized,e:=rlp.EncodeToBytes(rlpOut)
  if e!=nil{t.Fatalf("R_PARSER_RLP_CANONICAL_REENCODE_ERROR: %v",e)}
  if !bytes.Equal(normalized,arbitrary){t.Fatalf("R_PARSER_RLP_NONCANONICAL_ACCEPT: raw=%x normalized=%x",arbitrary,normalized)}
  if len(rlpOut)>len(arbitrary){t.Fatalf("R_PARSER_RLP_ALLOCATION_BOUND_FAIL")}
 }
 // Stream decoder with explicit byte budget must not invent data.
 stream:=rlp.NewStream(bytes.NewReader(arbitrary),uint64(len(arbitrary)))
 var streamed []byte
 if err:=stream.Decode(&streamed);err==nil&&len(streamed)>len(arbitrary){
  t.Fatalf("R_PARSER_RLP_STREAM_EXCEEDED_INPUT_BUDGET")
 }
}
func TestRParserBaselineControls(t *testing.T){
 for _,data:=range [][]byte{{0,1},{1,255},{2,0},{3,7},{4,63},{5,0},{0,4,5}}{auditRParserScenario(t,data)}
 t.Log("R_PARSER_BASELINE_ALL_GRAMMAR_CLASSES_PASS")
}
func FuzzRParserResourceBudget(f *testing.F){
 f.Add([]byte{0,1})
 f.Add([]byte{1,255})
 f.Add([]byte{2,0})
 f.Add([]byte{3,9})
 f.Add([]byte{4,63})
 f.Add([]byte{5,0})
 f.Add([]byte{0x83,'a','b','c'})
 f.Fuzz(func(t *testing.T,control []byte){auditRParserScenario(t,control)})
}
