// Worker R deep D2: grammar-aware nested ABI arrays and malicious pointer words.
// This executes the real ABI unpacker in certified scratch, not a parser mock.
package abi

import (
 "bytes"
 "encoding/binary"
 "testing"
)

func rDeepNestedABI(t *testing.T,script []byte) {
 t.Helper()
 if len(script)>2048{return}
 for _,name:=range []string{"bytes[]","bytes[][]"}{
  typ,err:=NewType(name,"",nil);if err!=nil{t.Fatal(err)}
  args:=Arguments{{Type:typ}}
  var data []byte
  if name=="bytes[]"{
   data,err=args.Pack([][]byte{[]byte("abc"),[]byte("defgh"),[]byte{0,1,2,3}})
  }else{
   data,err=args.Pack([][][]byte{{[]byte("one"),[]byte("two")},{[]byte("three")}})
  }
  if err!=nil{t.Fatalf("R_DEEP_ABI_POSITIVE_PACK: type=%s err=%v",name,err)}
  out,err:=args.Unpack(data)
  if err!=nil||len(out)!=1{t.Fatalf("R_DEEP_ABI_POSITIVE_UNPACK: type=%s err=%v values=%v",name,err,out)}
  if name=="bytes[]"{
   got,ok:=out[0].([][]byte)
   if !ok||len(got)!=3||!bytes.Equal(got[1],[]byte("defgh")){t.Fatalf("R_DEEP_ABI_CONTROL_CHANGED: %T %v",out[0],out)}
  }else{
   got,ok:=out[0].([][][]byte)
   if !ok||len(got)!=2||len(got[0])!=2||!bytes.Equal(got[1][0],[]byte("three")){t.Fatalf("R_DEEP_ABI_NESTED_CONTROL_CHANGED: %T %v",out[0],out)}
  }
  if len(script)==0{continue}
  mutated:=append([]byte(nil),data...)
  wordCount:=len(mutated)/32
  // Grammar mutations target existing ABI word locations while preserving
  // enough syntax to enter deep unpack/dependent length calculations.
  for i:=0;i<len(script)&&i<12;i++{
   index:=int(script[i])%wordCount
   off:=index*32
   switch script[i]%7{
   case 0: mutated[off]=0xff                                  // 256-bit offset/length
   case 1: binary.BigEndian.PutUint64(mutated[off+24:off+32],^uint64(0)) // overflow
   case 2: binary.BigEndian.PutUint64(mutated[off+24:off+32],uint64(len(mutated)+64))
   case 3: binary.BigEndian.PutUint64(mutated[off+24:off+32],uint64(32*(index+1)))
   case 4: mutated[off+31]^=0x7f
   case 5: mutated[off+30]^=0x80
   case 6: mutated[off+1]^=0x40
   }
  }
  if len(script)>3&&script[0]%7==6{
   n:=int(script[2])%len(mutated);mutated=mutated[:n]
  }
  decoded,e:=args.Unpack(mutated)
  if e!=nil{continue}
  if len(decoded)!=1{t.Fatalf("R_DEEP_ABI_INVALID_ARITY: %d",len(decoded))}
  switch got:=decoded[0].(type){
  case [][]byte:
   if name!="bytes[]"||len(got)>len(mutated)/32 {t.Fatalf("R_DEEP_ABI_RESOURCE_COUNT: type=%s count=%d input=%d",name,len(got),len(mutated))}
   for _,b:=range got{if len(b)>len(mutated){t.Fatalf("R_DEEP_ABI_OUTPUT_EXPANSION: byte element=%d input=%d",len(b),len(mutated))}}
  case [][][]byte:
   if name!="bytes[][]"||len(got)>len(mutated)/32 {t.Fatalf("R_DEEP_ABI_NESTED_RESOURCE_COUNT: count=%d input=%d",len(got),len(mutated))}
   for _,outer:=range got{
    if len(outer)>len(mutated)/32{t.Fatalf("R_DEEP_ABI_NESTED_CHILD_ALLOCATION: %d",len(outer))}
    for _,b:=range outer{if len(b)>len(mutated){t.Fatalf("R_DEEP_ABI_NESTED_BYTES_EXPANSION: %d",len(b))}}
   }
  default:t.Fatalf("R_DEEP_ABI_UNEXPECTED_TYPE: type=%s got=%T",name,decoded[0])
  }
 }
}
func TestRDeepNestedABIBaseline(t *testing.T){
 for _,seq:=range [][]byte{nil,{0,1,2,3,4,5},{1,1,1,1},{2,6,4,3},{3,3,3,3},{4,5,6,0},{255,254,253,252}}{rDeepNestedABI(t,seq)}
 t.Log("R_DEEP_NESTED_ABI_VALID_AND_SEMANTIC_MUTATION_CONTROLS_PASS")
}
func FuzzRDeepNestedABI(f *testing.F){
 f.Add([]byte{0,1,2,3,4,5})
 f.Add([]byte{255,254,253,252})
 f.Add([]byte{6,0,1,0,1,0,6})
 f.Fuzz(func(t *testing.T,script []byte){
  if len(script)>512{return}
  rDeepNestedABI(t,script)
 })
}
