package abi

import (
 "bytes"
 "encoding/binary"
 "runtime"
 "testing"
 "time"
)

func rNestedPayload(target int) [][][]byte{
 chunk:=bytes.Repeat([]byte{0x41},4096)
 outer:=make([][][]byte,0,target/(len(chunk)*8)+1)
 total:=0
 for total<target{
  row:=make([][]byte,0,8)
  for i:=0;i<8&&total<target;i++{row=append(row,append([]byte(nil),chunk...));total+=len(chunk)}
  outer=append(outer,row)
 }
 return outer
}

func TestRRealisticNestedABIResourceBudgets(t *testing.T){
 typ,err:=NewType("bytes[][]","",nil);if err!=nil{t.Fatal(err)}
 args:=Arguments{{Type:typ}}
 for _,size:=range []int{1024*1024,4*1024*1024}{
  value:=rNestedPayload(size)
  packed,err:=args.Pack(value);if err!=nil{t.Fatalf("R_ABI_LARGE_PACK_FAIL size=%d err=%v",size,err)}
  var before,after runtime.MemStats
  runtime.GC();runtime.ReadMemStats(&before)
  start:=time.Now();out,err:=args.Unpack(packed);elapsed:=time.Since(start)
  runtime.ReadMemStats(&after)
  if err!=nil||len(out)!=1{t.Fatalf("R_ABI_LARGE_UNPACK_FAIL size=%d err=%v",size,err)}
  got,ok:=out[0].([][][]byte);if !ok||len(got)!=len(value){t.Fatalf("R_ABI_LARGE_SHAPE_FAIL size=%d type=%T rows=%d/%d",size,out[0],len(got),len(value))}
  if elapsed>8*time.Second{t.Fatalf("R_ABI_LARGE_WALLTIME_BREACH size=%d elapsed=%s",size,elapsed)}
  delta:=uint64(0);if after.TotalAlloc>before.TotalAlloc{delta=after.TotalAlloc-before.TotalAlloc}
  // Decoder allocation may exceed payload due to slices/interfaces, but >12x
  // input is an explicit regression budget under this controlled shape.
  if delta>uint64(len(packed))*12{t.Fatalf("R_ABI_ALLOCATION_AMPLIFICATION size=%d encoded=%d alloc=%d",size,len(packed),delta)}
  t.Logf("R_ABI_REALISTIC_SIZE_PASS requested=%d encoded=%d rows=%d elapsed=%s alloc=%d",size,len(packed),len(got),elapsed,delta)

  // Semantic pointer mutation must fail quickly without decoding a giant tree.
  mutant:=append([]byte(nil),packed...)
  binary.BigEndian.PutUint64(mutant[24:32],^uint64(0))
  start=time.Now();bad,err:=args.Unpack(mutant);elapsed=time.Since(start)
  if err==nil&&bad!=nil{t.Fatalf("R_ABI_GIANT_OFFSET_ACCEPTED size=%d",size)}
  if elapsed>2*time.Second{t.Fatalf("R_ABI_GIANT_OFFSET_STALL size=%d elapsed=%s",size,elapsed)}
 }
}
