// Reverse R: real eth/66 receipt raw-wire commitment vs semantic RLP decoding.
// Synthetic messages only; injected into a disposable certified-source scratch.
package eth

import (
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
 "github.com/electroneum/electroneum-sc/trie"
)

func reverseDReceiptRoot(t *testing.T,receipts types.Receipts) (common.Hash,rlp.RawValue) {
 t.Helper()
 raw,err:=rlp.EncodeToBytes(receipts)
 if err!=nil {t.Fatal(err)}
 wire,ok:=newRawTypedList(raw,minReceiptContent)
 if !ok {t.Fatal("valid receipt failed network pre-hash framing")}
 return types.DeriveSha(wire,trie.NewStackTrie(nil)),raw
}

func TestReverseDReceiptWireCommitmentDifferential(t *testing.T){
 cases:=[]struct{name string;kind uint8}{
  {"legacy",types.LegacyTxType},
  {"access_list",types.AccessListTxType},
  {"dynamic_fee",types.DynamicFeeTxType},
  {"priority",types.PriorityTxType},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   r:=&types.Receipt{Type:tc.kind,Status:types.ReceiptStatusSuccessful,CumulativeGasUsed:21000,Logs:[]*types.Log{}}
   wireRoot,raw:=reverseDReceiptRoot(t,types.Receipts{r})
   decoded,err:=DecodeReceipts(raw)
   if err!=nil||len(decoded)!=1 {t.Fatalf("valid encoded receipt decode failed: %v count=%d",err,len(decoded))}
   canonicalRoot:=types.DeriveSha(types.Receipts(decoded),trie.NewStackTrie(nil))
   if wireRoot!=canonicalRoot {t.Fatalf("wire/decoded receipt commitment mismatch type=%d wire=%s decoded=%s",tc.kind,wireRoot,canonicalRoot)}
   if decoded[0].Type!=tc.kind||decoded[0].Status!=types.ReceiptStatusSuccessful {
    t.Fatal("semantically different receipt decoded from canonical encoding")
   }
   t.Logf("REVERSE_D_RECEIPT_WIRE_DECODE_ROOT_EQUAL_PASS type=%d",tc.kind)
  })
 }
 t.Run("reordering_changes_commitment",func(t *testing.T){
  a:=&types.Receipt{Type:types.LegacyTxType,Status:types.ReceiptStatusSuccessful,CumulativeGasUsed:21000}
  b:=&types.Receipt{Type:types.LegacyTxType,Status:types.ReceiptStatusFailed,CumulativeGasUsed:42000}
  first,_:=reverseDReceiptRoot(t,types.Receipts{a,b})
  swapped,_:=reverseDReceiptRoot(t,types.Receipts{b,a})
  if first==swapped {t.Fatal("receipt order mutation escaped trie-root oracle")}
  t.Log("REVERSE_D_RECEIPT_REORDER_MUTATION_SENSITIVE_PASS")
 })
 t.Run("unknown_type_may_hash_but_semantic_decoder_rejects",func(t *testing.T){
  unknown:=&types.Receipt{Type:0x7f,Status:types.ReceiptStatusSuccessful,CumulativeGasUsed:21000}
  raw,e:=rlp.EncodeToBytes(types.Receipts{unknown})
  if e!=nil {t.Fatal(e)}
  // Prefilter is intentionally structural rather than a semantic type authority.
  // Downstream DecodeReceipts must reject any type unknown to the certified fork.
  _,err:=DecodeReceipts(raw)
  if err==nil {t.Fatal("unknown typed receipt accepted by semantic decoder")}
  t.Logf("REVERSE_D_UNKNOWN_RECEIPT_TYPE_REJECTED_PASS err=%v",err)
 })
 t.Run("short_rlp_never_has_valid_wire_commitment",func(t *testing.T){
  bad:=rlp.RawValue{0xc1,0x80}
  if _,ok:=newRawTypedList(bad,minReceiptContent);ok {
   t.Fatal("structurally insufficient receipt accepted for wire root")
  }
  t.Log("REVERSE_D_SHORT_RECEIPT_WIRE_REJECTED_PASS")
 })
}
