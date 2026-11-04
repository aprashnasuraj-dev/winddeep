// Cross-component signed transaction -> rawdb canonical -> ethapi receipt
// reorg and time-of-check/time-of-use (TOCTOU) invariants.
// Scratch-only harness; certified source remains unchanged. No live chain.
package ethapi

import (
 "context"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
)

func auditRCheckReceipt(t *testing.T, f reverseCanonicalFixture, tx *types.Transaction, expectedBlock common.Hash, shouldExist bool) {
 t.Helper()
 response,err:=f.api.GetTransactionReceipt(context.Background(),tx.Hash())
 if err!=nil{t.Fatalf("RPC lookup error tx=%s: %v",tx.Hash(),err)}
 if !shouldExist {
  if response!=nil{t.Fatalf("R_REORG_ORPHAN_ACCEPTED: orphaned transaction %s returned %v",tx.Hash(),response)}
  return
 }
 if response==nil||response["transactionHash"]!=tx.Hash()||response["blockHash"]!=expectedBlock{
  t.Fatalf("R_REORG_CANONICAL_RECEIPT_MISMATCH: got %v expected tx=%s block=%s",response,tx.Hash(),expectedBlock)
 }
 if rawdb.ReadCanonicalHash(f.backend.db,1)!=expectedBlock{
  t.Fatalf("R_REORG_CANONICAL_DB_MISMATCH: block %s no longer canonical",expectedBlock)
 }
}

func auditRReorgScenario(t *testing.T, script []byte) {
 t.Helper()
 if len(script)==0{script=[]byte{0,1}}
 if len(script)>12{script=script[:12]}
 f:=reverseMakeCanonicalFixture(t)
 if f.oldTx.Hash()==f.newTx.Hash(){t.Fatal("invalid: old and new transactions identical")}
 oldBlock:=f.oldBlock.Hash()
 newBlock:=f.newBlock.Hash()
 // Actor-controlled operation transitions always use real rawdb and real
 // PublicTransactionPoolAPI, including a deterministic mid-RPC reorg hook.
 for i,op:=range script{
  switch op%4 {
  case 0: // positive: read still-canonical old transaction
   if rawdb.ReadCanonicalHash(f.backend.db,1)==oldBlock {
    auditRCheckReceipt(t,f,f.oldTx,oldBlock,true)
   }else{
    auditRCheckReceipt(t,f,f.oldTx,oldBlock,false)
   }
  case 1: // completed reorg, old removed, replacement becomes canonical
   reverseSwitchCanonical(f)
   auditRCheckReceipt(t,f,f.oldTx,oldBlock,false)
   auditRCheckReceipt(t,f,f.newTx,newBlock,true)
  case 2: // canonical switches DURING receipt request, before response
   if rawdb.ReadCanonicalHash(f.backend.db,1)!=oldBlock{
    rawdb.WriteCanonicalHash(f.backend.db,oldBlock,1)
    rawdb.WriteTxLookupEntriesByBlock(f.backend.db,f.oldBlock)
   }
   f.backend.flipOnReceipts=true
   response,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
   if f.backend.flips<1{t.Fatalf("R_REORG_INJECTION_MISSED: action=%d",i)}
   if rawdb.ReadCanonicalHash(f.backend.db,1)!=newBlock {t.Fatalf("R_REORG_INJECTION_DID_NOT_CHANGE_CHAIN action=%d",i)}
   if err==nil&&response!=nil {
    t.Fatalf("R_REORG_TOCTOU_ORACLE_FAIL: old transaction returned successfully after block 1 switched to %s, old=%s response=%v step=%d",newBlock,oldBlock,response,i)
   }
   auditRCheckReceipt(t,f,f.newTx,newBlock,true)
  case 3: // rollback to old canonical then validate old; new must become orphan
   rawdb.WriteCanonicalHash(f.backend.db,oldBlock,1)
   rawdb.WriteTxLookupEntriesByBlock(f.backend.db,f.oldBlock)
   rawdb.DeleteTxLookupEntry(f.backend.db,f.newTx.Hash())
   auditRCheckReceipt(t,f,f.oldTx,oldBlock,true)
   auditRCheckReceipt(t,f,f.newTx,newBlock,false)
  }
 }
 t.Logf("R_REORG_STATEFUL_SYNTHETIC_PASS transitions=%d",len(script))
}
func TestRReorgCompletedTransitions(t *testing.T){
 for _,script:=range [][]byte{{0,1,0},{0,1,3,1},{1,3,0,1}}{auditRReorgScenario(t,script)}
}
func FuzzRReorgStateMachine(f *testing.F) {
 // Seed only coherent states; let coverage-guided mutation discover TOCTOU.
 f.Add([]byte{0,1,0})
 f.Add([]byte{1,3,1,3})
 f.Add([]byte{0,0,1})
 f.Fuzz(func(t *testing.T,script []byte){
  if len(script)>24{return}
  auditRReorgScenario(t,script)
 })
}
