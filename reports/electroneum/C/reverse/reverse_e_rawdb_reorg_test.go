// Reverse Worker R independent E-RPC-004 canonical receipt read test.
// Installed into a disposable copy of immutable certified Electroneum
// under internal/ethapi. No public RPC, actual funds, or source mutation.
//
// This is a source-backed rawdb adapter with the SAME rawdb.ReadTransaction
// primitive as EthAPIBackend.GetTransaction. It does not instantiate a full
// eth.Ethereum node or prove an attacker can control chain reorg timing.
package ethapi

import (
 "context"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/ethdb"
 "github.com/electroneum/electroneum-sc/params"
 "github.com/electroneum/electroneum-sc/rpc"
 "github.com/electroneum/electroneum-sc/trie"
)

type reverseCanonicalDBBackend struct {
 Backend
 db ethdb.Database
 cfg *params.ChainConfig
 competing *types.Block
 orphanTx common.Hash
 flipOnReceipts bool
 flips int
}
func (b *reverseCanonicalDBBackend) ChainConfig() *params.ChainConfig {return b.cfg}
func (b *reverseCanonicalDBBackend) GetTransaction(_ context.Context,hash common.Hash)(*types.Transaction,common.Hash,uint64,uint64,error){
 tx,block,number,index:=rawdb.ReadTransaction(b.db,hash)
 return tx,block,number,index,nil
}
func (b *reverseCanonicalDBBackend) GetReceipts(_ context.Context,hash common.Hash)(types.Receipts,error){
 if b.flipOnReceipts {
  // Deterministic TOCTOU injection, just after canonical ReadTransaction.
  // Emulates a chain replacement and removal of the orphaned tx lookup.
  rawdb.WriteCanonicalHash(b.db,b.competing.Hash(),b.competing.NumberU64())
  rawdb.DeleteTxLookupEntry(b.db,b.orphanTx)
  b.flipOnReceipts=false
  b.flips++
 }
 number:=rawdb.ReadHeaderNumber(b.db,hash)
 if number==nil {return nil,nil}
 return rawdb.ReadReceipts(b.db,hash,*number,b.cfg),nil
}
func (b *reverseCanonicalDBBackend) HeaderByHash(_ context.Context,hash common.Hash)(*types.Header,error){
 number:=rawdb.ReadHeaderNumber(b.db,hash)
 if number==nil {return nil,nil}
 return rawdb.ReadHeader(b.db,hash,*number),nil
}
func (b *reverseCanonicalDBBackend) BlockByNumber(_ context.Context,number rpc.BlockNumber)(*types.Block,error){
 if number<0 {return nil,nil}
 hash:=rawdb.ReadCanonicalHash(b.db,uint64(number))
 if hash==(common.Hash{}) {return nil,nil}
 return rawdb.ReadBlock(b.db,hash,uint64(number)),nil
}

type reverseCanonicalFixture struct {
 backend *reverseCanonicalDBBackend
 api *PublicTransactionPoolAPI
 oldBlock,newBlock *types.Block
 oldTx,newTx *types.Transaction
}
func reverseMakeCanonicalFixture(t *testing.T) reverseCanonicalFixture {
 t.Helper()
 db:=rawdb.NewMemoryDatabase()
 cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0)}
 key,err:=crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
 if err!=nil {t.Fatal(err)}
 signer:=types.MakeSigner(cfg,big.NewInt(1))
 to:=common.HexToAddress("0x0000000000000000000000000000000000000101")
 makeBlock:=func(tag uint64)(*types.Block,*types.Transaction) {
  unsigned:=types.NewTransaction(tag,to,big.NewInt(int64(tag)),21000,big.NewInt(10),nil)
  tx,e:=types.SignTx(unsigned,signer,key)
  if e!=nil {t.Fatalf("synthetic signature: %v",e)}
  receipt:=&types.Receipt{
   Type:tx.Type(), Status:types.ReceiptStatusSuccessful,
   CumulativeGasUsed:21000, GasUsed:21000, TxHash:tx.Hash(),
  }
  header:=&types.Header{Number:big.NewInt(1), BaseFee:big.NewInt(1),
   GasLimit:30000000, GasUsed:21000, Difficulty:big.NewInt(1)}
  block:=types.NewBlock(header,[]*types.Transaction{tx},nil,[]*types.Receipt{receipt},trie.NewStackTrie(nil))
  rawdb.WriteBlock(db,block)
  rawdb.WriteReceipts(db,block.Hash(),block.NumberU64(),types.Receipts{receipt})
  rawdb.WriteTxLookupEntriesByBlock(db,block)
  return block,tx
 }
 oldBlock,oldTx:=makeBlock(1)
 newBlock,newTx:=makeBlock(2)
 if oldBlock.Hash()==newBlock.Hash()||oldTx.Hash()==newTx.Hash(){t.Fatal("fixture collisions")}
 rawdb.WriteCanonicalHash(db,oldBlock.Hash(),1)
 b:=&reverseCanonicalDBBackend{db:db,cfg:cfg,competing:newBlock,orphanTx:oldTx.Hash()}
 if rawdb.ReadReceipts(db,oldBlock.Hash(),1,cfg)==nil {t.Fatal("missing source-backed stored receipts")}
 return reverseCanonicalFixture{b,NewPublicTransactionPoolAPI(b,new(AddrLocker)),oldBlock,newBlock,oldTx,newTx}
}
func reverseSwitchCanonical(f reverseCanonicalFixture){
 rawdb.WriteCanonicalHash(f.backend.db,f.newBlock.Hash(),1)
 rawdb.DeleteTxLookupEntry(f.backend.db,f.oldTx.Hash())
}

func TestReverseECanonicalRawdbDefenseMatrix(t *testing.T){
 t.Run("honest_canonical_positive",func(t *testing.T){
  f:=reverseMakeCanonicalFixture(t)
  result,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
  if err!=nil||result==nil||result["transactionHash"]!=f.oldTx.Hash()||result["blockHash"]!=f.oldBlock.Hash(){
   t.Fatalf("coherent stored receipt rejected or mismatched: err=%v response=%v",err,result)
  }
  if rawdb.ReadCanonicalHash(f.backend.db,1)!=f.oldBlock.Hash(){t.Fatal("canonical mapping changed unexpectedly")}
  t.Log("REVERSE_E_RAWDB_COHERENT_RECEIPT_PASS")
 })
 t.Run("completed_reorg_orphan_rejected_even_with_stale_lookup",func(t *testing.T){
  f:=reverseMakeCanonicalFixture(t)
  // Keep lookup deliberately; rawdb canonical body scan must reject old tx.
  rawdb.WriteCanonicalHash(f.backend.db,f.newBlock.Hash(),1)
  old,_,_,_:=rawdb.ReadTransaction(f.backend.db,f.oldTx.Hash())
  if old!=nil{t.Fatal("stale orphan lookup bypassed canonical body check")}
  result,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
  if err!=nil||result!=nil{t.Fatalf("completed reorg orphan advertised: err=%v resp=%v",err,result)}
  t.Log("REVERSE_E_RAWDB_ORPHAN_INDEX_DEFENSE_PASS")
 })
 t.Run("completed_reorg_new_canonical_receipt",func(t *testing.T){
  f:=reverseMakeCanonicalFixture(t)
  reverseSwitchCanonical(f)
  result,err:=f.api.GetTransactionReceipt(context.Background(),f.newTx.Hash())
  if err!=nil||result==nil||result["transactionHash"]!=f.newTx.Hash()||result["blockHash"]!=f.newBlock.Hash(){
   t.Fatalf("new canonical tx not served: err=%v resp=%v",err,result)
  }
  t.Log("REVERSE_E_RAWDB_NEW_CANONICAL_PASS")
 })
 t.Run("missing_receipt_fails_closed",func(t *testing.T){
  f:=reverseMakeCanonicalFixture(t)
  rawdb.DeleteReceipts(f.backend.db,f.oldBlock.Hash(),1)
  result,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
  if err!=nil||result!=nil {t.Fatalf("missing stored receipt advertised: err=%v resp=%v",err,result)}
  t.Log("REVERSE_E_RAWDB_MISSING_RECEIPT_NULL_PASS")
 })
 t.Run("mid_request_reorg_source_characterization",func(t *testing.T){
  f:=reverseMakeCanonicalFixture(t)
  f.backend.flipOnReceipts=true
  result,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
  if f.backend.flips!=1||rawdb.ReadCanonicalHash(f.backend.db,1)!=f.newBlock.Hash(){
   t.Fatalf("reorg timing hook failed")
  }
  if err==nil && result!=nil && result["blockHash"]==f.oldBlock.Hash(){
   t.Log("REVERSE_E_RAWDB_TOCTOU_STALE_RECEIPT_OBSERVED: old receipt emitted after block 1 switched canonical")
  } else {
   t.Logf("REVERSE_E_RAWDB_TOCTOU_FAIL_CLOSED: err=%v response=%v",err,result)
  }
  // Source code's canonicality check must NOT be inferred from a successful
  // completed-reorg control: this test deliberately switches mid-query.
 })
}

// An independent invariant: an RPC success response must correspond to the
// canonical block at the point of response. The original target is expected to
// fail this oracle under a deterministic mid-query local reorg. A scratch-only
// post-read canonicality guard should make it pass.
func TestReverseECanonicalTOCTOUOracle(t *testing.T){
 f:=reverseMakeCanonicalFixture(t)
 f.backend.flipOnReceipts=true
 result,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
 if f.backend.flips!=1 {t.Fatal("reorg injection did not execute")}
 canonical:=rawdb.ReadCanonicalHash(f.backend.db,1)
 if canonical!=f.newBlock.Hash(){t.Fatalf("unexpected canonical head %s",canonical)}
 if err==nil && result!=nil {
  t.Errorf("REVERSE_E_CANONICAL_TOCTOU_ORACLE_MISMATCH: orphan %s returned as valid after canonical block changed to %s",f.oldBlock.Hash(),canonical)
  return
 }
 t.Logf("REVERSE_E_CANONICAL_TOCTOU_ORACLE_PASS: stale orphan rejected err=%v",err)
}
