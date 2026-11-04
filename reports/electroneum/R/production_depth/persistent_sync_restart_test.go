// Worker R production-depth P2: persistent LevelDB stage checkpoints.
// Simulates process loss between separate sync persistence stages, reopens the DB,
// and verifies block/receipt/canonical commitments before and after BlockChain recovery.
package core

import (
 "math/big"
 "path/filepath"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/ethdb"
 "github.com/electroneum/electroneum-sc/params"
 "github.com/electroneum/electroneum-sc/trie"
)

type rPersistStage struct {
 name string
 body bool
 receipts bool
 lookup bool
 head bool
}

func rOpenPersist(t *testing.T,path string) ethdb.Database{
 t.Helper()
 db,err:=rawdb.NewLevelDBDatabase(path,16,16,"r-prod-depth",false)
 if err!=nil{t.Fatalf("R_PERSIST_OPEN_FAIL: %v",err)}
 return db
}

func rPersistFixture(t *testing.T,db ethdb.Database)(*Genesis,*types.Block,types.Receipts,*types.Transaction){
 t.Helper()
 key,err:=crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
 if err!=nil{t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 target:=common.HexToAddress("0x0000000000000000000000000000000000000099")
 cfg:=*params.TestChainConfig
 gspec:=&Genesis{Config:&cfg,GasLimit:8_000_000,Alloc:GenesisAlloc{sender:{Balance:new(big.Int).Mul(big.NewInt(1000),big.NewInt(1e18))}}}
 genesis:=gspec.MustCommit(db)
 signer:=types.LatestSigner(&cfg)
 var tx *types.Transaction
 blocks,receipts:=GenerateChain(&cfg,genesis,ethash.NewFaker(),db,1,func(i int,b *BlockGen){
  tx,err=types.SignTx(types.NewTransaction(b.TxNonce(sender),target,big.NewInt(7),100_000,b.BaseFee(),[]byte{0xaa,0xbb}),signer,key)
  if err!=nil{t.Fatal(err)}
  b.AddTx(tx)
 })
 return gspec,blocks[0],receipts[0],tx
}

func rWriteCheckpoint(t *testing.T,db ethdb.Database,genesis,target *types.Block,receipts types.Receipts,stage rPersistStage){
 t.Helper()
 td:=new(big.Int).Add(rawdb.ReadTd(db,genesis.Hash(),0),target.Difficulty())
 rawdb.WriteTd(db,target.Hash(),target.NumberU64(),td)
 rawdb.WriteHeader(db,target.Header())
 rawdb.WriteCanonicalHash(db,target.Hash(),target.NumberU64())
 if stage.body{rawdb.WriteBody(db,target.Hash(),target.NumberU64(),target.Body())}
 if stage.receipts{rawdb.WriteReceipts(db,target.Hash(),target.NumberU64(),receipts)}
 if stage.lookup{rawdb.WriteTxLookupEntriesByBlock(db,target)}
 if stage.head{
  rawdb.WriteHeadHeaderHash(db,target.Hash())
  rawdb.WriteHeadFastBlockHash(db,target.Hash())
  rawdb.WriteHeadBlockHash(db,target.Hash())
 }
 if _,_,err:=rawdb.PushUncleanShutdownMarker(db);err!=nil{t.Fatalf("R_PERSIST_CRASH_MARKER_FAIL: %v",err)}
}

func rCheckCommitments(t *testing.T,db ethdb.Database,cfg *params.ChainConfig,target *types.Block,receipts types.Receipts,tx *types.Transaction,stage rPersistStage){
 t.Helper()
 h:=rawdb.ReadHeader(db,target.Hash(),target.NumberU64())
 if h==nil||h.Hash()!=target.Hash(){t.Fatalf("R_PERSIST_HEADER_LOST stage=%s",stage.name)}
 body:=rawdb.ReadBody(db,target.Hash(),target.NumberU64())
 if stage.body {
  if body==nil{t.Fatalf("R_PERSIST_BODY_LOST stage=%s",stage.name)}
  if got:=types.DeriveSha(types.Transactions(body.Transactions),trie.NewStackTrie(nil));got!=h.TxHash{
   t.Fatalf("R_PERSIST_TX_ROOT_MISMATCH stage=%s got=%s want=%s",stage.name,got,h.TxHash)
  }
  if got:=types.CalcUncleHash(body.Uncles);got!=h.UncleHash{t.Fatalf("R_PERSIST_UNCLE_ROOT_MISMATCH stage=%s",stage.name)}
 } else if body!=nil {t.Fatalf("R_PERSIST_BODY_EARLY stage=%s",stage.name)}
 raw:=rawdb.ReadRawReceipts(db,target.Hash(),target.NumberU64())
 if stage.receipts {
  if raw==nil{t.Fatalf("R_PERSIST_RAW_RECEIPTS_LOST stage=%s",stage.name)}
  if got:=types.DeriveSha(raw,trie.NewStackTrie(nil));got!=h.ReceiptHash{
   t.Fatalf("R_PERSIST_RECEIPT_ROOT_MISMATCH stage=%s got=%s want=%s",stage.name,got,h.ReceiptHash)
  }
 } else if raw!=nil {t.Fatalf("R_PERSIST_RECEIPTS_EARLY stage=%s",stage.name)}
 derived:=rawdb.ReadReceipts(db,target.Hash(),target.NumberU64(),cfg)
 if stage.body&&stage.receipts {
  if derived==nil||len(derived)!=len(receipts){t.Fatalf("R_PERSIST_DERIVED_RECEIPTS_FAIL stage=%s",stage.name)}
 } else if derived!=nil {
  t.Fatalf("R_PERSIST_INCOMPLETE_RECEIPTS_EXPOSED stage=%s",stage.name)
 }
 found,_,_,_:=rawdb.ReadTransaction(db,tx.Hash())
 if stage.lookup&&stage.body {
  if found==nil||found.Hash()!=tx.Hash(){t.Fatalf("R_PERSIST_LOOKUP_LOST stage=%s",stage.name)}
 } else if found!=nil {
  t.Fatalf("R_PERSIST_LOOKUP_EARLY stage=%s",stage.name)
 }
}

func TestRPersistentSyncCheckpointRestartMatrix(t *testing.T){
 stages:=[]rPersistStage{
  {name:"header_head_only",head:true},
  {name:"receipt_before_body",receipts:true,head:true},
  {name:"body_before_receipt",body:true,head:true},
  {name:"body_receipt_no_lookup",body:true,receipts:true,head:true},
  {name:"complete",body:true,receipts:true,lookup:true,head:true},
 }
 for _,stage:=range stages{
  t.Run(stage.name,func(t *testing.T){
   path:=filepath.Join(t.TempDir(),"chaindata")
   db:=rOpenPersist(t,path)
   gspec,target,receipts,tx:=rPersistFixture(t,db)
   genesis:=rawdb.ReadBlock(db,rawdb.ReadCanonicalHash(db,0),0)
   if genesis==nil{t.Fatal("R_PERSIST_GENESIS_MISSING")}
   rWriteCheckpoint(t,db,genesis,target,receipts,stage)
   if err:=db.Close();err!=nil{t.Fatal(err)}

   db=rOpenPersist(t,path)
   rCheckCommitments(t,db,gspec.Config,target,receipts,tx,stage)
   // Confirm the simulated unclean marker really persisted across process reopen.
   previous,_,err:=rawdb.PushUncleanShutdownMarker(db)
   if err!=nil||len(previous)==0{db.Close();t.Fatalf("R_PERSIST_CRASH_MARKER_NOT_PERSISTED stage=%s previous=%v err=%v",stage.name,previous,err)}
   chain,err:=NewBlockChain(db,nil,gspec.Config,ethash.NewFaker(),vm.Config{},nil,nil)
   if err!=nil{db.Close();t.Fatalf("R_PERSIST_BLOCKCHAIN_RESTART_FAIL stage=%s err=%v",stage.name,err)}
   head:=chain.CurrentBlock()
   if head==nil{chain.Stop();db.Close();t.Fatalf("R_PERSIST_RESTART_NIL_HEAD stage=%s",stage.name)}
   // If the interrupted head had no body, loadLastState must not expose it as
   // the current full block. With a body and generated state present, the block
   // may legitimately be current even when receipts/indexing are still pending.
   if !stage.body&&head.Hash()==target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_INCOMPLETE_HEAD_SURVIVED stage=%s",stage.name)}
   if head.Hash()==target.Hash(){
    if rawdb.ReadBlock(db,target.Hash(),target.NumberU64())==nil{chain.Stop();db.Close();t.Fatalf("R_PERSIST_HEAD_WITHOUT_BLOCK stage=%s",stage.name)}
    if _,err:=chain.StateAt(target.Root());err!=nil{chain.Stop();db.Close();t.Fatalf("R_PERSIST_HEAD_STATE_MISSING stage=%s err=%v",stage.name,err)}
   }
   canonical:=chain.GetCanonicalHash(target.NumberU64())
   if head.NumberU64()<target.NumberU64()&&canonical==target.Hash(){
    chain.Stop();db.Close();t.Fatalf("R_PERSIST_CANONICAL_AHEAD_OF_RECOVERED_HEAD stage=%s",stage.name)
   }
   t.Logf("R_PERSIST_RESTART_STAGE_PASS stage=%s head=%d body=%t receipts=%t lookup=%t canonical_target=%t",stage.name,head.NumberU64(),stage.body,stage.receipts,stage.lookup,canonical==target.Hash())
   chain.Stop()
   if err:=db.Close();err!=nil{t.Fatal(err)}
  })
 }
}

func TestRPersistentCommitmentCorruptionControls(t *testing.T){
 // Counterexample: roots must detect actual persistent data mutation, so a
 // passing restart matrix cannot be caused by an oracle that ignores contents.
 path:=filepath.Join(t.TempDir(),"chaindata")
 db:=rOpenPersist(t,path)
 gspec,target,receipts,_:=rPersistFixture(t,db)
 genesis:=rawdb.ReadBlock(db,rawdb.ReadCanonicalHash(db,0),0)
 stage:=rPersistStage{name:"corruption_control",body:true,receipts:true,lookup:true,head:true}
 rWriteCheckpoint(t,db,genesis,target,receipts,stage)
 raw:=rawdb.ReadBodyRLP(db,target.Hash(),target.NumberU64())
 if len(raw)<2{db.Close();t.Fatal("R_PERSIST_CORRUPTION_FIXTURE_SHORT")}
 raw[len(raw)-1]^=0x01
 rawdb.WriteBodyRLP(db,target.Hash(),target.NumberU64(),raw)
 db.Close()
 db=rOpenPersist(t,path);defer db.Close()
 body:=rawdb.ReadBody(db,target.Hash(),target.NumberU64())
 if body!=nil{
  if got:=types.DeriveSha(types.Transactions(body.Transactions),trie.NewStackTrie(nil));got==target.TxHash(){
   t.Fatal("R_PERSIST_CORRUPTION_ORACLE_BLIND")
  }
 }
 if got:=rawdb.ReadReceipts(db,target.Hash(),target.NumberU64(),gspec.Config);got!=nil{
  // ReadReceipts must derive fields through the body; corrupted/mismatched body
  // must not silently become a valid committed receipt set.
  if root:=types.DeriveSha(got,trie.NewStackTrie(nil));root==target.ReceiptHash(){
   t.Fatal("R_PERSIST_CORRUPTED_BODY_WITH_VALID_RECEIPT_EXPOSED")
  }
 }
 t.Log("R_PERSIST_CORRUPTION_CONTROL_DETECTED_PASS")
}
