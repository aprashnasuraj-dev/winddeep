// Worker R production-depth P2: persistent LevelDB stage checkpoints.
// Simulates process loss between separate sync persistence stages, reopens the DB,
// and verifies block/receipt/canonical commitments before and after BlockChain recovery.
package core

import (
 "math/big"
 "os"
 "os/exec"
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
  // Header sync is allowed to lead body/receipt/full-state persistence.
  rawdb.WriteHeadHeaderHash(db,target.Hash())
  // Fast head only advances once body+receipts are jointly available.
  if stage.body&&stage.receipts{rawdb.WriteHeadFastBlockHash(db,target.Hash())}
  // Full head requires the completed checkpoint in this model.
  if stage.body&&stage.receipts&&stage.lookup{rawdb.WriteHeadBlockHash(db,target.Hash())}
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
   // Canonical/header sync may legitimately be ahead of the full block head.
   // Only the completed body+receipt+lookup checkpoint advances the full head.
   if !stage.lookup&&head.Hash()==target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_FULL_HEAD_ADVANCED_EARLY stage=%s",stage.name)}
   if stage.lookup&&head.Hash()!=target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_COMPLETE_HEAD_NOT_RESTORED stage=%s head=%s",stage.name,head.Hash())}
   currentHeader:=chain.CurrentHeader()
   if currentHeader==nil||currentHeader.Hash()!=target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_HEADER_HEAD_LOST stage=%s",stage.name)}
   fast:=chain.CurrentFastBlock()
   if stage.body&&stage.receipts {
    if fast==nil||fast.Hash()!=target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_FAST_HEAD_NOT_RESTORED stage=%s",stage.name)}
   } else if fast!=nil&&fast.Hash()==target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_FAST_HEAD_ADVANCED_EARLY stage=%s",stage.name)}
   if head.Hash()==target.Hash(){
    if rawdb.ReadBlock(db,target.Hash(),target.NumberU64())==nil{chain.Stop();db.Close();t.Fatalf("R_PERSIST_HEAD_WITHOUT_BLOCK stage=%s",stage.name)}
    if _,err:=chain.StateAt(target.Root());err!=nil{chain.Stop();db.Close();t.Fatalf("R_PERSIST_HEAD_STATE_MISSING stage=%s err=%v",stage.name,err)}
   }
   canonical:=chain.GetCanonicalHash(target.NumberU64())
   if canonical!=target.Hash(){chain.Stop();db.Close();t.Fatalf("R_PERSIST_CANONICAL_HEADER_MAPPING_LOST stage=%s",stage.name)}
   t.Logf("R_PERSIST_RESTART_STAGE_PASS stage=%s full_head=%d fast_head=%d header_head=%d body=%t receipts=%t lookup=%t",stage.name,head.NumberU64(),fast.NumberU64(),currentHeader.Number.Uint64(),stage.body,stage.receipts,stage.lookup)
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


func rAbruptStage(name string) (rPersistStage, bool) {
 switch name {
 case "receipt_before_body":
  return rPersistStage{name:name,receipts:true,head:true},true
 case "body_before_receipt":
  return rPersistStage{name:name,body:true,head:true},true
 case "body_receipt_no_lookup":
  return rPersistStage{name:name,body:true,receipts:true,head:true},true
 case "complete":
  return rPersistStage{name:name,body:true,receipts:true,lookup:true,head:true},true
 default:
  return rPersistStage{},false
 }
}

// Child-only helper. The parent invokes the current Go test binary and this
// function exits the entire process without closing LevelDB, after all writes
// for one sync checkpoint have returned. This models an unclean process loss
// between persistence stages (not a torn sector inside an individual Put).
func TestRPersistentSubprocessAbruptExitChild(t *testing.T) {
 stageName:=os.Getenv("R_PERSIST_CHILD_STAGE")
 if stageName=="" { return }
 stage,ok:=rAbruptStage(stageName);if !ok{t.Fatalf("R_PERSIST_CHILD_BAD_STAGE %q",stageName)}
 path:=os.Getenv("R_PERSIST_CHILD_PATH");if path==""{t.Fatal("R_PERSIST_CHILD_PATH missing")}
 db:=rOpenPersist(t,path)
 _,target,receipts,_:=rPersistFixture(t,db)
 genesis:=rawdb.ReadBlock(db,rawdb.ReadCanonicalHash(db,0),0)
 if genesis==nil{t.Fatal("R_PERSIST_CHILD_GENESIS_MISSING")}
 rWriteCheckpoint(t,db,genesis,target,receipts,stage)
 // Intentionally do not Stop/Close/flush through application teardown.
 // Individual LevelDB Put calls have returned; process termination happens
 // between stage writes, which is the crash boundary being tested.
 os.Exit(97)
}

func TestRPersistentSubprocessAbruptExitRecovery(t *testing.T) {
 for _,stageName:=range []string{"receipt_before_body","body_before_receipt","body_receipt_no_lookup","complete"}{
  t.Run(stageName,func(t *testing.T){
   stage,_:=rAbruptStage(stageName)
   path:=filepath.Join(t.TempDir(),"chaindata")
   cmd:=exec.Command(os.Args[0],"-test.run=^TestRPersistentSubprocessAbruptExitChild$","-test.v")
   cmd.Env=append(os.Environ(),"R_PERSIST_CHILD_STAGE="+stageName,"R_PERSIST_CHILD_PATH="+path)
   output,err:=cmd.CombinedOutput()
   if err==nil{t.Fatalf("R_PERSIST_CHILD_DID_NOT_EXIT_ABRUPTLY stage=%s output=%s",stageName,output)}
   exitErr,ok:=err.(*exec.ExitError)
   if !ok||exitErr.ExitCode()!=97{t.Fatalf("R_PERSIST_CHILD_WRONG_EXIT stage=%s err=%v output=%s",stageName,err,output)}

   db:=rOpenPersist(t,path)
   targetHash:=rawdb.ReadCanonicalHash(db,1)
   if targetHash==(common.Hash{}){db.Close();t.Fatalf("R_PERSIST_ABRUPT_CANONICAL_MISSING stage=%s",stageName)}
   header:=rawdb.ReadHeader(db,targetHash,1)
   if header==nil{db.Close();t.Fatalf("R_PERSIST_ABRUPT_HEADER_MISSING stage=%s",stageName)}
   body:=rawdb.ReadBody(db,targetHash,1)
   rawReceipts:=rawdb.ReadRawReceipts(db,targetHash,1)
   if stage.body!=(body!=nil){db.Close();t.Fatalf("R_PERSIST_ABRUPT_BODY_STAGE_MISMATCH stage=%s present=%t",stageName,body!=nil)}
   if stage.receipts!=(rawReceipts!=nil){db.Close();t.Fatalf("R_PERSIST_ABRUPT_RECEIPT_STAGE_MISMATCH stage=%s present=%t",stageName,rawReceipts!=nil)}
   if body!=nil{
    if root:=types.DeriveSha(types.Transactions(body.Transactions),trie.NewStackTrie(nil));root!=header.TxHash{
     db.Close();t.Fatalf("R_PERSIST_ABRUPT_TX_ROOT_MISMATCH stage=%s",stageName)
    }
   }
   if rawReceipts!=nil{
    if root:=types.DeriveSha(rawReceipts,trie.NewStackTrie(nil));root!=header.ReceiptHash{
     db.Close();t.Fatalf("R_PERSIST_ABRUPT_RECEIPT_ROOT_MISMATCH stage=%s",stageName)
    }
   }
   if stage.lookup{
    if body==nil||len(body.Transactions)==0{db.Close();t.Fatal("R_PERSIST_ABRUPT_LOOKUP_FIXTURE_MISSING_TX")}
    tx:=body.Transactions[0]
    found,blockHash,number,_:=rawdb.ReadTransaction(db,tx.Hash())
    if found==nil||found.Hash()!=tx.Hash()||blockHash!=targetHash||number!=1{db.Close();t.Fatalf("R_PERSIST_ABRUPT_LOOKUP_LOST stage=%s",stageName)}
   } else if body!=nil&&len(body.Transactions)>0{
    if entry:=rawdb.ReadTxLookupEntry(db,body.Transactions[0].Hash());entry!=nil{db.Close();t.Fatalf("R_PERSIST_ABRUPT_LOOKUP_ADVANCED_EARLY stage=%s",stageName)}
   }
   previous,_,err:=rawdb.PushUncleanShutdownMarker(db)
   if err!=nil||len(previous)==0{db.Close();t.Fatalf("R_PERSIST_ABRUPT_UNCLEAN_MARKER_MISSING stage=%s previous=%v err=%v",stageName,previous,err)}

   // Restart the real blockchain on the uncleanly terminated database.
   cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
   if cfg==nil{db.Close();t.Fatalf("R_PERSIST_ABRUPT_CHAIN_CONFIG_MISSING stage=%s",stageName)}
   chain,err:=NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
   if err!=nil{db.Close();t.Fatalf("R_PERSIST_ABRUPT_BLOCKCHAIN_RESTART_FAIL stage=%s err=%v",stageName,err)}
   full:=chain.CurrentBlock();fast:=chain.CurrentFastBlock();head:=chain.CurrentHeader()
   if head==nil||head.Hash()!=targetHash{chain.Stop();db.Close();t.Fatalf("R_PERSIST_ABRUPT_HEADER_HEAD_LOST stage=%s",stageName)}
   if stage.body&&stage.receipts{
    if fast==nil||fast.Hash()!=targetHash{chain.Stop();db.Close();t.Fatalf("R_PERSIST_ABRUPT_FAST_HEAD_LOST stage=%s",stageName)}
   } else if fast!=nil&&fast.Hash()==targetHash{
    chain.Stop();db.Close();t.Fatalf("R_PERSIST_ABRUPT_FAST_HEAD_ADVANCED_EARLY stage=%s",stageName)
   }
   if stage.lookup{
    if full==nil||full.Hash()!=targetHash{chain.Stop();db.Close();t.Fatalf("R_PERSIST_ABRUPT_FULL_HEAD_LOST stage=%s",stageName)}
   } else if full!=nil&&full.Hash()==targetHash{
    chain.Stop();db.Close();t.Fatalf("R_PERSIST_ABRUPT_FULL_HEAD_ADVANCED_EARLY stage=%s",stageName)
   }
   t.Logf("R_PERSIST_ABRUPT_EXIT_RESTART_PASS stage=%s full=%d fast=%d header=%d",stageName,full.NumberU64(),fast.NumberU64(),head.Number.Uint64())
   chain.Stop()
   if err:=db.Close();err!=nil{t.Fatal(err)}
  })
 }
 t.Log("R_PERSIST_ABRUPT_EXIT_MATRIX_PASS")
}
