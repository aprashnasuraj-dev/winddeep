// Worker R production-depth P1: real core.BlockChain + real EthAPIBackend receipt
// behavior during validated competing-chain import. No public network is used.
// InsertChain is the same validated block-import path fed by normal sync/peer data.
package eth

import (
 "context"
 "math/big"
 "runtime"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/internal/ethapi"
 "github.com/electroneum/electroneum-sc/params"
)

type rFullFixture struct {
 chain *core.BlockChain
 db interface{ Close() error }
 backend *EthAPIBackend
 api *ethapi.PublicTransactionPoolAPI
 fork types.Blocks
 oldTx *types.Transaction
 oldBlock *types.Block
 oldHead *types.Block
}

func rNewFullFixture(t *testing.T, oldLen int) *rFullFixture {
 t.Helper()
 key,err:=crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
 if err!=nil{t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 target:=common.HexToAddress("0x0000000000000000000000000000000000000042")
 db:=rawdb.NewMemoryDatabase()
 gspec:=&core.Genesis{Config:paramsCopyForRFull(),GasLimit:8_000_000,Alloc:core.GenesisAlloc{sender:{Balance:new(big.Int).Mul(big.NewInt(1000),big.NewInt(1e18))}}}
 genesis:=gspec.MustCommit(db)
 signer:=types.LatestSigner(gspec.Config)
 var tx *types.Transaction
 old, _:=core.GenerateChain(gspec.Config,genesis,ethash.NewFaker(),db,oldLen,func(i int,b *core.BlockGen){
  b.SetExtra([]byte{0xa1,byte(i)})
  if i==0{
   tx,err=types.SignTx(types.NewTransaction(b.TxNonce(sender),target,big.NewInt(1),100_000,b.BaseFee(),[]byte{0x01}),signer,key)
   if err!=nil{t.Fatal(err)}
   b.AddTx(tx)
  }
 })
 chain,err:=core.NewBlockChain(db,nil,gspec.Config,ethash.NewFaker(),vm.Config{},nil,nil)
 if err!=nil{t.Fatal(err)}
 if i,err:=chain.InsertChain(old);err!=nil{chain.Stop();t.Fatalf("R_FULL_OLD_IMPORT_FAIL index=%d err=%v",i,err)}
 fork,_:=core.GenerateChain(gspec.Config,genesis,ethash.NewFaker(),db,oldLen+1,func(i int,b *core.BlockGen){
  b.SetExtra([]byte{0xb2,byte(i)})
 })
 svc:=&Ethereum{blockchain:chain,chainDb:db}
 backend:=&EthAPIBackend{eth:svc}
 api:=ethapi.NewPublicTransactionPoolAPI(backend,new(ethapi.AddrLocker))
 f:=&rFullFixture{chain:chain,db:db,backend:backend,api:api,fork:fork,oldTx:tx,oldBlock:old[0],oldHead:old[len(old)-1]}
 before,err:=api.GetTransactionReceipt(context.Background(),tx.Hash())
 if err!=nil||before==nil||before["blockHash"]!=f.oldBlock.Hash(){f.Close();t.Fatalf("R_FULL_POSITIVE_RECEIPT_CONTROL_FAIL err=%v receipt=%v",err,before)}
 return f
}

func paramsCopyForRFull()*params.ChainConfig{
 c:=*params.TestChainConfig
 return &c
}

func (f *rFullFixture)Close(){if f.chain!=nil{f.chain.Stop()};if f.db!=nil{_ = f.db.Close()}}

type rDelayedFullBackend struct {
 ethapi.Backend
 beforeReceipts func()
}
func (b *rDelayedFullBackend)GetReceipts(ctx context.Context,h common.Hash)(types.Receipts,error){
 if b.beforeReceipts!=nil{b.beforeReceipts()}
 return b.Backend.GetReceipts(ctx,h)
}

func TestRFullBackendDeterministicReorgOracle(t *testing.T){
 f:=rNewFullFixture(t,4);defer f.Close()
 var once sync.Once
 wrapped:=&rDelayedFullBackend{Backend:f.backend,beforeReceipts:func(){
  once.Do(func(){
   if i,err:=f.chain.InsertChain(f.fork);err!=nil{t.Fatalf("R_FULL_INJECTED_FORK_IMPORT_FAIL index=%d err=%v",i,err)}
  })
 }}
 api:=ethapi.NewPublicTransactionPoolAPI(wrapped,new(ethapi.AddrLocker))
 receipt,err:=api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
 if err!=nil{t.Fatalf("R_FULL_ORACLE_RPC_ERROR: %v",err)}
 if f.chain.GetCanonicalHash(f.oldBlock.NumberU64())==f.oldBlock.Hash(){t.Fatal("R_FULL_ORACLE_REORG_NOT_APPLIED")}
 if receipt==nil||receipt["blockHash"]!=f.oldBlock.Hash(){
  t.Fatalf("R_FULL_ORACLE_CHANGED: expected stale old receipt under injected between-call reorg, got=%v",receipt)
 }
 canonical:=f.chain.GetCanonicalHash(f.oldBlock.NumberU64())
 if canonical==f.oldBlock.Hash(){t.Fatal("R_FULL_ORACLE_FALSE_POSITIVE")}
 t.Logf("R_FULL_BACKEND_TOCTOU_ORACLE_MISMATCH old=%s new=%s confirmations_before=%d",f.oldBlock.Hash(),canonical,f.oldHead.NumberU64()-f.oldBlock.NumberU64())
 // A confirmation-aware consumer that rechecks block identity must reject it.
 if receipt["blockHash"]==canonical{t.Fatal("R_FULL_DOWNSTREAM_CANONICAL_RECHECK_ORACLE_BROKEN")}
 t.Log("R_FULL_DOWNSTREAM_RECHECK_REJECTS_STALE_RECEIPT_PASS")
}

func TestRFullBackendOrdinaryImportRaceWindow(t *testing.T){
 // No delay wrapper here. We repeatedly query the unmodified real EthAPIBackend
 // while a validated longer fork is imported via BlockChain.InsertChain.
 depths:=[]int{2,4,7}
 const trialsPerDepth=8
 var totalCalls,totalOldResponses,totalStraddled,totalPostcheckStale int64
 var maxStraddleNs int64
 for _,oldLen:=range depths{
  for trial:=0;trial<trialsPerDepth;trial++{
   f:=rNewFullFixture(t,oldLen)
   oldHash:=f.oldBlock.Hash()
   oldNumber:=f.oldBlock.NumberU64()
   var flipNs atomic.Int64
   stopWatch:=make(chan struct{})
   go func(){
    for{
     select{case <-stopWatch:return;default:}
     if f.chain.GetCanonicalHash(oldNumber)!=oldHash{flipNs.CompareAndSwap(0,time.Now().UnixNano());return}
     runtime.Gosched()
    }
   }()
   start:=make(chan struct{})
   stop:=make(chan struct{})
   var wg sync.WaitGroup
   workers:=2
   wg.Add(workers)
   for w:=0;w<workers;w++{
    go func(){
     defer wg.Done();<-start
     for{
      select{case <-stop:return;default:}
      t0:=time.Now().UnixNano()
      receipt,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
      t1:=time.Now().UnixNano()
      if err!=nil{t.Errorf("R_FULL_DIRECT_RPC_ERROR: %v",err);return}
      atomic.AddInt64(&totalCalls,1)
      if receipt!=nil&&receipt["blockHash"]==oldHash{
       atomic.AddInt64(&totalOldResponses,1)
       canonicalAfter:=f.chain.GetCanonicalHash(oldNumber)
       if canonicalAfter!=oldHash{atomic.AddInt64(&totalPostcheckStale,1)}
       flip:=flipNs.Load()
       if flip>0&&t0<=flip&&flip<=t1{
        atomic.AddInt64(&totalStraddled,1)
        delta:=t1-flip
        for{
         cur:=atomic.LoadInt64(&maxStraddleNs)
         if delta<=cur||atomic.CompareAndSwapInt64(&maxStraddleNs,cur,delta){break}
        }
       }
      }
     }
    }()
   }
   close(start)
   time.Sleep(200*time.Microsecond)
   if i,err:=f.chain.InsertChain(f.fork);err!=nil{close(stop);wg.Wait();close(stopWatch);f.Close();t.Fatalf("R_FULL_PEER_EQUIVALENT_FORK_IMPORT_FAIL index=%d err=%v",i,err)}
   deadline:=time.Now().Add(2*time.Millisecond)
   for time.Now().Before(deadline){runtime.Gosched()}
   close(stop);wg.Wait();close(stopWatch)
   if f.chain.GetCanonicalHash(oldNumber)==oldHash{f.Close();t.Fatal("R_FULL_PEER_EQUIVALENT_REORG_DID_NOT_WIN")}
   // Completed reorg control: old transaction must no longer resolve.
   completed,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
   if err!=nil||completed!=nil{f.Close();t.Fatalf("R_FULL_COMPLETED_REORG_CONTROL_FAIL err=%v receipt=%v",err,completed)}
   f.Close()
  }
 }
 if totalCalls==0||totalOldResponses==0{t.Fatalf("R_FULL_RACE_CAMPAIGN_NOT_EXERCISED calls=%d old=%d",totalCalls,totalOldResponses)}
 t.Logf("R_FULL_BACKEND_DIRECT_RACE_METRICS trials=%d calls=%d old_receipts=%d postcheck_stale=%d straddled=%d max_flip_to_return_ns=%d",
  len(depths)*trialsPerDepth,totalCalls,totalOldResponses,totalPostcheckStale,totalStraddled,maxStraddleNs)
 if totalStraddled>0{
  t.Log("R_FULL_BACKEND_ORDINARY_IMPORT_TOCTOU_OBSERVED")
 }else{
  t.Log("R_FULL_BACKEND_ORDINARY_IMPORT_TOCTOU_NOT_OBSERVED_IN_BOUNDED_CAMPAIGN")
 }
 t.Log("R_FULL_BACKEND_PEER_EQUIVALENT_INSERTCHAIN_CONTROL_PASS")
}
