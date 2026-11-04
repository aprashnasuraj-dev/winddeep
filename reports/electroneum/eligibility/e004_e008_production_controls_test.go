// E004: demonstrate a receipt/head consistency failure through the real
// downloader -> BlockChain -> EthAPIBackend path, with a minimal third-party
// decision oracle. This is an IN-PROCESS peer and ethash.NewFaker chain:
// it DOES NOT establish public QBFT attacker reachability or a real exchange bug.
package eth

import (
 "context"
 "sync"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/common/hexutil"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/eth/downloader"
 ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
 "github.com/electroneum/electroneum-sc/event"
 "github.com/electroneum/electroneum-sc/internal/ethapi"
 "github.com/electroneum/electroneum-sc/rpc"
)

func eligibilityReceiptDecision(t *testing.T, receipt map[string]interface{}, head uint64, minConf uint64, canonicalHash func(uint64)common.Hash)(naive bool,canonicalAware bool,confirmations uint64){
 t.Helper()
 if receipt==nil{return false,false,0}
 number,ok:=receipt["blockNumber"].(hexutil.Uint64)
 if !ok{t.Fatalf("unexpected block number encoding %T",receipt["blockNumber"])}
 status,ok:=receipt["status"].(hexutil.Uint)
 if !ok{t.Fatalf("unexpected receipt status encoding %T",receipt["status"])}
 blockHash,ok:=receipt["blockHash"].(common.Hash)
 if !ok{t.Fatalf("unexpected receipt block hash encoding %T",receipt["blockHash"])}
 if uint64(number)>head{return false,false,0}
 confirmations=head-uint64(number)+1
 naive=uint64(status)==types.ReceiptStatusSuccessful && confirmations>=minConf
 canonicalAware=naive && canonicalHash(uint64(number))==blockHash
 return
}

func TestEligibilityE004DownloaderTriggeredStaleReceiptDecision(t *testing.T){
 const minConf uint64=3
 f:=rNewFullFixture(t,4)
 defer f.Close()
 before,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
 if err!=nil||before==nil{t.Fatalf("valid baseline missing err=%v",err)}
 initialNaive,initialSafe,initialCount:=eligibilityReceiptDecision(t,before,f.chain.CurrentBlock().NumberU64(),minConf,f.chain.GetCanonicalHash)
 if !initialNaive||!initialSafe||initialCount<minConf{t.Fatal("valid canonical positive control failed")}
 t.Logf("ELIGIBILITY_E004_CANONICAL_POSITIVE_PASS confirmations=%d",initialCount)

 remoteDB,remote:=rRemoteForkChain(t,f)
 defer remoteDB.Close()
 defer remote.Stop()
 dl:=downloader.New(0,f.backend.ChainDb(),new(event.TypeMux),f.chain,nil,func(string){},nil)
 defer dl.Terminate()
 peer:=&rProtocolPeer{id:"eligibility-peer",chain:remote}
 if err:=dl.RegisterPeer(peer.id,ethproto.ETH66,peer);err!=nil{t.Fatalf("register peer: %v",err)}

 var once sync.Once
 var syncErr error
 wrapped:=&rDelayedFullBackend{Backend:f.backend,beforeReceipts:func(){
  once.Do(func(){
   head,td:=peer.Head()
   syncErr=dl.LegacySync(peer.id,head,td,nil,downloader.FullSync)
  })
 }}
 api:=ethapi.NewPublicTransactionPoolAPI(wrapped,new(ethapi.AddrLocker))
 response,err:=api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
 if syncErr!=nil{t.Fatalf("valid downloader sync failed: %v",syncErr)}
 if err!=nil||response==nil{t.Fatalf("mid-sync receipt unavailable err=%v",err)}
 canonical:=f.chain.GetCanonicalHash(f.oldBlock.NumberU64())
 if canonical==f.oldBlock.Hash(){t.Fatal("competing fork did not become canonical")}
 if response["transactionHash"]!=f.oldTx.Hash()||response["blockHash"]!=f.oldBlock.Hash(){t.Fatalf("unexpected receipt response: %v",response)}
 head:=f.chain.CurrentBlock().NumberU64()
 naive,safe,conf:=eligibilityReceiptDecision(t,response,head,minConf,f.chain.GetCanonicalHash)
 if !naive||safe{t.Fatalf("expected naive credit and canonical-aware rejection: naive=%v safe=%v conf=%d",naive,safe,conf)}
 t.Logf("ELIGIBILITY_E004_DOWNLOADER_STALE_RECEIPT_CONFIRMED head=%d receipt_block=%d apparent_confirmations=%d canonical=%s old=%s",head,uint64(response["blockNumber"].(hexutil.Uint64)),conf,canonical,f.oldBlock.Hash())
 t.Logf("ELIGIBILITY_E004_UNSAFE_CONSUMER_FALSE_CREDIT_SIMULATED naive_credit=%t canonical_aware_credit=%t min_confirmations=%d",naive,safe,minConf)

 after,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
 if err!=nil||after!=nil{t.Fatalf("completed reorg must reject orphan: err=%v receipt=%v",err,after)}
 t.Log("ELIGIBILITY_E004_COMPLETED_REORG_NEGATIVE_CONTROL_PASS")
 t.Log("ELIGIBILITY_E004_SCOPE_NOTE in_process_peer=true qbft_validator_attack=false real_exchange=false")
}

func TestEligibilityE008CoherentBackendHeadersAcrossFork(t *testing.T){
 f:=rNewFullFixture(t,4)
 defer f.Close()
 check:=func(label string){
  for n:=uint64(1);n<=f.chain.CurrentBlock().NumberU64();n++{
   header,err:=f.backend.HeaderByNumber(context.Background(),rpc.BlockNumber(n))
   if err!=nil||header==nil||header.Number.Uint64()!=n{
    t.Fatalf("%s canonical header missing at n=%d: header=%v err=%v",label,n,header,err)
   }
  }
 }
 check("before")
 if i,err:=f.chain.InsertChain(f.fork);err!=nil{t.Fatalf("validated replacement fork failed i=%d err=%v",i,err)}
 check("after")
 t.Log("ELIGIBILITY_E008_COHERENT_FULL_BACKEND_HEADER_RANGE_PASS missing_middle_header_not_produced_by_normal_import")
 t.Log("ELIGIBILITY_E008_SCOPE_NOTE does_not_test_concurrent_pruning_or_storage_fault")
}
