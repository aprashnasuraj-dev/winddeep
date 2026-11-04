// Worker R production-depth P1b: real downloader Peer -> LegacySync -> real
// core.BlockChain reorg while real eth.EthAPIBackend receipt queries run.
// Synthetic in-process peer; no public network or validator system is touched.
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
 "github.com/electroneum/electroneum-sc/eth/downloader"
 ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
 "github.com/electroneum/electroneum-sc/ethdb"
 "github.com/electroneum/electroneum-sc/event"
 "github.com/electroneum/electroneum-sc/rlp"
 "github.com/electroneum/electroneum-sc/trie"
)

type rProtocolPeer struct {
 id string
 chain *core.BlockChain
}

func (p *rProtocolPeer) Head()(common.Hash,*big.Int){
 head:=p.chain.CurrentBlock()
 return head.Hash(),p.chain.GetTd(head.Hash(),head.NumberU64())
}

func rProtocolHeaders(raw []rlp.RawValue)[]*types.Header{
 out:=make([]*types.Header,len(raw))
 for i,b:=range raw{
  var h types.Header
  if err:=rlp.DecodeBytes(b,&h);err!=nil{panic(err)}
  out[i]=&h
 }
 return out
}

func (p *rProtocolPeer) RequestHeadersByHash(origin common.Hash,amount int,skip int,reverse bool,sink chan *ethproto.Response)(*ethproto.Request,error){
 raw:=ethproto.ServiceGetBlockHeadersQuery(p.chain,&ethproto.GetBlockHeadersPacket{
  Origin:ethproto.HashOrNumber{Hash:origin},Amount:uint64(amount),Skip:uint64(skip),Reverse:reverse,
 },nil)
 headers:=rProtocolHeaders(raw)
 hashes:=make([]common.Hash,len(headers));for i,h:=range headers{hashes[i]=h.Hash()}
 req:=&ethproto.Request{Peer:p.id}
 res:=&ethproto.Response{Req:req,Res:(*ethproto.BlockHeadersPacket)(&headers),Meta:hashes,Time:1,Done:make(chan error,1)}
 go func(){sink<-res}()
 return req,nil
}
func (p *rProtocolPeer) RequestHeadersByNumber(origin uint64,amount int,skip int,reverse bool,sink chan *ethproto.Response)(*ethproto.Request,error){
 raw:=ethproto.ServiceGetBlockHeadersQuery(p.chain,&ethproto.GetBlockHeadersPacket{
  Origin:ethproto.HashOrNumber{Number:origin},Amount:uint64(amount),Skip:uint64(skip),Reverse:reverse,
 },nil)
 headers:=rProtocolHeaders(raw)
 hashes:=make([]common.Hash,len(headers));for i,h:=range headers{hashes[i]=h.Hash()}
 req:=&ethproto.Request{Peer:p.id}
 res:=&ethproto.Response{Req:req,Res:(*ethproto.BlockHeadersPacket)(&headers),Meta:hashes,Time:1,Done:make(chan error,1)}
 go func(){sink<-res}()
 return req,nil
}
func (p *rProtocolPeer) RequestBodies(hashes []common.Hash,sink chan *ethproto.Response)(*ethproto.Request,error){
 blobs:=ethproto.ServiceGetBlockBodiesQuery(p.chain,hashes)
 bodies:=make([]*ethproto.BlockBody,len(blobs))
 for i,blob:=range blobs{
  bodies[i]=new(ethproto.BlockBody)
  if err:=rlp.DecodeBytes(blob,bodies[i]);err!=nil{return nil,err}
 }
 txRoots:=make([]common.Hash,len(bodies));uncleRoots:=make([]common.Hash,len(bodies))
 for i,b:=range bodies{
  txRoots[i]=types.DeriveSha(types.Transactions(b.Transactions),trie.NewStackTrie(nil))
  uncleRoots[i]=types.CalcUncleHash(b.Uncles)
 }
 raw:=make(ethproto.RawBlockBodiesPacket,len(blobs))
 for i,blob:=range blobs{if err:=rlp.DecodeBytes(blob,&raw[i]);err!=nil{return nil,err}}
 req:=&ethproto.Request{Peer:p.id}
 res:=&ethproto.Response{Req:req,Res:&raw,Meta:[][]common.Hash{txRoots,uncleRoots},Time:1,Done:make(chan error,1)}
 go func(){sink<-res}()
 return req,nil
}
func (p *rProtocolPeer) RequestReceipts(hashes []common.Hash,sink chan *ethproto.Response)(*ethproto.Request,error){
 blobs:=ethproto.ServiceGetReceiptsQuery(p.chain,hashes)
 decoded:=make([][]*types.Receipt,len(blobs))
 for i,blob:=range blobs{if err:=rlp.DecodeBytes(blob,&decoded[i]);err!=nil{return nil,err}}
 roots:=make([]common.Hash,len(decoded))
 for i,receipt:=range decoded{roots[i]=types.DeriveSha(types.Receipts(receipt),trie.NewStackTrie(nil))}
 raw:=ethproto.RawReceiptsPacket(blobs)
 req:=&ethproto.Request{Peer:p.id}
 res:=&ethproto.Response{Req:req,Res:&raw,Meta:roots,Time:1,Done:make(chan error,1)}
 go func(){sink<-res}()
 return req,nil
}

func rRemoteForkChain(t *testing.T,f *rFullFixture)(ethdb.Database,*core.BlockChain){
 t.Helper()
 key,err:=crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");if err!=nil{t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 db:=rawdb.NewMemoryDatabase()
 cfg:=paramsCopyForRFull()
 gspec:=&core.Genesis{Config:cfg,GasLimit:8_000_000,Alloc:core.GenesisAlloc{sender:{Balance:new(big.Int).Mul(big.NewInt(1000),big.NewInt(1e18))}}}
 genesis:=gspec.MustCommit(db)
 localGenesis:=f.chain.GetBlockByNumber(0)
 if localGenesis==nil||genesis.Hash()!=localGenesis.Hash(){db.Close();t.Fatalf("R_PEER_REMOTE_GENESIS_MISMATCH remote=%s local=%v",genesis.Hash(),localGenesis)}
 remote,err:=core.NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
 if err!=nil{db.Close();t.Fatal(err)}
 if i,err:=remote.InsertChain(f.fork);err!=nil{remote.Stop();db.Close();t.Fatalf("R_PEER_REMOTE_FORK_BUILD_FAIL index=%d err=%v",i,err)}
 return db,remote
}

type rPeerRaceResult struct{
 calls,oldResponses,postcheckStale,straddled int64
 maxFlipToReturnNs int64
}

func rPeerDownloaderTrial(t *testing.T,oldLen int)rPeerRaceResult{
 t.Helper()
 f:=rNewFullFixture(t,oldLen)
 remoteDB,remote:=rRemoteForkChain(t,f)
 dl:=downloader.New(0,f.backend.ChainDb(),new(event.TypeMux),f.chain,nil,func(string){},nil)
 peer:=&rProtocolPeer{id:"r-peer",chain:remote}
 if err:=dl.RegisterPeer(peer.id,ethproto.ETH66,peer);err!=nil{
  dl.Terminate();remote.Stop();remoteDB.Close();f.Close();t.Fatalf("R_PEER_REGISTER_FAIL: %v",err)
 }
 oldHash:=f.oldBlock.Hash();oldNumber:=f.oldBlock.NumberU64()
 var flipNs atomic.Int64
 watchStop:=make(chan struct{})
 go func(){
  for{
   select{case <-watchStop:return;default:}
   if f.chain.GetCanonicalHash(oldNumber)!=oldHash{flipNs.CompareAndSwap(0,time.Now().UnixNano());return}
   runtime.Gosched()
  }
 }()
 var result rPeerRaceResult
 start:=make(chan struct{});stop:=make(chan struct{})
 var wg sync.WaitGroup
 const workers=4
 wg.Add(workers)
 for i:=0;i<workers;i++{
  go func(){
   defer wg.Done();<-start
   for{
    select{case <-stop:return;default:}
    t0:=time.Now().UnixNano()
    receipt,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
    t1:=time.Now().UnixNano()
    if err!=nil{return}
    atomic.AddInt64(&result.calls,1)
    if receipt!=nil&&receipt["blockHash"]==oldHash{
     atomic.AddInt64(&result.oldResponses,1)
     if f.chain.GetCanonicalHash(oldNumber)!=oldHash{atomic.AddInt64(&result.postcheckStale,1)}
     flip:=flipNs.Load()
     if flip>0&&t0<=flip&&flip<=t1{
      atomic.AddInt64(&result.straddled,1)
      delta:=t1-flip
      for{
       cur:=atomic.LoadInt64(&result.maxFlipToReturnNs)
       if delta<=cur||atomic.CompareAndSwapInt64(&result.maxFlipToReturnNs,cur,delta){break}
      }
     }
    }
   }
  }()
 }
 close(start);time.Sleep(250*time.Microsecond)
 head,td:=peer.Head()
 syncErr:=dl.LegacySync(peer.id,head,td,nil,downloader.FullSync)
 deadline:=time.Now().Add(2*time.Millisecond);for time.Now().Before(deadline){runtime.Gosched()}
 close(stop);wg.Wait();close(watchStop)
 if syncErr!=nil{
  dl.Terminate();remote.Stop();remoteDB.Close();f.Close();t.Fatalf("R_PEER_LEGACY_SYNC_FAIL oldLen=%d err=%v",oldLen,syncErr)
 }
 if f.chain.CurrentBlock().Hash()!=remote.CurrentBlock().Hash(){
  dl.Terminate();remote.Stop();remoteDB.Close();f.Close();t.Fatalf("R_PEER_SYNC_HEAD_MISMATCH local=%s remote=%s",f.chain.CurrentBlock().Hash(),remote.CurrentBlock().Hash())
 }
 completed,err:=f.api.GetTransactionReceipt(context.Background(),f.oldTx.Hash())
 if err!=nil||completed!=nil{
  dl.Terminate();remote.Stop();remoteDB.Close();f.Close();t.Fatalf("R_PEER_COMPLETED_REORG_CONTROL_FAIL err=%v receipt=%v",err,completed)
 }
 dl.Terminate();remote.Stop();remoteDB.Close();f.Close()
 return result
}

func TestRPeerDownloaderReorgRace(t *testing.T){
 depths:=[]int{2,4,7,10}
 const trialsEach=8
 var total rPeerRaceResult
 for _,depth:=range depths{
  for trial:=0;trial<trialsEach;trial++{
   got:=rPeerDownloaderTrial(t,depth)
   total.calls+=got.calls;total.oldResponses+=got.oldResponses;total.postcheckStale+=got.postcheckStale;total.straddled+=got.straddled
   if got.maxFlipToReturnNs>total.maxFlipToReturnNs{total.maxFlipToReturnNs=got.maxFlipToReturnNs}
  }
 }
 if total.calls==0||total.oldResponses==0{t.Fatalf("R_PEER_RACE_NOT_EXERCISED calls=%d old=%d",total.calls,total.oldResponses)}
 t.Logf("R_PEER_DOWNLOADER_RACE_METRICS trials=%d calls=%d old_receipts=%d postcheck_stale=%d straddled=%d max_flip_to_return_ns=%d",
  len(depths)*trialsEach,total.calls,total.oldResponses,total.postcheckStale,total.straddled,total.maxFlipToReturnNs)
 if total.postcheckStale>0||total.straddled>0{
  t.Log("R_PEER_DOWNLOADER_TOCTOU_OBSERVED")
 }else{
  t.Log("R_PEER_DOWNLOADER_TOCTOU_NOT_OBSERVED_IN_BOUNDED_CAMPAIGN")
 }
 t.Log("R_PEER_DOWNLOADER_REORG_CONTROL_PASS")
}
