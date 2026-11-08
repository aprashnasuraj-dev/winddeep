// Isolated multi-component Electroneum safety test: genuine four-signer QBFT
// backends plus two REAL miner update loops and downloader sync cycles.
// A synthetic registered ETH66 downloader peer represents untrusted input.
// ETH66 status wire reachability is separately established in the companion
// isolated test; this test does NOT provide full transport-to-quorum proof.
package backend

import (
 "errors"
 "fmt"
 "math/big"
 "sync"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/eth/downloader"
 ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
 "github.com/electroneum/electroneum-sc/event"
 etnminer "github.com/electroneum/electroneum-sc/miner"
)

type independentMinerAdapter struct {
 chain *core.BlockChain
 txpool *core.TxPool
}
func(m *independentMinerAdapter) BlockChain() *core.BlockChain{return m.chain}
func(m *independentMinerAdapter) TxPool() *core.TxPool{return m.txpool}
func(m *independentMinerAdapter) StateAtBlock(block *types.Block,reexec uint64,base *state.StateDB,checkLive bool,preferDisk bool)(*state.StateDB,error) {
 return nil, errors.New("historical state query disabled in isolated liveness test")
}
type independentHeadOnlyQPeer struct {
 head *types.Header
 called chan struct{}
 mu sync.Mutex
 first bool
}
func(p *independentHeadOnlyQPeer) Head()(common.Hash,*big.Int){
 return p.head.Hash(),big.NewInt(1000000000)
}
func(p *independentHeadOnlyQPeer) RequestHeadersByHash(hash common.Hash, amount int,skip int,reverse bool,sink chan *ethproto.Response)(*ethproto.Request,error){
 req:=&ethproto.Request{Peer:"independent-untrusted-headonly"}
 var headers []*types.Header
 var hashes []common.Hash
 p.mu.Lock()
 if !p.first && hash==p.head.Hash() {
  p.first=true
  headers=[]*types.Header{p.head}
  hashes=[]common.Hash{p.head.Hash()}
 }
 p.mu.Unlock()
 res:=&ethproto.Response{Req:req,Res:(*ethproto.BlockHeadersPacket)(&headers),Meta:hashes,Time:1,Done:make(chan error,1)}
 go func(){sink<-res}()
 return req,nil
}
func(p *independentHeadOnlyQPeer) RequestHeadersByNumber(number uint64,amount int,skip int,reverse bool,sink chan *ethproto.Response)(*ethproto.Request,error){
 select{case p.called<-struct{}{}:default:}
 return &ethproto.Request{Peer:"independent-untrusted-headonly"},nil
}
func(p *independentHeadOnlyQPeer) RequestBodies(h []common.Hash,sink chan *ethproto.Response)(*ethproto.Request,error){
 return &ethproto.Request{Peer:"independent-untrusted-headonly"},nil
}
func(p *independentHeadOnlyQPeer) RequestReceipts(h []common.Hash,sink chan *ethproto.Response)(*ethproto.Request,error){
 return &ethproto.Request{Peer:"independent-untrusted-headonly"},nil
}
var _ downloader.Peer=(*independentHeadOnlyQPeer)(nil)

func independentWaitMinerState(m *etnminer.Miner,want bool)(bool){
 limit:=time.Now().Add(2*time.Second)
 for time.Now().Before(limit){
  if m.Mining()==want{return true}
  time.Sleep(10*time.Millisecond)
 }
 return m.Mining()==want
}
func TestIndependentHeadOnlyPausesTwoRealQBFTValidators(t *testing.T){
 _,nodes,cleanup:=independentMakeRealQBFTNetwork(t)
 defer cleanup()
 proposer:=independentPickProposer(t,nodes)
 // Only two non-proposers are adversarially targeted, so another live node
 // and the live proposer can otherwise reach consensus with 3 honest signers.
 type target struct{
  miner *etnminer.Miner
  txpool *core.TxPool
  mux *event.TypeMux
  dl *downloader.Downloader
  syncResult chan error
  addr common.Address
 }
 var targets []*target
 defer func(){
  for _,x:=range targets {
   x.dl.Cancel()
  }
  for _,x:=range targets {
   x.miner.Close()
   x.dl.Terminate()
   x.txpool.Stop()
  }
 }()
 for _,node:=range nodes{
  if node==proposer||len(targets)>=2{continue}
  pool:=core.NewTxPool(core.DefaultTxPoolConfig,node.chain.Config(),node.chain)
  adapter:=&independentMinerAdapter{chain:node.chain,txpool:pool}
  mux:=new(event.TypeMux)
  cfg:=etnminer.Config{Etherbase:node.addr,GasCeil:11500000}
  mining:=etnminer.New(adapter,&cfg,node.chain.Config(),mux,node.engine,nil)
  mining.Start(node.addr)
  if !independentWaitMinerState(mining,true) {
   t.Fatal("actual miner did not start on selected signed QBFT validator")
  }
  head:=&types.Header{
   ParentHash:node.chain.CurrentBlock().Hash(),
   Number:new(big.Int).Add(node.chain.CurrentBlock().Number(),big.NewInt(1)),
   GasLimit:11500000,
   Difficulty:big.NewInt(1),
   Time:uint64(time.Now().Unix()),
   Extra:[]byte("untrusted_head_only"),
  }
  peer:=&independentHeadOnlyQPeer{head:head,called:make(chan struct{},1)}
  dl:=downloader.New(0,rawdb.NewMemoryDatabase(),mux,node.chain,nil,nil,nil)
  id:=fmt.Sprintf("untrusted-headonly-%d",len(targets))
  if err:=dl.RegisterPeer(id,ethproto.ETH66,peer);err!=nil{
   t.Fatalf("register isolated ETH66 protocol peer: %v",err)
  }
  x:=&target{miner:mining,txpool:pool,mux:mux,dl:dl,syncResult:make(chan error,1),addr:node.addr}
  targets=append(targets,x)
  go func(){x.syncResult<-dl.LegacySync(id,head.Hash(),big.NewInt(1000000000),nil,downloader.FullSync)}()
  select {
  case <-peer.called:
  case err:=<-x.syncResult:t.Fatalf("attacker head-only downloader ended unexpectedly: %v",err)
  case <-time.After(7*time.Second):
   t.Fatal("attacker head-only peer did not reach ancestor lookup")
  }
  if !independentWaitMinerState(mining,false){
   t.Fatal("genuine miner remained active after unverified downloader progress")
  }
  node.engine.coreMu.RLock()
  running:=node.engine.coreStarted
  node.engine.coreMu.RUnlock()
  if running{
   t.Fatal("genuine QBFT consensus core remained active after head-only downloader progress")
  }
  if node.chain.CurrentBlock().NumberU64()!=0{
   t.Fatalf("unexpected canonical import before ancestor verification: height=%d",node.chain.CurrentBlock().NumberU64())
  }
  t.Logf("INTEGRATED_QBFT_VAL_STOPPED address=%s real_miner=false core_started=false ancestry_verified=false",node.addr)
 }
 if len(targets)!=2{t.Fatal("expected exactly two isolated victim miners")}
 // The two live backends remain signed validators. Proposing a genuine
 // candidate must not commit without a third distinct validator.
 candidate:=makeBlockWithoutSeal(proposer.chain,proposer.engine,proposer.chain.Genesis(),true)
 result:=make(chan *types.Block,2)
 stop:=make(chan struct{})
 if err:=proposer.engine.Seal(proposer.chain,candidate,result,stop);err!=nil{
  t.Fatalf("signed QBFT proposal cannot start: %v",err)
 }
 timer:=time.NewTimer(6*time.Second)
 defer timer.Stop()
 select {
 case b:=<-result:
  if b!=nil{t.Fatalf("only 2 live QBFT validators finalized a signed block: %s",b.Hash())}
 case <-timer.C:
 }
 close(stop)
 for _,x:=range targets {
  if x.miner.Mining(){t.Fatal("attacker-held miner resumed before downloader timeout/cancel")}
 }
 t.Log("INTEGRATED_QBFT_QUORUM_UNAVAILABLE validator_total=4 validators_stopped_by_actual_downloader=2 live=2 signed_finality_6s=false synthetic_peer_registration=true")
}
