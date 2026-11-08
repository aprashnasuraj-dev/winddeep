// Isolated ETN-SC four-validator production-component experiment.
// Genuine eth/66 status handshakes, request/response codecs, registered eth
// protocol handler peers and two real miner/downloader event buses are used.
// Four independent QBFT signer cores are linked with in-memory consensus
// messages. No TCP/ENR discovery, public RPC, live validator traffic or funds.
// This is research evidence, not an automatically reportable P2.
package eth

import (
 "bytes"
 "errors"
 "fmt"
 "math/big"
 "sync"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 qbftbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
 istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 "github.com/electroneum/electroneum-sc/consensus/misc"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/forkid"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/eth/downloader"
 ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
 "github.com/electroneum/electroneum-sc/event"
 etnminer "github.com/electroneum/electroneum-sc/miner"
 "github.com/electroneum/electroneum-sc/p2p"
 "github.com/electroneum/electroneum-sc/p2p/enode"
)

type isolatedWireQBFTNode struct{
 chain *core.BlockChain
 engine *qbftbackend.Backend
 addr common.Address
 pool *core.TxPool
 miner *etnminer.Miner
 handler *handler
}
type isolatedWireQBFTNet struct{
 nodes map[common.Address]*isolatedWireQBFTNode
 mu sync.RWMutex
}
type isolatedWireQBFTRouter struct{net *isolatedWireQBFTNet; src common.Address; node *isolatedWireQBFTNode}
type isolatedWireQBFTRemote struct{net *isolatedWireQBFTNet; from,to common.Address}
var _ consensus.Broadcaster=(*isolatedWireQBFTRouter)(nil)
var _ consensus.Peer=(*isolatedWireQBFTRemote)(nil)

func(p *isolatedWireQBFTRemote)Send(code uint64,data interface{})error{return nil}
func(p *isolatedWireQBFTRemote)SendConsensus(code uint64,data interface{})error{return nil}
func(p *isolatedWireQBFTRemote)SendQBFTConsensus(code uint64,payload []byte)error{
 p.net.mu.RLock();dst:=p.net.nodes[p.to];p.net.mu.RUnlock()
 if dst==nil{return nil}
 msg:=p2p.Msg{Code:code,Size:uint32(len(payload)),Payload:bytes.NewReader(append([]byte{},payload...))}
 _,err:=dst.engine.HandleMsg(p.from,msg)
 // Remote engines are allowed to be stopped: these send errors should not
 // turn a failed quorum (expected in this experiment) into a fake finding.
 return err
}
func(b *isolatedWireQBFTRouter)FindPeers(targets map[common.Address]bool)map[common.Address]consensus.Peer{
 result:=map[common.Address]consensus.Peer{}
 b.net.mu.RLock();defer b.net.mu.RUnlock()
 for addr:=range targets{
  if b.net.nodes[addr]!=nil{
   result[addr]=&isolatedWireQBFTRemote{net:b.net,from:b.src,to:addr}
  }
 }
 return result
}
func(b *isolatedWireQBFTRouter)Enqueue(id string,blk *types.Block){
 go func(){
  if _,err:=b.node.chain.InsertChain([]*types.Block{blk});err==nil{
   _=b.node.engine.NewChainHead()
  }
 }()
}
type isolatedWireMinerBackend struct{chain *core.BlockChain;pool *core.TxPool}
func(m *isolatedWireMinerBackend)BlockChain()*core.BlockChain{return m.chain}
func(m *isolatedWireMinerBackend)TxPool()*core.TxPool{return m.pool}
func(m *isolatedWireMinerBackend)StateAtBlock(block *types.Block,reexec uint64,base *state.StateDB,checkLive bool,preferDisk bool)(*state.StateDB,error){
 return nil,errors.New("archival state unsupported in short-lived isolated network")
}
type isolatedWireAttacker struct{
 localRW,attackerRW *p2p.MsgPipeRW
 localPeer,attackerPeer *ethproto.Peer
 serveErrors chan error
 ancestryRequested chan struct{}
 syncResult chan error
}
func isolatedWaitMiner(m *etnminer.Miner,want bool)bool{
 deadline:=time.Now().Add(2*time.Second)
 for time.Now().Before(deadline){
  if m.Mining()==want{return true}
  time.Sleep(10*time.Millisecond)
 }
 return m.Mining()==want
}
func isolatedWireQBFTCandidate(node *isolatedWireQBFTNode)(*types.Block,error){
 parent:=node.chain.CurrentBlock()
 header:=&types.Header{
  ParentHash:parent.Hash(),
  Number:new(big.Int).Add(parent.Number(),big.NewInt(1)),
  GasLimit:core.CalcGasLimit(parent.GasLimit(),parent.GasLimit()),
  GasUsed:0,
  Time:parent.Time()+istanbul.DefaultConfig.BlockPeriod,
  Difficulty:istanbulcommon.DefaultDifficulty,
  Coinbase:node.addr,
 }
 if node.chain.Config().IsLondon(header.Number){
  header.BaseFee=misc.CalcBaseFee(node.chain.Config(),parent.Header())
 }
 if err:=node.engine.Prepare(node.chain,header);err!=nil{return nil,err}
 st,err:=node.chain.StateAt(parent.Root());if err!=nil{return nil,err}
 return node.engine.FinalizeAndAssemble(node.chain,header,st,nil,nil,nil)
}
func isolatedWireConnectHeadOnly(t *testing.T,n *isolatedWireQBFTNode,idx byte)(*isolatedWireAttacker,error){
 t.Helper()
 rw,attackerRW:=p2p.MsgPipe()
 caps:=[]p2p.Cap{{Name:"etn",Version:ethproto.ETH66}}
 vPeer:=ethproto.NewPeer(ethproto.ETH66,p2p.NewPeer(enode.ID{idx},"qbft-victim",caps),rw,n.pool)
 aPeer:=ethproto.NewPeer(ethproto.ETH66,p2p.NewPeer(enode.ID{idx+16},"untrusted-peer",caps),attackerRW,n.pool)
 c:=&isolatedWireAttacker{localRW:rw,attackerRW:attackerRW,localPeer:vPeer,attackerPeer:aPeer,serveErrors:make(chan error,2),ancestryRequested:make(chan struct{},1),syncResult:make(chan error,1)}
 parent:=n.chain.CurrentBlock()
 head:=&types.Header{
  ParentHash:parent.Hash(), Number:new(big.Int).Add(parent.Number(),big.NewInt(1)),
  GasLimit:11500000,Difficulty:big.NewInt(1),
  Time:uint64(time.Now().Unix()),Extra:[]byte("controlled_etn66_head"),
 }
 go func(){
  genesis:=n.chain.Genesis().Hash()
  fork:=forkid.NewID(n.chain.Config(),genesis,parent.NumberU64())
  filter:=forkid.NewFilter(n.chain)
  if err:=aPeer.Handshake(1,big.NewInt(1000000000),head.Hash(),genesis,fork,filter);err!=nil{
   c.serveErrors<-fmt.Errorf("attacker ETH66 status handshake: %w",err)
   return
  }
  first:=true
  for{
   msg,err:=attackerRW.ReadMsg()
   if err!=nil{return}
   if msg.Code!=ethproto.GetBlockHeadersMsg{
    _=msg.Discard()
    continue
   }
   var q ethproto.GetBlockHeadersPacket66
   if err:=msg.Decode(&q);err!=nil{
    c.serveErrors<-fmt.Errorf("attacker header query decode: %w",err)
    return
   }
   if q.GetBlockHeadersPacket==nil{
    c.serveErrors<-fmt.Errorf("nil ETH66 header query")
    return
   }
   if first && q.Origin.Hash==head.Hash(){
    first=false
    reply:=&ethproto.BlockHeadersPacket66{
     RequestId:q.RequestId,
     BlockHeadersPacket:ethproto.BlockHeadersPacket{head},
    }
    if err:=p2p.Send(attackerRW,ethproto.BlockHeadersMsg,reply);err!=nil{
     c.serveErrors<-fmt.Errorf("attacker head header reply: %w",err)
     return
    }
   }else{
    // Hold every ancestry request open; do not provide canonical proof.
    select{case c.ancestryRequested<-struct{}{}:default:}
   }
  }
 }()
 go func(){c.serveErrors<-n.handler.runEthPeer(vPeer,func(p *ethproto.Peer)error{
  return ethproto.Handle((*ethHandler)(n.handler),p)
 })}()
 deadline:=time.Now().Add(7*time.Second)
 for n.handler.peers.len()<1{
  if time.Now().After(deadline){return c,fmt.Errorf("real ETH66 handshake did not register untrusted peer")}
  select{case err:=<-c.serveErrors:return c,fmt.Errorf("ETH66 registration failed: %w",err)
  default:}
  time.Sleep(10*time.Millisecond)
 }
 peer:=n.handler.peers.peerWithHighestTD()
 if peer==nil{return c,fmt.Errorf("no successfully authenticated ETH66 source")}
 op:=peerToSyncOp(downloader.FullSync,peer)
 if op.td.Cmp(big.NewInt(0))<=0{return c,fmt.Errorf("untrusted peer did not advertise higher TD")}
 go func(){c.syncResult<-n.handler.doSync(op)}()
 select{
 case <-c.ancestryRequested:
 case err:=<-c.syncResult:return c,fmt.Errorf("head-only peer exited before ancestry: %w",err)
 case err:=<-c.serveErrors:return c,fmt.Errorf("attacker test wire service failed: %w",err)
 case <-time.After(10*time.Second):return c,fmt.Errorf("no ETH66 ancestry lookup observed")
 }
 if !isolatedWaitMiner(n.miner,false){return c,fmt.Errorf("actual QBFT miner still running")}
 if n.chain.CurrentBlock().NumberU64()!=0{return c,fmt.Errorf("attacker imported unauthorized canonical block")}
 t.Logf("QBFT_ETH66_WIRE_VALIDATOR_STOPPED address=%s real_eth66_handshake=true ancestor_verified=false miner_running=false",n.addr)
 return c,nil
}
func independentRunEth66WireQBFTThreshold(t *testing.T, maxVictims int){
 genesis,keys:=testutils.GenesisAndKeys(4)
 net:=&isolatedWireQBFTNet{nodes:map[common.Address]*isolatedWireQBFTNode{}}
 nodes:=make([]*isolatedWireQBFTNode,0,4)
 for _,key:=range keys{
  db:=rawdb.NewMemoryDatabase()
  cfg:=*istanbul.DefaultConfig
  cfg.ProposerPolicy=istanbul.NewRoundRobinProposerPolicy()
  cfg.RequestTimeoutSeconds=3
  cfg.MaxRequestTimeoutSeconds=9
  eng:=qbftbackend.New(cfg,key,db)
  genesis.MustCommit(db)
  chain,err:=core.NewBlockChain(db,nil,genesis.Config,eng,vm.Config{},nil,nil)
  if err!=nil{t.Fatalf("four validator blockchain setup: %v",err)}
  addr:=crypto.PubkeyToAddress(key.PublicKey)
  n:=&isolatedWireQBFTNode{chain:chain,engine:eng,addr:addr}
  net.nodes[addr]=n
  nodes=append(nodes,n)
 }
 var attacks []*isolatedWireAttacker
 defer func(){
  for _,a:=range attacks{_ =a.localRW.Close(); _=a.attackerRW.Close()}
  for _,n:=range nodes{
   if n.miner!=nil{n.miner.Close()}
   if n.handler!=nil{n.handler.Stop()}
   if n.pool!=nil{n.pool.Stop()}
   _=n.engine.Stop()
   n.chain.Stop()
  }
  for _,a:=range attacks{a.localPeer.Close();a.attackerPeer.Close()}
 }()
 for _,node:=range nodes{
  node.engine.SetBroadcaster(&isolatedWireQBFTRouter{net:net,src:node.addr,node:node})
  if err:=node.engine.Start(node.chain,node.chain.CurrentBlock,rawdb.HasBadBlock);err!=nil{
   t.Fatalf("QBFT core start: %v",err)
  }
 }
 // Each validator has its own authentic signing key, local chain and active
 // signed QBFT backend. Choose two non-proposers as ETH66 peer victims.
 valset:=nodes[0].engine.Validators(nodes[0].chain.Genesis())
 if valset==nil||valset.Size()!=4{t.Fatalf("invalid four-validator genesis snapshot")}
 proposerAddr:=valset.GetProposer().Address()
 var proposer *isolatedWireQBFTNode
 for _,node:=range nodes{if node.addr==proposerAddr{proposer=node}}
 if proposer==nil{t.Fatal("QBFT proposer not in genesis validator set")}
 targeted:=0
 for _,n:=range nodes{
  if n==proposer||targeted>=maxVictims{continue}
  pool:=core.NewTxPool(core.DefaultTxPoolConfig,n.chain.Config(),n.chain)
  mux:=new(event.TypeMux)
  h,err:=newHandler(&handlerConfig{
   Database:rawdb.NewMemoryDatabase(),Chain:n.chain,TxPool:pool,
   Merger:consensus.NewMerger(rawdb.NewMemoryDatabase()),
   Network:1,Sync:downloader.FullSync,EventMux:mux,Engine:n.engine,
  })
  if err!=nil{t.Fatalf("real etn/66 protocol handler init: %v",err)}
  n.pool=pool
  n.handler=h
  // newHandler calls SetBroadcaster(h): restore the actual isolated
  // validator-to-validator consensus mesh for this experiment.
  n.engine.SetBroadcaster(&isolatedWireQBFTRouter{net:net,src:n.addr,node:n})
  h.Start(1000)
  cfg:=etnminer.Config{Etherbase:n.addr,GasCeil:11500000}
  n.miner=etnminer.New(&isolatedWireMinerBackend{chain:n.chain,pool:pool},&cfg,n.chain.Config(),mux,n.engine,nil)
  n.miner.Start(n.addr)
  if !isolatedWaitMiner(n.miner,true){t.Fatal("actual validator miner did not start")}
  attack,err:=isolatedWireConnectHeadOnly(t,n,byte(targeted+1))
  if attack!=nil{attacks=append(attacks,attack)}
  if err!=nil{t.Fatal(err)}
  targeted++
 }
 if targeted!=maxVictims{t.Fatalf("real ETH66 victim count %d, want %d",targeted,maxVictims)}
 candidate,err:=isolatedWireQBFTCandidate(proposer)
 if err!=nil{t.Fatalf("remaining honest proposer cannot prepare: %v",err)}
 results:=make(chan *types.Block,2)
 stop:=make(chan struct{})
 if err:=proposer.engine.Seal(proposer.chain,candidate,results,stop);err!=nil{
  t.Fatalf("signer proposal did not start: %v",err)
 }
 var committed *types.Block
 select{
 case committed=<-results:
 case <-time.After(30*time.Second):
 }
 if maxVictims==1 {
  if committed==nil{
   close(stop)
   t.Fatal("one untrusted ETH66 peer unexpectedly prevented a 3-of-4 signed QBFT quorum")
  }
  if _,err:=proposer.chain.InsertChain([]*types.Block{committed});err!=nil{
   close(stop)
   t.Fatalf("3-of-4 real QBFT block rejected by canonical InsertChain: %v",err)
  }
  if err:=proposer.engine.VerifyHeader(proposer.chain,committed.Header(),true);err!=nil{
   close(stop)
   t.Fatalf("3-of-4 QBFT signed committed-seal verification: %v",err)
  }
  t.Logf("QBFT_ETH66_WIRE_ONE_PEER_GUARD signers=4 untrusted_eth66_sessions=1 stopped_real_miners=1 remaining_signers=3 signed_finality=true canonical_height=%d committed_hash=%s",committed.NumberU64(),committed.Hash())
 } else {
  if committed!=nil{
   close(stop)
   t.Fatalf("2-of-4 Byzantine quorum accepted a block: %s",committed.Hash())
  }
  t.Log("QBFT_ETH66_WIRE_TWO_VALIDATOR_OUTAGE signers=4 untrusted_eth66_sessions=2 real_status_handshakes=2 stopped_real_miners=2 remaining_signers=2 signed_finality_30s=false canonical_imports=0")
 }
 close(stop)
 for _,n:=range nodes{
  if n.miner!=nil&&n.miner.Mining(){t.Fatal("attacker-stopped miner resumed before parent sync verified")}
 }
}
func TestIndependentTwoEth66WirePeersHaltFourQBFTSignerQuorum(t *testing.T) {
 t.Run("one_untrusted_peer_three_live_signed_quorum",func(t *testing.T){
  independentRunEth66WireQBFTThreshold(t,1)
 })
 t.Run("two_untrusted_peers_two_live_no_quorum",func(t *testing.T){
  independentRunEth66WireQBFTThreshold(t,2)
 })
}
