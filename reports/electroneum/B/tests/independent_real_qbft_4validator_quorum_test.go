// Research fixture: real signed Electroneum QBFT, four isolated validator
// backends with independent blockchains and an in-memory consensus transport.
// No public network, production keys, or changes to target source.
// The quorum-loss control here does NOT by itself demonstrate a remote DoS.
package backend

import (
 "bytes"
 "fmt"
 "math/big"
 "sync"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/p2p"
)

type independentQuorumNode struct {
 chain *core.BlockChain
 engine *Backend
 addr common.Address
 active bool
}
type independentQuorumNet struct {
 mu sync.Mutex
 nodes map[common.Address]*independentQuorumNode
 errors chan error
}
type independentQuorumBroadcaster struct {
 net *independentQuorumNet
 from common.Address
 node *independentQuorumNode
}
type independentQuorumPeer struct {
 net *independentQuorumNet
 from common.Address
 to common.Address
}
var _ consensus.Broadcaster = (*independentQuorumBroadcaster)(nil)
var _ consensus.Peer = (*independentQuorumPeer)(nil)

func (p *independentQuorumPeer) Send(code uint64, data interface{}) error { return nil }
func (p *independentQuorumPeer) SendConsensus(code uint64, data interface{}) error { return nil }
func (p *independentQuorumPeer) SendQBFTConsensus(code uint64, payload []byte) error {
 p.net.mu.Lock()
 dst:=p.net.nodes[p.to]
 active:=dst!=nil && dst.active
 p.net.mu.Unlock()
 if !active { return nil }
 cpy:=append([]byte(nil),payload...)
 msg:=p2p.Msg{Code:code, Size:uint32(len(cpy)), Payload:bytes.NewReader(cpy)}
 _,err:=dst.engine.HandleMsg(p.from,msg)
 if err!=nil {
  select { case p.net.errors<-fmt.Errorf("delivery %s -> %s code %d: %w",p.from.Hex(),p.to.Hex(),code,err): default: }
 }
 return err
}
func (b *independentQuorumBroadcaster) FindPeers(targets map[common.Address]bool) map[common.Address]consensus.Peer {
 out:=make(map[common.Address]consensus.Peer)
 b.net.mu.Lock()
 defer b.net.mu.Unlock()
 for addr:=range targets {
  if node:=b.net.nodes[addr];node!=nil&&node.active {
   out[addr]=&independentQuorumPeer{net:b.net,from:b.from,to:addr}
  }
 }
 return out
}
func (b *independentQuorumBroadcaster) Enqueue(id string, block *types.Block) {
 go func() {
  b.net.mu.Lock()
  active:=b.node.active
  b.net.mu.Unlock()
  if !active { return }
  if _,err:=b.node.chain.InsertChain([]*types.Block{block});err!=nil {
   select {case b.net.errors<-fmt.Errorf("canonical import by %s: %w",b.from.Hex(),err):default:}
   return
  }
  if err:=b.node.engine.NewChainHead();err!=nil {
   select {case b.net.errors<-fmt.Errorf("new chain head %s: %w",b.from.Hex(),err):default:}
  }
 }()
}
func independentMakeRealQBFTNetwork(t *testing.T) (*independentQuorumNet, []*independentQuorumNode,func()) {
 t.Helper()
 genesis,keys:=testutils.GenesisAndKeys(4)
 net:=&independentQuorumNet{nodes:make(map[common.Address]*independentQuorumNode),errors:make(chan error,100)}
 nodes:=make([]*independentQuorumNode,0,4)
 for _,key:=range keys {
  db:=rawdb.NewMemoryDatabase()
  cfg:=*istanbul.DefaultConfig
  cfg.ProposerPolicy=istanbul.NewRoundRobinProposerPolicy()
  cfg.RequestTimeoutSeconds=3
  cfg.MaxRequestTimeoutSeconds=9
  engine:=New(cfg,key,db)
  genesis.MustCommit(db)
  chain,err:=core.NewBlockChain(db,nil,genesis.Config,engine,vm.Config{},nil,nil)
  if err!=nil {t.Fatalf("create QBFT chain: %v",err)}
  addr:=crypto.PubkeyToAddress(key.PublicKey)
  node:=&independentQuorumNode{chain:chain,engine:engine,addr:addr,active:true}
  nodes=append(nodes,node)
  net.nodes[addr]=node
 }
 for _,node:=range nodes {
  node.engine.SetBroadcaster(&independentQuorumBroadcaster{net:net,from:node.addr,node:node})
 }
 for _,node:=range nodes {
  if err:=node.engine.Start(node.chain,node.chain.CurrentBlock,rawdb.HasBadBlock);err!=nil{
   t.Fatalf("start QBFT engine %s: %v",node.addr.Hex(),err)
  }
 }
 cleanup:=func(){
  for _,node:=range nodes {
   net.mu.Lock()
   wasActive:=node.active
   node.active=false
   net.mu.Unlock()
   if wasActive { _=node.engine.Stop() }
  }
  for _,node:=range nodes {node.chain.Stop()}
 }
 return net,nodes,cleanup
}
func independentPickProposer(t *testing.T,nodes []*independentQuorumNode) *independentQuorumNode {
 t.Helper()
 snap,err:=nodes[0].engine.snapshot(nodes[0].chain,0,nodes[0].chain.Genesis().Hash(),nil)
 if err!=nil {t.Fatalf("genesis validator snapshot: %v",err)}
 if got:=snap.ValSet.Size();got!=4 {t.Fatalf("expected 4 signed validators, got %d",got)}
 want:=snap.ValSet.GetProposer().Address()
 for _,node:=range nodes {if node.addr==want {return node}}
 t.Fatalf("proposer not in 4-validator set: %s",want.Hex())
 return nil
}
func independentStopValidator(t *testing.T,net *independentQuorumNet,n *independentQuorumNode){
 t.Helper()
 net.mu.Lock()
 n.active=false
 net.mu.Unlock()
 if err:=n.engine.Stop();err!=nil {t.Fatalf("pause QBFT node %s: %v",n.addr.Hex(),err)}
}
func TestIndependentRealQBFTQuorumFourValidators(t *testing.T) {
 for _,tc:=range []struct{name string;offline int;shouldFinalize bool}{
  {"honest_four_signers",0,true},
  {"one_stopped_three_signers",1,true},
  {"two_stopped_two_signers",2,false},
 }{
  t.Run(tc.name,func(t *testing.T){
   net,nodes,cleanup:=independentMakeRealQBFTNetwork(t)
   defer cleanup()
   proposer:=independentPickProposer(t,nodes)
   stopped:=0
   for _,node:=range nodes {
    if node!=proposer&&stopped<tc.offline{
     independentStopValidator(t,net,node)
     stopped++
    }
   }
   if stopped!=tc.offline {t.Fatalf("stopped=%d wanted=%d",stopped,tc.offline)}
   block:=makeBlockWithoutSeal(proposer.chain,proposer.engine,proposer.chain.Genesis(),true)
   sealed:=make(chan *types.Block,2)
   stop:=make(chan struct{})
   if err:=proposer.engine.Seal(proposer.chain,block,sealed,stop);err!=nil {
    t.Fatalf("real QBFT seal failed to start: %v",err)
   }
   var committed *types.Block
   timer:=time.NewTimer(7*time.Second)
   defer timer.Stop()
   select{
   case committed=<-sealed:
   case <-timer.C:
   }
   if tc.shouldFinalize && committed==nil {
    select{case err:=<-net.errors:t.Fatalf("quorum did not finalize: network error: %v",err)
    default:t.Fatal("no committed block with >=3 genuine signer processes") }
   }
   if !tc.shouldFinalize && committed!=nil {
    t.Fatalf("2-of-4 improperly finalized candidate block %s",committed.Hash())
   }
   if committed==nil {
    close(stop)
    t.Logf("QBFT_SIGNED_QUORUM_NO_FINALITY live=%d offline=%d time_bound_s=7 expected=true",4-tc.offline,tc.offline)
    return
   }
   if _,err:=proposer.chain.InsertChain([]*types.Block{committed});err!=nil {
    t.Fatalf("committed sealed QBFT block rejected by canonical InsertChain: %v",err)
   }
   _=proposer.engine.NewChainHead()
   if err:=proposer.engine.VerifyHeader(proposer.chain,committed.Header(),true);err!=nil{
    t.Fatalf("genuine QBFT committed-seal verification rejected block: %v",err)
   }
   deadline:=time.Now().Add(3*time.Second)
   for time.Now().Before(deadline) {
    all:=true
    for _,node:=range nodes {
     net.mu.Lock();active:=node.active;net.mu.Unlock()
     if active&&node.chain.CurrentBlock().Hash()!=committed.Hash(){all=false}
    }
    if all{break}
    time.Sleep(25*time.Millisecond)
   }
   for _,node:=range nodes {
    net.mu.Lock();active:=node.active;net.mu.Unlock()
    if active&&node.chain.CurrentBlock().Hash()!=committed.Hash(){
     t.Fatalf("genuine signed QBFT finality not imported by live validator %s: got=%s expected=%s",node.addr.Hex(),node.chain.CurrentBlock().Hash(),committed.Hash())
    }
   }
   t.Logf("QBFT_SIGNED_QUORUM_FINALIZED validators=4 live=%d offline=%d block_number=%d hash=%s real_seals=true",4-tc.offline,tc.offline,committed.NumberU64(),committed.Hash())
  })
 }
 _=big.NewInt(0) // keep fixture's imports explicit across pinned source versions
}
