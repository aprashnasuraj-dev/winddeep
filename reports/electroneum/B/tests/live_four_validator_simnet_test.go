package backend

import (
 "bytes"
 "fmt"
 "sync/atomic"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/p2p"
)

type liveBNetNode struct { b *Backend; chain *core.BlockChain; addr common.Address }
type liveBNet struct {
 nodes map[common.Address]*liveBNetNode
 byzantine common.Address
 attack bool
 retagged atomic.Int64
 forwarded atomic.Int64
}
type liveBNetBroadcaster struct{net *liveBNet; source common.Address}
type liveBNetPeer struct{net *liveBNet; source,destination common.Address}
func (n *liveBNet) deliver(source,dest common.Address,code uint64,payload []byte)error{
 node:=n.nodes[dest]
 handled,err:=node.b.HandleMsg(source,p2p.Msg{Code:code,Size:uint32(len(payload)),Payload:bytes.NewReader(payload)})
 if !handled||err!=nil{return fmt.Errorf("deliver %s->%s code=%d handled=%v err=%v",source,dest,code,handled,err)}
 n.forwarded.Add(1)
 return nil
}
func (p *liveBNetPeer) Send(code uint64,data interface{})error{return nil}
func (p *liveBNetPeer) SendConsensus(code uint64,data interface{})error{return nil}
func (p *liveBNetPeer) SendQBFTConsensus(code uint64,payload []byte)error{
 n:=p.net
 if p.source==n.byzantine{return nil} // the single faulty validator withholds its own votes
 if n.attack && code==qbfttypes.PrepareCode && p.destination==n.byzantine {
  // The Byzantine validator has now received the authentic signed PREPARE
  // from an honest peer, and relays the exact payload under COMMIT code
  // before intentionally delayed honest-to-honest packets are delivered.
  for dest,node:=range n.nodes {
   if dest==n.byzantine||dest==p.source {continue}
   _=node
   n.retagged.Add(1)
   go func(to common.Address,bytes []byte){_ = n.deliver(n.byzantine,to,qbfttypes.CommitCode,bytes)}(dest,append([]byte(nil),payload...))
  }
 }
 if n.attack && code==qbfttypes.PrepareCode && p.destination!=n.byzantine {
  time.Sleep(90*time.Millisecond)
 }
 return n.deliver(p.source,p.destination,code,payload)
}
func (b *liveBNetBroadcaster) Enqueue(id string,block *types.Block){
 node:=b.net.nodes[b.source]
 go func(){
  _,err:=node.chain.InsertChain(types.Blocks{block})
  if err==nil { _=node.b.NewChainHead() }
 }()
}
func (b *liveBNetBroadcaster) FindPeers(targets map[common.Address]bool)map[common.Address]consensus.Peer{
 out:=make(map[common.Address]consensus.Peer)
 for dst:=range targets {
  if _,ok:=b.net.nodes[dst];ok {
   out[dst]=&liveBNetPeer{net:b.net,source:b.source,destination:dst}
  }
 }
 return out
}

// TestLiveBOneByzantineFourValidatorNetworkLiveness compares 4 genuine QBFT
// backend/core instances, the 3 honest validator senders and 1 Byzantine
// sender, on identical genesis under honest vs wrong-code first scheduling.
// This is an in-process deterministic transport emulator, NOT a real-network
// experiment. The attacker only sees the authentic signed PREPARE delivered
// to its validator peer; it has no other validator's private keys.
func TestLiveBOneByzantineFourValidatorNetworkLiveness(t *testing.T){
 for _,seed:=range []int{1,2} {
  t.Run(fmt.Sprintf("network_%d",seed),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(4)
   run:=func(attack bool)(progress int,byzRetags int64,states string,err error){
    net:=&liveBNet{nodes:make(map[common.Address]*liveBNetNode),attack:attack}
    nodes:=make([]*liveBNetNode,4)
    for i,key:=range keys {
     db:=rawdb.NewMemoryDatabase()
     cfg:=*istanbul.DefaultConfig
     cfg.ProposerPolicy=istanbul.NewRoundRobinProposerPolicy()
     b:=New(cfg,key,db)
     genesis.MustCommit(db)
     chain,e:=core.NewBlockChain(db,nil,genesis.Config,b,vm.Config{},nil,nil)
     if e!=nil{return 0,0,"",e}
     if e=b.Start(chain,chain.CurrentBlock,rawdb.HasBadBlock);e!=nil{return 0,0,"",e}
     node:=&liveBNetNode{b:b,chain:chain,addr:crypto.PubkeyToAddress(key.PublicKey)}
     nodes[i]=node
     net.nodes[node.addr]=node
    }
    defer func(){
     for _,node:=range nodes {
      if node!=nil { _=node.b.Stop();node.chain.Stop() }
     }
    }()
    snap,e:=nodes[0].b.snapshot(nodes[0].chain,0,common.Hash{},nil)
    if e!=nil{return 0,0,"",e}
    proposerAddr:=snap.ValSet.GetProposer().Address()
    var proposer *liveBNetNode
    for _,n:=range nodes {if n.addr==proposerAddr {proposer=n}}
    if proposer==nil{return 0,0,"",fmt.Errorf("proposer not found")}
    for i:=len(nodes)-1;i>=0;i-- {
     if nodes[i].addr!=proposerAddr {net.byzantine=nodes[i].addr;break}
    }
    for _,node:=range nodes {
     node.b.SetBroadcaster(&liveBNetBroadcaster{net:net,source:node.addr})
    }
    block:=makeBlockWithoutSeal(proposer.chain,proposer.b,proposer.chain.Genesis(),true)
    out:=make(chan *types.Block,1)
    stop:=make(chan struct{})
    defer close(stop)
    if e=proposer.b.Seal(proposer.chain,block,out,stop);e!=nil{return 0,0,"",e}
    select {
    case b:=<-out:
     if b!=nil {
      if _,e=proposer.chain.InsertChain(types.Blocks{b});e!=nil{return 0,0,"",e}
      _=proposer.b.NewChainHead()
     }
    case <-time.After(4*time.Second):
    }
    // Give non-proposer nodes a bounded interval for committed-block enqueue
    // then sample *every* honest node's true canonical height and QBFT state.
    time.Sleep(250*time.Millisecond)
    for _,n:=range nodes {
     if n.addr==net.byzantine {continue}
     if n.chain.CurrentBlock().NumberU64()>0 {progress++}
     info:=n.b.core.RoundState()
     if info!=nil {
      states+=fmt.Sprintf(" node=%s height=%d round=%d state=%s prepare=%d commit=%d;",n.addr,n.chain.CurrentBlock().NumberU64(),info.Round,info.State,info.Prepares,info.Commits)
     }
    }
    return progress,net.retagged.Load(),states,nil
   }
   honestProgress,hRetags,hStates,e:=run(false);if e!=nil{t.Fatal(e)}
   badProgress,bRetags,bStates,e:=run(true);if e!=nil{t.Fatal(e)}
   t.Logf("B_FOUR_VALIDATOR_NETWORK_ORACLE seed=%d honest_progress=%d attacked_progress=%d retags=%d honest_state=%s attacked_state=%s",
    seed,honestProgress,badProgress,bRetags,hStates,bStates)
   if honestProgress!=3 {
    t.Fatalf("B_FOUR_VALIDATOR_BASELINE_INCOMPLETE: expected 3 honest finalized nodes; got %d",honestProgress)
   }
   if hRetags!=0 {t.Fatal("clean network unexpectedly retagged")}
   if bRetags==0 {t.Fatal("attacker never intercepted honest PREPARE")}
   if badProgress<3 {
    t.Logf("B_FOUR_VALIDATOR_LIVENESS_FAILURE seed=%d honest_progress=%d attacked_progress=%d retags=%d",seed,honestProgress,badProgress,bRetags)
   }else{
    t.Logf("B_FOUR_VALIDATOR_GUARD_HELD seed=%d honest_progress=%d attacked_progress=%d",seed,honestProgress,badProgress)
   }
  })
 }
}
