package backend

import (
 "bytes"
 "crypto/ecdsa"
 "fmt"
 "math/big"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
 "github.com/electroneum/electroneum-sc/consensus/misc"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/p2p"
 "github.com/electroneum/electroneum-sc/rlp"
)

// TestLiveBCrossCodeQuorumImpact compares state transitions from the SAME
// 3 authentic validator PREPARE votes (including local own vote), with and
// without a Byzantine validator relaying one vote as the wrong message code
// first. Runs real QBFT backend+core, but no full distributed network.
func TestLiveBCrossCodeQuorumImpact(t *testing.T) {
 for _,seed:=range []byte{11,19,29} {
  t.Run(fmt.Sprintf("state_%d",seed),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(4)
   cfg:=*istanbul.DefaultConfig
   run:=func(poison bool)(*istanbul.RoundStateInfo,error) {
    db:=rawdb.NewMemoryDatabase()
    backend:=New(cfg,keys[0],db)
    genesis.MustCommit(db)
    chain,err:=core.NewBlockChain(db,nil,genesis.Config,backend,vm.Config{},nil,nil)
    if err!=nil {return nil,err}
    if err=backend.Start(chain,chain.CurrentBlock,rawdb.HasBadBlock);err!=nil {return nil,err}
    defer backend.Stop()
    parent:=chain.Genesis()
    snap,err:=backend.snapshot(chain,0,common.Hash{},nil)
    if err!=nil {return nil,err}
    proposer:=snap.ValSet.GetProposer().Address()
    var proposerKey *ecdsa.PrivateKey
    for _,k:=range keys {if crypto.PubkeyToAddress(k.PublicKey)==proposer {proposerKey=k}}
    if proposerKey==nil {return nil,fmt.Errorf("cannot identify proposer key")}
    hdr:=makeHeader(parent,backend.config)
    hdr.Coinbase=proposer
    if chain.Config().IsLondon(hdr.Number) {
     hdr.BaseFee=misc.CalcBaseFee(chain.Config(),parent.Header())
    }
    if err=backend.Prepare(chain,hdr);err!=nil {return nil,err}
    state,err:=chain.StateAt(parent.Root());if err!=nil {return nil,err}
    block,err:=backend.FinalizeAndAssemble(chain,hdr,state,nil,nil,nil)
    if err!=nil {return nil,err}
    pp:=qbfttypes.NewPreprepare(big.NewInt(1),big.NewInt(0),block)
    pbytes,e:=pp.EncodePayloadForSigning();if e!=nil {return nil,e}
    psig,e:=crypto.Sign(crypto.Keccak256(pbytes),proposerKey);if e!=nil{return nil,e}
    pp.SetSignature(psig)
    wire,e:=rlp.EncodeToBytes(pp);if e!=nil{return nil,e}
    send:=func(code uint64,addr common.Address,payload []byte) error {
     handled,e:=backend.HandleMsg(addr,p2p.Msg{
      Code:code,Size:uint32(len(payload)),Payload:bytes.NewReader(payload),
     })
     if !handled||e!=nil {return fmt.Errorf("send code=%d handled=%v err=%v",code,handled,e)}
     return nil
    }
    if err=send(qbfttypes.PreprepareCode,proposer,wire);err!=nil{return nil,err}
    wait:=func(check func(*istanbul.RoundStateInfo)bool) *istanbul.RoundStateInfo{
     deadline:=time.Now().Add(1200*time.Millisecond)
     for time.Now().Before(deadline){
      info:=backend.core.RoundState()
      if info!=nil&&check(info){return info}
      time.Sleep(15*time.Millisecond)
     }
     return backend.core.RoundState()
    }
    started:=wait(func(x *istanbul.RoundStateInfo)bool{return x.HasProposal})
    if started==nil||!started.HasProposal {
     return started,fmt.Errorf("fixture did not accept valid signed preprepare: state=%+v",started)
    }
    honestSent:=0
    for i:=1;i<4;i++ {
     from:=crypto.PubkeyToAddress(keys[i].PublicKey)
     if from==backend.Address() {continue}
     m:=qbfttypes.NewPrepare(big.NewInt(1),big.NewInt(0),block.Hash())
     encoded,e:=m.EncodePayloadForSigning();if e!=nil{return nil,e}
     msig,e:=crypto.Sign(crypto.Keccak256(encoded),keys[i]);if e!=nil{return nil,e}
     m.SetSignature(msig)
     raw,e:=rlp.EncodeToBytes(m);if e!=nil{return nil,e}
     if i==2&&poison{
      if e=send(qbfttypes.CommitCode,crypto.PubkeyToAddress(keys[3].PublicKey),raw);e!=nil{return nil,e}
      time.Sleep(30*time.Millisecond)
     }
     if i==3{continue} // validator 3 is Byzantine and never votes
     if e=send(qbfttypes.PrepareCode,from,raw);e!=nil{return nil,e}
     honestSent++
    }
    finish:=wait(func(x *istanbul.RoundStateInfo)bool{return x.State=="Prepared"||x.State=="Committed"})
    if finish==nil{return nil,fmt.Errorf("no round state after valid vote sequence")}
    t.Logf("B_QUORUM_ACTUAL_STATE seed=%d poison=%v own=%s proposer=%s sent_other_honest=%d quorum=%d prepares=%d commits=%d state=%s",
     seed,poison,backend.Address(),proposer,honestSent,finish.QuorumSize,finish.Prepares,finish.Commits,finish.State)
    return finish,nil
   }
   good,e:=run(false);if e!=nil {t.Fatal(e)}
   bad,e:=run(true);if e!=nil {t.Fatal(e)}
   if good.QuorumSize!=3||good.Validators!=4 {t.Fatalf("invalid 4-validator oracle quorum=%d validators=%d",good.QuorumSize,good.Validators)}
   if good.State!="Prepared"&&good.State!="Committed" {t.Fatalf("B_QUORUM_HARNESS_BAD_CONTROL state=%s prepares=%d",good.State,good.Prepares)}
   t.Logf("B_QUORUM_LIVENESS_DIFFERENTIAL seed=%d good_state=%s bad_state=%s good_prepares=%d bad_prepares=%d quorum=%d",seed,good.State,bad.State,good.Prepares,bad.Prepares,good.QuorumSize)
   if bad.State!="Prepared"&&bad.State!="Committed" {
    t.Logf("B_QUORUM_SINGLE_NODE_STALLED seed=%d one_byzantine_retagged_vote=true",seed)
   }else{
    t.Logf("B_QUORUM_GUARD_HELD seed=%d bad_node_still_prepared=true",seed)
   }
  })
 }
}
