// Lane D: out-of-order peer-like block delivery must not persist an orphan as canonical.
// This is an import-order harness using fake PoW; it does NOT prove QBFT or P2P exposure.
package core

import (
 "testing"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/params"
)

func TestWorkerDOutOfOrderAncestorRecovery(t *testing.T) {
 for _, tc := range []struct{name string; honest, competing int}{
  {"gap_two",4,2}, {"gap_three",5,3}, {"gap_four",6,4},
 } {
  t.Run(tc.name,func(t *testing.T){
   engine:=ethash.NewFaker()
   db,bc,err:=newCanonical(engine,0,true)
   if err!=nil {t.Fatal(err)}
   genesis:=bc.CurrentBlock()
   honest:=makeBlockChain(genesis,tc.honest,engine,db,canonicalSeed)
   rival:=makeBlockChain(genesis,tc.competing,engine,db,forkSeed)
   if _,err=bc.InsertChain(honest);err!=nil{bc.Stop();t.Fatalf("honest: %v",err)}
   expected:=honest[len(honest)-1].Hash()
   // Candidate arrives without its required parent. It must not alter canonical history.
   orphan:=rival[tc.competing-1]
   if _,err=bc.InsertChain(types.Blocks{orphan});err==nil{
    bc.Stop();t.Fatal("D_ORPHAN_ADMITTED_WITHOUT_ANCESTRY")
   }
   if bc.CurrentBlock().Hash()!=expected || rawdb.ReadHeadBlockHash(db)!=expected {
    bc.Stop();t.Fatal("D_ORPHAN_CHANGED_CANONICAL_HEAD")
   }
   t.Logf("D_ORPHAN_REJECTED case=%s height=%d",tc.name,orphan.NumberU64())
   // Honest ancestor repair: deliver complete valid shorter competing branch in order.
   if _,err=bc.InsertChain(types.Blocks(rival));err!=nil{bc.Stop();t.Fatalf("ordered recovery: %v",err)}
   if bc.CurrentBlock().Hash()!=expected{bc.Stop();t.Fatal("D_RECOVERY_REORG_UNEXPECTED")}
   bc.Stop()
   reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
   if err!=nil{t.Fatal(err)}
   defer reopened.Stop()
   if reopened.CurrentBlock().Hash()!=expected || rawdb.ReadHeadBlockHash(db)!=expected {
    t.Fatal("D_RESTART_HEAD_DRIFT")
   }
   for i,b:=range honest{
    if rawdb.ReadCanonicalHash(db,uint64(i+1))!=b.Hash(){t.Fatalf("D_CANONICAL_DRIFT height=%d",i+1)}
   }
   t.Logf("D_ORDERED_RECOVERY_RESTART_OK case=%s",tc.name)
  })
 }
}
