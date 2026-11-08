// Lane D: sidechain body persistence and canonical-number lookup must remain distinct.
// This isolates an import/restart invariant; fake PoW means NO QBFT or remote exploit claim.
package core

import (
 "testing"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/params"
)

func TestWorkerDSidechainHashLookupRestart(t *testing.T) {
 for _, tc := range []struct{name string; honest, competing int}{
  {"shorter_one",4,1}, {"shorter_two",4,2}, {"shorter_three",5,3},
 } {
  t.Run(tc.name,func(t *testing.T){
   engine:=ethash.NewFaker()
   db,bc,err:=newCanonical(engine,0,true)
   if err!=nil {t.Fatal(err)}
   genesis:=bc.CurrentBlock()
   honest:=makeBlockChain(genesis,tc.honest,engine,db,canonicalSeed)
   competitor:=makeBlockChain(genesis,tc.competing,engine,db,forkSeed)
   if honest[0].Hash()==competitor[0].Hash(){bc.Stop();t.Fatal("D_LOOKUP_FIXTURE_COLLISION")}
   if _,err=bc.InsertChain(honest);err!=nil{bc.Stop();t.Fatalf("honest insert: %v",err)}
   if _,err=bc.InsertChain(types.Blocks(competitor));err!=nil{bc.Stop();t.Fatalf("competitor insert: %v",err)}
   expected:=honest[len(honest)-1].Hash()
   check:=func(stage string){
    t.Helper()
    if got:=rawdb.ReadHeadBlockHash(db);got!=expected{t.Fatalf("%s head=%s expected=%s",stage,got,expected)}
    for i,block:=range honest{
     n:=uint64(i+1)
     if got:=rawdb.ReadCanonicalHash(db,n);got!=block.Hash(){t.Fatalf("%s canonical[%d]=%s expected=%s",stage,n,got,block.Hash())}
     if got:=rawdb.ReadBlock(db,block.Hash(),n);got==nil||got.Hash()!=block.Hash(){t.Fatalf("%s missing canonical block by hash height=%d",stage,n)}
    }
    for i,block:=range competitor{
     n:=uint64(i+1)
     if rawdb.ReadCanonicalHash(db,n)==block.Hash(){t.Fatalf("%s D_SIDECHAIN_CANONICAL_BREACH height=%d",stage,n)}
     if got:=rawdb.ReadBlock(db,block.Hash(),n);got==nil||got.Hash()!=block.Hash(){t.Fatalf("%s sidechain body missing height=%d",stage,n)}
     if hn:=rawdb.ReadHeaderNumber(db,block.Hash());hn==nil||*hn!=n{t.Fatalf("%s D_SIDECHAIN_HEADER_NUMBER_BREACH height=%d lookup=%v",stage,n,hn)}
     if hdr:=rawdb.ReadHeader(db,block.Hash(),n);hdr==nil||hdr.Hash()!=block.Hash(){t.Fatalf("%s D_SIDECHAIN_HEADER_BREACH height=%d",stage,n)}
    }
   }
   check("before_restart")
   t.Logf("D_SIDECHAIN_HASH_LOOKUP_PRE_RESTART_OK case=%s",tc.name)
   bc.Stop()
   reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
   if err!=nil{t.Fatalf("restart: %v",err)}
   defer reopened.Stop()
   if reopened.CurrentBlock().Hash()!=expected{t.Fatalf("restart head mismatch")}
   check("after_restart")
   t.Logf("D_SIDECHAIN_HASH_LOOKUP_POST_RESTART_OK case=%s",tc.name)
  })
 }
}
