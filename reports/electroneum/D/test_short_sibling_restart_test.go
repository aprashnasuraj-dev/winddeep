// Class D: deterministic real InsertChain fork-choice and persistent canonical-map regression.
// Ethash faker deliberately isolates import/fork choice; NOT QBFT finality or peer reachability.
package core

import (
 "testing"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/params"
)

func TestWorkerDShortSiblingRestartIntegrity(t *testing.T) {
 for _, tc := range []struct{name string; siblingLength int}{
  {"single_sibling",1}, {"two_siblings",2},
 } {
  t.Run(tc.name,func(t *testing.T){
   engine:=ethash.NewFaker()
   db,bc,err:=newCanonical(engine,0,true)
   if err!=nil {t.Fatal(err)}
   genesis:=bc.CurrentBlock()
   chainA:=makeBlockChain(genesis,3,engine,db,canonicalSeed)
   chainB:=makeBlockChain(genesis,tc.siblingLength,engine,db,forkSeed)
   if chainA[0].Hash()==chainB[0].Hash(){bc.Stop();t.Fatal("fixture branches identical")}
   if _,err=bc.InsertChain(chainA);err!=nil{bc.Stop();t.Fatalf("honest A: %v",err)}
   expected:=chainA[2].Hash()
   for height:=uint64(1);height<=3;height++{
    if got:=rawdb.ReadCanonicalHash(db,height);got!=chainA[height-1].Hash(){bc.Stop();t.Fatalf("A oracle height=%d got=%s",height,got)}
   }
   t.Logf("D_BRANCH_A_ACCEPTED height=3 hash=%s",expected)
   if _,err=bc.InsertChain(types.Blocks(chainB));err!=nil{bc.Stop();t.Fatalf("valid shorter sibling rejected: %v",err)}
   if got:=bc.CurrentBlock().Hash();got!=expected{bc.Stop();t.Fatalf("short sibling changed head got=%s want=%s",got,expected)}
   for height:=uint64(1);height<=3;height++{
    if got:=rawdb.ReadCanonicalHash(db,height);got!=chainA[height-1].Hash(){bc.Stop();t.Fatalf("short sibling changed canonical height=%d",height)}
   }
   if got:=rawdb.ReadHeadBlockHash(db);got!=expected{bc.Stop();t.Fatalf("persisted head block hash before restart got=%s want=%s",got,expected)}
   if got:=rawdb.ReadHeadHeaderHash(db);got!=expected{bc.Stop();t.Fatalf("persisted head header hash before restart got=%s want=%s",got,expected)}
   t.Logf("D_PERSISTED_HEAD_POINTERS_OK length=%d",tc.siblingLength)
   t.Logf("D_SHORT_SIBLING_NONCANONICAL length=%d",tc.siblingLength)
   bc.Stop()
   reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
   if err!=nil{t.Fatalf("restart: %v",err)}
   defer reopened.Stop()
   if got:=reopened.CurrentBlock().Hash();got!=expected{t.Fatalf("restart head got=%s want=%s",got,expected)}
   for height:=uint64(1);height<=3;height++{
    if got:=rawdb.ReadCanonicalHash(db,height);got!=chainA[height-1].Hash(){t.Fatalf("restart canonical mismatch height=%d",height)}
   }
   if got:=rawdb.ReadHeadBlockHash(db);got!=expected{t.Fatalf("restart persisted block head got=%s want=%s",got,expected)}
   if got:=rawdb.ReadHeadHeaderHash(db);got!=expected{t.Fatalf("restart persisted header head got=%s want=%s",got,expected)}
   t.Logf("D_RESTART_HEAD_POINTERS_OK length=%d",tc.siblingLength)
   t.Logf("D_RESTART_CANONICAL_ORACLE_OK length=%d",tc.siblingLength)
  })
 }
}


// Invalid-root sibling must never modify canonical mappings or persisted head.
// This is an import admission boundary, not a QBFT finality or P2P test.
func TestWorkerDInvalidSiblingRootRestartIntegrity(t *testing.T) {
 for _, tc := range []struct{name string; corruptRoot string}{
  {"transaction_root","tx"},{"receipt_root","receipt"},{"state_root","state"},
 } {
  t.Run(tc.name,func(t *testing.T){
   engine:=ethash.NewFaker()
   db,bc,err:=newCanonical(engine,0,true)
   if err!=nil {t.Fatal(err)}
   genesis:=bc.CurrentBlock()
   chainA:=makeBlockChain(genesis,3,engine,db,canonicalSeed)
   sibling:=makeBlockChain(genesis,1,engine,db,forkSeed)
   if _,err=bc.InsertChain(chainA);err!=nil{bc.Stop();t.Fatal(err)}
   head:=chainA[2].Hash()
   header:=sibling[0].Header()
   switch tc.corruptRoot {
   case "receipt": header.ReceiptHash[0]^=1
   case "state": header.Root[0]^=1
   default: header.TxHash[0]^=1
   }
   invalid:=types.NewBlockWithHeader(header).WithBody(sibling[0].Transactions(),sibling[0].Uncles())
   if _,err=bc.InsertChain(types.Blocks{invalid});err==nil{bc.Stop();t.Fatal("invalid sibling root admitted")}
   t.Logf("D_INVALID_SIBLING_ROOT_REJECTED case=%s error=%v",tc.name,err)
   for height:=uint64(1);height<=3;height++{
    if got:=rawdb.ReadCanonicalHash(db,height);got!=chainA[height-1].Hash(){bc.Stop();t.Fatalf("canonical drift height=%d",height)}
   }
   if rawdb.ReadHeadBlockHash(db)!=head || rawdb.ReadHeadHeaderHash(db)!=head {bc.Stop();t.Fatal("persisted head drift before restart")}
   bc.Stop()
   reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
   if err!=nil{t.Fatal(err)}
   defer reopened.Stop()
   if reopened.CurrentBlock().Hash()!=head || rawdb.ReadHeadBlockHash(db)!=head || rawdb.ReadHeadHeaderHash(db)!=head {t.Fatal("restart head drift")}
   for height:=uint64(1);height<=3;height++{
    if rawdb.ReadCanonicalHash(db,height)!=chainA[height-1].Hash(){t.Fatalf("restart canonical drift height=%d",height)}
   }
   t.Logf("D_INVALID_SIBLING_RESTART_ORACLE_OK case=%s",tc.name)
  })
 }
}
