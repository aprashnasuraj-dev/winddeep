// Reverse Worker R: full real core.BlockChain SetHead and restart invariants.
// Scratch-only test injected into immutable certified Electroneum source; no
// network requests, public-chain probes or committed source changes.
package core

import (
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/params"
)

func TestReverseDHeaderSetHeadRestart(t *testing.T) {
 t.Run("honest_rollback_restart_reimport",func(t *testing.T){
  engine:=ethash.NewFaker()
  db,bc,err:=newCanonical(engine,0,true)
  if err!=nil {t.Fatalf("fixture genesis: %v",err)}
  blocks:=makeBlockChain(bc.CurrentBlock(),5,engine,db,canonicalSeed)
  if _,err=bc.InsertChain(blocks);err!=nil {bc.Stop();t.Fatalf("valid five-block import: %v",err)}
  if bc.CurrentBlock().Hash()!=blocks[4].Hash()||bc.GetCanonicalHash(5)!=blocks[4].Hash() {
   bc.Stop();t.Fatal("honest canonical head was not imported")
  }
  if err=bc.SetHead(2);err!=nil {bc.Stop();t.Fatalf("SetHead(2): %v",err)}
  if bc.CurrentBlock().Hash()!=blocks[1].Hash() {
   bc.Stop();t.Fatalf("rollback did not reach canonical height2: got=%s want=%s",bc.CurrentBlock().Hash(),blocks[1].Hash())
  }
  for height:=uint64(3);height<=5;height++{
   if h:=rawdb.ReadCanonicalHash(db,height);h!=(common.Hash{}) {
    bc.Stop();t.Fatalf("orphan canonical hash survives rewind height=%d hash=%s",height,h)
   }
  }
  bc.Stop()
  reopened,e:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
  if e!=nil {t.Fatalf("restart after rewind: %v",e)}
  defer reopened.Stop()
  if reopened.CurrentBlock().Hash()!=blocks[1].Hash(){
   t.Fatalf("restart resurrected orphan head got=%s want=%s",reopened.CurrentBlock().Hash(),blocks[1].Hash())
  }
  if h:=reopened.GetCanonicalHash(5);h!=(common.Hash{}){
   t.Fatalf("restart exposes stale canonical height5=%s",h)
  }
  t.Log("REVERSE_D_REWIND_RESTART_CLEARS_ORPHANS_PASS head=2")
  _,err=reopened.InsertChain(blocks[2:])
  if err!=nil {t.Fatalf("honest chain reimport after rewind: %v",err)}
  if reopened.CurrentBlock().Hash()!=blocks[4].Hash()||reopened.GetCanonicalHash(5)!=blocks[4].Hash(){
   t.Fatal("honest reimport after rewind did not restore expected canonical tip")
  }
  t.Log("REVERSE_D_REWIND_REIMPORT_VALID_PASS head=5")
 })
 t.Run("corrupt_header_after_rewind_not_committed",func(t *testing.T){
  engine:=ethash.NewFaker()
  db,bc,e:=newCanonical(engine,0,true)
  if e!=nil {t.Fatal(e)}
  blocks:=makeBlockChain(bc.CurrentBlock(),5,engine,db,canonicalSeed)
  if _,e=bc.InsertChain(blocks);e!=nil {bc.Stop();t.Fatalf("setup: %v",e)}
  if e=bc.SetHead(2);e!=nil {bc.Stop();t.Fatalf("SetHead: %v",e)}
  mutated:=blocks[2].Header()
  mutated.ReceiptHash[0]^=0x01
  bad:=types.NewBlockWithHeader(mutated).WithBody(blocks[2].Transactions(),blocks[2].Uncles())
  if _,e=bc.InsertChain(types.Blocks{bad});e==nil {
   bc.Stop();t.Fatal("corrupt header admitted after rewind")
  }
  if bc.CurrentBlock().Hash()!=blocks[1].Hash() || bc.GetCanonicalHash(3)!=(common.Hash{}) {
   bc.Stop();t.Fatal("corrupt candidate advanced canonical chain")
  }
  t.Logf("REVERSE_D_REWIND_CORRUPT_RECEIPT_ROOT_REJECTED_PASS err=%v",e)
  bc.Stop()
  reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
  if err!=nil {t.Fatalf("restart: %v",err)}
  defer reopened.Stop()
  if reopened.CurrentBlock().Hash()!=blocks[1].Hash() || reopened.GetCanonicalHash(3)!=(common.Hash{}) {
   t.Fatal("restart resurrected corrupt-orphan header")
  }
  t.Log("REVERSE_D_RESTART_CORRUPT_ORPHAN_ABSENT_PASS")
 })
}
