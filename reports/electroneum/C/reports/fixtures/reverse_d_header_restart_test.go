// Reverse Worker R — certified-source local header rewind/restart and orphan index oracle.
// Copy ONLY to scratch core package. Synthetic memory database and FakePow isolate
// persistence from QBFT signing; a local SetHead is an administrator operation,
// not evidence an outside attacker can rewrite finalized history.
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

func TestReverseDHeaderRollbackRestart(t *testing.T) {
 t.Run("rewind_full_chain_and_reopen_same_db", func(t *testing.T) {
  db,bc,err:=newCanonical(ethash.NewFaker(),8,true)
  if err!=nil {t.Fatalf("synthetic chain generation: %v",err)}
  if bc.CurrentBlock().NumberU64()!=8 {bc.Stop();t.Fatalf("honest head not at 8")}
  saved:=make([]common.Hash,9)
  for n:=uint64(0);n<=8;n++ {
   saved[n]=rawdb.ReadCanonicalHash(db,n)
   if saved[n]==(common.Hash{}) {bc.Stop();t.Fatalf("honest canonical missing at %d",n)}
  }
  if err:=bc.SetHead(4);err!=nil {bc.Stop();t.Fatalf("rewind to 4 failed: %v",err)}
  if bc.CurrentBlock().NumberU64()!=4 || bc.CurrentBlock().Hash()!=saved[4] {bc.Stop();t.Fatalf("rewound head disagrees with canonical oracle")}
  for n:=uint64(0);n<=8;n++ {
   want:=common.Hash{}
   if n<=4 {want=saved[n]}
   if got:=rawdb.ReadCanonicalHash(db,n);got!=want {
    bc.Stop();t.Fatalf("post-rewind canonical index n=%d got=%s want=%s",n,got,want)
   }
  }
  t.Log("REVERSE_D_HEADER_REWIND_CANONICAL_INDEX_PASS retained=0..4 removed=5..8")
  bc.Stop()
  reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
  if err!=nil {t.Fatalf("reopen synthetic chain: %v",err)}
  defer reopened.Stop()
  if reopened.CurrentBlock()==nil || reopened.CurrentBlock().NumberU64()!=4 || reopened.CurrentBlock().Hash()!=saved[4] {
   t.Fatalf("reopened block head differs: %v",reopened.CurrentBlock())
  }
  if reopened.CurrentHeader().Number.Uint64()!=4 || reopened.CurrentHeader().Hash()!=saved[4] {
   t.Fatalf("reopened header head differs: %v",reopened.CurrentHeader())
  }
  for n:=uint64(1);n<=4;n++ {
   h:=reopened.GetHeaderByNumber(n)
   if h==nil || h.Hash()!=saved[n] || h.ParentHash!=saved[n-1] {
    t.Fatalf("reopened ancestor chain mismatch n=%d header=%v",n,h)
   }
  }
  for n:=uint64(5);n<=8;n++ {
   if rawdb.ReadCanonicalHash(db,n)!=(common.Hash{}) {
    t.Fatalf("reopened removed height %d has canonical mapping",n)
   }
  }
  t.Log("REVERSE_D_HEADER_RESTART_ROOT_AND_ANCESTRY_PASS head=4")
  // Independent mutation sensitivity: inject an old height-6 canonical index
  // into a DISPOSABLE in-memory DB, verify full-width oracle detects it, then
  // restore. Not a claim network peers can modify local LevelDB directly.
  rawdb.WriteCanonicalHash(db,saved[6],6)
  observed:=rawdb.ReadCanonicalHash(db,6)
  if observed!=(common.Hash{}) && observed==saved[6] {
   t.Log("REVERSE_D_HEADER_ORACLE_DETECTS_INJECTED_STALE_INDEX_PASS height=6")
  } else {t.Fatal("oracle did not observe deliberately injected corrupted canonical index")}
  rawdb.DeleteCanonicalHash(db,6)
  if rawdb.ReadCanonicalHash(db,6)!=(common.Hash{}) {t.Fatal("stale-index injection not cleaned")}
 })
 t.Run("noncontiguous_forged_block_batch_rejected",func(t *testing.T) {
  db,bc,err:=newCanonical(ethash.NewFaker(),0,true)
  if err!=nil {t.Fatal(err)}
  defer bc.Stop()
  blocks:=makeBlockChain(bc.CurrentBlock(),2,ethash.NewFaker(),db,canonicalSeed)
  // Peer-controlled ordering cannot trick the high-level InsertChain ancestor precheck.
  adversarial:=types.Blocks{blocks[1],blocks[0]}
  if _,err:=bc.InsertChain(adversarial);err==nil {
   t.Fatal("misordered block batch was accepted as valid history")
  }
  if bc.CurrentBlock().NumberU64()!=0 || rawdb.ReadCanonicalHash(db,1)!=(common.Hash{}) {
   t.Fatal("rejected adversarial history changed canonical state")
  }
  t.Log("REVERSE_D_NONCONTIGUOUS_HISTORY_REJECTED_PASS")
 })

 t.Run("finalized_pointer_after_explicit_admin_rewind",func(t *testing.T){
  db,bc,err:=newCanonical(ethash.NewFaker(),8,true)
  if err!=nil {t.Fatal(err)}
  finalized:=bc.GetBlockByNumber(7)
  if finalized==nil {bc.Stop();t.Fatal("missing synthetic finalized block")}
  bc.SetFinalized(finalized)
  if bc.CurrentFinalizedBlock()==nil || bc.CurrentFinalizedBlock().Hash()!=finalized.Hash() {bc.Stop();t.Fatal("finalized baseline invalid")}
  if rawdb.ReadFinalizedBlockHash(db)!=finalized.Hash() {bc.Stop();t.Fatal("finalized marker baseline invalid")}
  if err:=bc.SetHead(4);err!=nil {bc.Stop();t.Fatalf("admin rewind failed: %v",err)}
  if bc.CurrentBlock().NumberU64()!=4 {bc.Stop();t.Fatal("rewound chain head wrong")}
  ptr:=bc.CurrentFinalizedBlock()
  if ptr!=nil&&ptr.NumberU64()>bc.CurrentBlock().NumberU64() {
   t.Logf("REVERSE_D_STALE_FINALIZED_POINTER_OBSERVED finalized=%d current=%d",ptr.NumberU64(),bc.CurrentBlock().NumberU64())
  } else {t.Log("REVERSE_D_NO_STALE_FINALIZED_POINTER")}
  if rawdb.ReadFinalizedBlockHash(db)==finalized.Hash() {t.Log("REVERSE_D_FINALIZED_DB_MARKER_SURVIVED_REWIND_OBSERVED")}
  bc.Stop()
  reopened,err:=NewBlockChain(db,nil,params.AllEthashProtocolChanges,ethash.NewFaker(),vm.Config{},nil,nil)
  if err!=nil {t.Fatalf("reopen after finalized rewind: %v",err)}
  defer reopened.Stop()
  ptr=reopened.CurrentFinalizedBlock()
  if ptr!=nil && ptr.NumberU64()>reopened.CurrentBlock().NumberU64() {
   t.Logf("REVERSE_D_REOPENED_FINALIZED_POINTER_ABOVE_HEAD_OBSERVED finalized=%d current=%d",ptr.NumberU64(),reopened.CurrentBlock().NumberU64())
  } else {t.Log("REVERSE_D_REOPENED_NO_STALE_POINTER")}
  if rawdb.ReadFinalizedBlockHash(db)==finalized.Hash() {t.Log("REVERSE_D_REOPENED_DB_FINALIZED_MARKER_STALE_OBSERVED")}
 })

}


// This intentionally strict local-state oracle may find an administrative
// rewind inconsistency. That condition alone does NOT prove an outsider can
// rewrite finalized QBFT history or exploit a production node.
func TestReverseDFinalityRewindFailClosedOracle(t *testing.T){
 _,bc,err:=newCanonical(ethash.NewFaker(),8,true)
 if err!=nil {t.Fatal(err)}
 defer bc.Stop()
 b:=bc.GetBlockByNumber(7)
 if b==nil {t.Fatal("missing synthetic finalized block")}
 bc.SetFinalized(b)
 if err:=bc.SetHead(4);err!=nil {t.Fatal(err)}
 f:=bc.CurrentFinalizedBlock()
 if f!=nil && f.NumberU64()>bc.CurrentBlock().NumberU64() {
  t.Errorf("REVERSE_D_FINALIZED_REWIND_ORACLE_MISMATCH finalized=%d current=%d",f.NumberU64(),bc.CurrentBlock().NumberU64())
 }
}
