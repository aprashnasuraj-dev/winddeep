package backend

import (
 "testing"
 "github.com/electroneum/electroneum-sc/core/types"
)

// A_QBFT_IMPORT_BASELINE establishes a real backend-built block import.
// This is an admission prerequisite, NOT a value-creation vulnerability.
func TestWorkerAQBFTImportAdmission(t *testing.T) {
 for _, n := range []int{1,2,3} {
  t.Run(string(rune('0'+n)),func(t *testing.T){
   chain, engine := newBlockChain(1)
   defer engine.Stop()
   parent := chain.Genesis()
   for i:=0;i<n;i++ {
    block:=makeBlock(chain,engine,parent)
    if block==nil {t.Fatal("nil QBFT block")}
    if index,err:=chain.InsertChain(types.Blocks{block});err!=nil {
     t.Fatalf("QBFT import height=%d index=%d: %v",i+1,index,err)
    }
    if chain.CurrentBlock().Hash()!=block.Hash(){t.Fatalf("canonical head mismatch at %d",i+1)}
    parent=block
   }
   st,err:=chain.State();if err!=nil{t.Fatal(err)}
   if st==nil {t.Fatal("nil canonical state")}
   t.Logf("A_QBFT_IMPORT_BASELINE blocks=%d head=%s state_root=%s",n,parent.Hash(),parent.Root())
  })
 }
}
