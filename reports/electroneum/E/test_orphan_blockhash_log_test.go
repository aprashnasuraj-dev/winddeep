package filters

import (
 "context"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/params"
)

// E-RPC-018: outsider supplies an old block hash after canonical replacement.
// This is a bounded rawdb/filter behavioral discriminator, NOT signed QBFT proof.
// A hash-specific historical query may intentionally return noncanonical logs.
func TestWorkerEOrphanBlockHashLogBoundary(t *testing.T) {
 for state:=0;state<3;state++ {
  db:=rawdb.NewMemoryDatabase()
  addr:=common.BytesToAddress([]byte{byte(state+1)})
  genesis:=core.GenesisBlockForTesting(db,addr,big.NewInt(1000000))
  makeChain:=func(topic byte)([]*types.Block,[]types.Receipts) {
   return core.GenerateChain(params.TestChainConfig,genesis,ethash.NewFaker(),db,1,func(_ int,g *core.BlockGen){
    receipt:=types.NewReceipt(nil,false,0)
    receipt.Logs=[]*types.Log{{Address:addr,Topics:[]common.Hash{common.BytesToHash([]byte{topic})}}}
    g.AddUncheckedReceipt(receipt)
    g.AddUncheckedTx(types.NewTransaction(uint64(topic),addr,big.NewInt(1),21000,g.BaseFee(),nil))
   })
  }
  old,oldReceipts:=makeChain(byte(state+1))
  replacement,replacementReceipts:=makeChain(byte(state+11))
  if old[0].Hash()==replacement[0].Hash(){t.Fatal("E_ORPHAN_FIXTURE_IDENTICAL")}
  for _,entry:=range []struct{block *types.Block;receipts types.Receipts}{{old[0],oldReceipts[0]},{replacement[0],replacementReceipts[0]}}{
   rawdb.WriteBlock(db,entry.block)
   rawdb.WriteReceipts(db,entry.block.Hash(),entry.block.NumberU64(),entry.receipts)
  }
  rawdb.WriteCanonicalHash(db,replacement[0].Hash(),replacement[0].NumberU64())
  rawdb.WriteHeadBlockHash(db,replacement[0].Hash())
  backend:=&testBackend{db:db}
  current,err:=NewBlockFilter(backend,replacement[0].Hash(),nil,nil).Logs(context.Background())
  if err!=nil||len(current)!=1 {t.Fatalf("E_ORPHAN_CANONICAL state=%d count=%d err=%v",state,len(current),err)}
  stale,err:=NewBlockFilter(backend,old[0].Hash(),nil,nil).Logs(context.Background())
  t.Logf("E_ORPHAN_DIFFERENTIAL state=%d canonical_hash=%s orphan_hash=%s canonical_logs=%d orphan_logs=%d orphan_error=%v",state,replacement[0].Hash(),old[0].Hash(),len(current),len(stale),err)
  // An orphan-specific hash response is not automatically a security violation.
  // Independent canonical oracle: current canonical hash must be replacement.
  if got:=rawdb.ReadCanonicalHash(db,1);got!=replacement[0].Hash(){t.Fatalf("E_ORPHAN_CANONICAL_ORACLE state=%d got=%s",state,got)}
 }
}
