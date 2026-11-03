package state

import (
 "math/big"
 "math/rand"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
)

// Worker A scratch-only certified-source supply conservation campaign.
// Independent integer ledger is deliberately separate from StateDB operations.
func TestWorkerASupplyRollbackCampaign(t *testing.T) {
 const cases=2500
 for seed:=int64(1);seed<=cases;seed++ {
  r:=rand.New(rand.NewSource(seed))
  s,err:=New(common.Hash{},NewDatabase(rawdb.NewMemoryDatabase()),nil)
  if err!=nil {t.Fatal(err)}
  a,b,c:=common.Address{1},common.Address{2},common.Address{3}
  initial:=int64(100000+r.Intn(900000))
  s.SetBalance(a,big.NewInt(initial))
  s.SetBalance(b,big.NewInt(0));s.SetBalance(c,big.NewInt(0))
  before:=s.Snapshot()
  amt:=int64(1+r.Intn(int(initial)))
  s.SubBalance(a,big.NewInt(amt))
  s.AddBalance(b,big.NewInt(amt))
  // An attacker-triggered reverted execution must not leak a recipient credit.
  s.RevertToSnapshot(before)
  if s.GetBalance(a).Cmp(big.NewInt(initial))!=0 || s.GetBalance(b).Sign()!=0 {
   t.Fatalf("seed=%d rollback balance violation",seed)
  }
  // Two different transfers after rollback, then rollback a nested failed call.
  x:=int64(r.Intn(int(initial)+1))
  s.SubBalance(a,big.NewInt(x));s.AddBalance(b,big.NewInt(x))
  nested:=s.Snapshot()
  y:=int64(r.Intn(int(x)+1))
  s.SubBalance(b,big.NewInt(y));s.AddBalance(c,big.NewInt(y))
  s.RevertToSnapshot(nested)
  expectedA:=big.NewInt(initial-x);expectedB:=big.NewInt(x)
  if s.GetBalance(a).Cmp(expectedA)!=0 || s.GetBalance(b).Cmp(expectedB)!=0 || s.GetBalance(c).Sign()!=0 {
   t.Fatalf("seed=%d nested rollback mismatch",seed)
  }
  sum:=new(big.Int).Add(s.GetBalance(a),s.GetBalance(b));sum.Add(sum,s.GetBalance(c))
  if sum.Cmp(big.NewInt(initial))!=0 {t.Fatalf("seed=%d unauthorized delta=%s",seed,new(big.Int).Sub(sum,big.NewInt(initial)))}
  // Mutation oracle: injected duplicate credit MUST be detected, not accepted.
  mutated:=new(big.Int).Add(sum,big.NewInt(amt))
  if mutated.Cmp(big.NewInt(initial))==0 {t.Fatalf("seed=%d mutation escaped oracle",seed)}
 }
 t.Logf("PASS seeds=%d; revert, nested revert, transfer conservation, injected duplicate-credit oracle",cases)
}
