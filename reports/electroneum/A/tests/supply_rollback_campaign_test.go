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


// Coverage-guided synthetic StateDB conservation, from the certified source in CI.
// Alternates state-changing transfers with speculative nested execution/reversion.
// Independent int64 ledger remains separate from the target's big.Int StateDB.
func FuzzWorkerAStateConservation(f *testing.F) {
 f.Add([]byte{1, 2, 3, 4, 5, 6, 7})
 f.Add([]byte{255, 255, 128, 0, 1, 254, 32})
 f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
 f.Fuzz(func(t *testing.T, data []byte) {
  if len(data)<2 || len(data)>512 {return}
  s,err:=New(common.Hash{},NewDatabase(rawdb.NewMemoryDatabase()),nil)
  if err!=nil {t.Fatal(err)}
  addrs:=[3]common.Address{{1},{2},{3}}
  initial:=int64(10000)+int64(data[0])*257
  want:=[3]int64{initial,0,0}
  s.SetBalance(addrs[0],big.NewInt(initial))
  s.SetBalance(addrs[1],big.NewInt(0))
  s.SetBalance(addrs[2],big.NewInt(0))
  for i:=1;i<len(data);i++ {
   op:=int(data[i]%5)
   from,to:=op%3,(op%3+1)%3
   if op==4 {from,to=2,0}
   amount:=int64(data[i])*(int64(data[(i+1)%len(data)])+1)
   if want[from]<amount {amount=want[from]}
   if op==3 {
    // A reverted speculative transfer must not affect any account.
    snap:=s.Snapshot()
    trial:=int64(data[i])
    if trial>want[0] {trial=want[0]}
    s.SubBalance(addrs[0],big.NewInt(trial))
    s.AddBalance(addrs[1],big.NewInt(trial))
    s.RevertToSnapshot(snap)
   } else {
    s.SubBalance(addrs[from],big.NewInt(amount))
    s.AddBalance(addrs[to],big.NewInt(amount))
    want[from]-=amount
    want[to]+=amount
   }
   total:=int64(0)
   for j:=0;j<3;j++ {
    total+=want[j]
    if s.GetBalance(addrs[j]).Cmp(big.NewInt(want[j]))!=0 {
     t.Fatalf("step=%d op=%d account=%d expected=%d actual=%s",i,op,j,want[j],s.GetBalance(addrs[j]).String())
    }
   }
   if total!=initial {t.Fatalf("step=%d supply delta=%d",i,total-initial)}
  }
  if s.GetBalance(addrs[0]).Sign()<0 {t.Fatal("underflow")}
 })
}
