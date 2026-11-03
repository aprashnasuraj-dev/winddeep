// Reverse Worker R: independent E-RPC-008 eth_getLogs range integrity test.
// Copied ONLY to a certified immutable-source SCRATCH copy under eth/filters.
// No real chain requests, transactions, keys or persistent state.
package filters

import (
 "context"
 "errors"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/ethdb"
 "github.com/electroneum/electroneum-sc/rpc"
)

type reverseLogBackend struct {
 Backend
 db ethdb.Database
 heads map[int64]*types.Header
 byHash map[common.Hash]int64
 missingAt int64
 errorAt int64
}
func (b *reverseLogBackend) ChainDb() ethdb.Database {return b.db}
func (b *reverseLogBackend) BloomStatus()(uint64,uint64){return 4096,0}
func (b *reverseLogBackend) HeaderByNumber(_ context.Context,n rpc.BlockNumber)(*types.Header,error){
 if n==rpc.LatestBlockNumber {return b.heads[3],nil}
 i:=int64(n)
 if i==b.errorAt {return nil, errors.New("synthetic header backend failure")}
 if i==b.missingAt {return nil,nil}
 return b.heads[i],nil
}
func (b *reverseLogBackend) GetLogs(_ context.Context,hash common.Hash)([][]*types.Log,error){
 n,ok:=b.byHash[hash]
 if !ok {return nil,errors.New("synthetic unknown header")}
 return [][]*types.Log{{&types.Log{TxHash:common.HexToHash("0xabcd"),BlockNumber:uint64(n),Index:0}}},nil
}

func reverseLogFixture() *reverseLogBackend {
 b:=&reverseLogBackend{
  db:rawdb.NewMemoryDatabase(),
  heads:map[int64]*types.Header{},
  byHash:map[common.Hash]int64{},
  missingAt:-99,errorAt:-99,
 }
 for i:=int64(1);i<=3;i++{
  h:=&types.Header{Number:big.NewInt(i),GasLimit:30000000}
  b.heads[i]=h;b.byHash[h.Hash()]=i
 }
 return b
}
func reverseRange(b *reverseLogBackend, cap uint64)*Filter{
 return NewRangeFilter(b,1,3,nil,nil,cap)
}

func TestReverseELogRangeDefenseMatrix(t *testing.T){
 t.Run("complete_honest_range",func(t *testing.T){
  b:=reverseLogFixture()
  f:=reverseRange(b,0)
  logs,err:=f.Logs(context.Background())
  if err!=nil||len(logs)!=3||f.begin!=4 {t.Fatalf("complete range mismatch count=%d err=%v next=%d",len(logs),err,f.begin)}
  t.Log("REVERSE_E_LOG_COMPLETE_RANGE_PASS count=3")
 })
 t.Run("missing_middle_header",func(t *testing.T){
  b:=reverseLogFixture();b.missingAt=2
  f:=reverseRange(b,0)
  logs,err:=f.Logs(context.Background())
  if len(logs)!=1||f.begin!=2 {t.Fatalf("unexpected partial prefix count=%d next=%d err=%v",len(logs),f.begin,err)}
  if err==nil {
   t.Log("REVERSE_E_LOG_MISSING_MIDDLE_SILENT_PARTIAL_OBSERVED count=1 requested=3")
  }else{
   t.Logf("REVERSE_E_LOG_MISSING_MIDDLE_ERROR_OBSERVED err=%v",err)
  }
 })
 t.Run("missing_first_header",func(t *testing.T){
  b:=reverseLogFixture();b.missingAt=1
  f:=reverseRange(b,0)
  logs,err:=f.Logs(context.Background())
  if len(logs)!=0||f.begin!=1 {t.Fatalf("unexpected missing-first response count=%d next=%d err=%v",len(logs),f.begin,err)}
  if err==nil {t.Log("REVERSE_E_LOG_MISSING_FIRST_SILENT_EMPTY_OBSERVED")} else {t.Logf("REVERSE_E_LOG_MISSING_FIRST_ERROR_OBSERVED err=%v",err)}
 })
 t.Run("backend_explicit_error_propagated",func(t *testing.T){
  b:=reverseLogFixture();b.errorAt=2
  f:=reverseRange(b,0)
  logs,err:=f.Logs(context.Background())
  if err==nil||len(logs)!=1 {t.Fatalf("expected explicit backend error on partial range; count=%d err=%v",len(logs),err)}
  t.Log("REVERSE_E_LOG_EXPLICIT_ERROR_CONTROL_PASS")
 })
 t.Run("range_cap_enforced",func(t *testing.T){
  b:=reverseLogFixture()
  f:=reverseRange(b,1)
  logs,err:=f.Logs(context.Background())
  if err==nil||len(logs)!=0 {t.Fatalf("range limit not enforced err=%v count=%d",err,len(logs))}
  t.Log("REVERSE_E_LOG_RANGE_CAP_CONTROL_PASS")
 })
}

// The independent oracle requires a missing *intermediate* header to be an
// explicit query error, not a successful truncated log response. Fails on
// original certified code with the named marker; passes after R-only scratch
// repair. No claim a real full node can expose such a gap by client action.
func TestReverseELogFailClosedOracle(t *testing.T){
 b:=reverseLogFixture();b.missingAt=2
 f:=reverseRange(b,0)
 logs,err:=f.Logs(context.Background())
 if err==nil {
  t.Errorf("REVERSE_E_LOG_FAIL_CLOSED_ORACLE_MISMATCH: query [1..3] returned %d logs with nil error and missing block 2",len(logs))
  return
 }
 t.Logf("REVERSE_E_LOG_FAIL_CLOSED_ORACLE_PASS err=%v returned_prefix=%d",err,len(logs))
}
