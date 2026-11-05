package gasprice

import (
 "context"
 "encoding/json"
 "math/big"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/rpc"
)

// Non-destructive, bounded characterization of the real FeeHistory implementation.
// Uses the existing signed synthetic-block test backend, not an Internet RPC node.
func TestIndependentFeeHistoryRewardPercentileAmplification(t *testing.T) {
 backend := newTestBackend(t, big.NewInt(16), false)
 oracle := NewOracle(backend, Config{MaxHeaderHistory: 1024, MaxBlockHistory: 1024})
 const blocks = 32
 for _, count := range []int{1, 64, 512, 4096} {
  percentiles := make([]float64, count)
  for i := range percentiles { percentiles[i] = 1 }
  requestJSON, err := json.Marshal([]interface{}{"eth_feeHistory", "0x20", "latest", percentiles})
  if err != nil { t.Fatal(err) }
  start := time.Now()
  _, reward, _, _, err := oracle.FeeHistory(context.Background(), blocks, rpc.LatestBlockNumber, percentiles)
  took := time.Since(start)
  if err != nil { t.Fatalf("percentiles=%d: %v",count,err) }
  if len(reward) != blocks { t.Fatalf("percentiles=%d: got %d rows, want %d", count,len(reward),blocks) }
  for i,row := range reward {
   if len(row) != count { t.Fatalf("row=%d percentiles=%d: got %d values",i,count,len(row)) }
  }
  rewardJSON, err := json.Marshal(reward)
  if err != nil { t.Fatal(err) }
  cells := blocks*count
  factor := float64(len(rewardJSON))/float64(len(requestJSON))
  t.Logf("ETN_PROVEN_FEEHISTORY_AMPLIFICATION percentiles=%d blocks=%d matrix_cells=%d request_bytes=%d reward_json_bytes=%d wire_factor=%.2f duration=%s",count,blocks,cells,len(requestJSON),len(rewardJSON),factor,took)
  if count == 4096 && (cells != 131072 || factor < 10) {
   t.Fatalf("unexpected safety bound or reproduction drift: cells=%d factor=%.2f",cells,factor)
  }
 }
}
