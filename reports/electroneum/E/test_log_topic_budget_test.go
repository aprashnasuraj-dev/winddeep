package filters

import (
 "testing"
 "github.com/electroneum/electroneum-sc/common"
)

// E-RPC-009: bound and document the distinction between per-position
// topic limits and aggregate topic count. This is a guard characterization,
// not proof of resource exhaustion.
func TestWorkerELogTopicBudget(t *testing.T) {
 const capPerPosition = 8
 makeTopics := func(positions, alternatives int) [][]common.Hash {
  out := make([][]common.Hash, positions)
  for p := range out {
   out[p] = make([]common.Hash, alternatives)
   for j := range out[p] {
    out[p][j][0] = byte(p+1)
    out[p][j][1] = byte(j+1)
   }
  }
  return out
 }
 cases := []struct{name string; positions,alternatives int; reject bool}{
  {"normal",1,1,false},
  {"per_position_boundary",4,8,false},
  {"per_position_over",4,9,true},
  {"aggregate_above_single_cap",4,8,false},
  {"extra_positions",5,8,false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   topics:=makeTopics(tc.positions,tc.alternatives)
   got:=CheckLogQueryLimit(capPerPosition,nil,topics)
   if (got!=nil)!=tc.reject {t.Fatalf("E_LOG_TOPIC_GUARD case=%s positions=%d alternatives=%d reject=%v expected=%v",tc.name,tc.positions,tc.alternatives,got!=nil,tc.reject)}
   t.Logf("E_LOG_TOPIC_GUARD case=%s positions=%d alternatives=%d aggregate=%d rejected=%v",tc.name,tc.positions,tc.alternatives,tc.positions*tc.alternatives,got!=nil)
  })
 }
}
