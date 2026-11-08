package filters

import (
 "encoding/json"
 "strings"
 "testing"
)

// E-RPC-016: distinct from per-position OR budgets: positional wildcard depth.
// This characterizes a possible budget bypass, NOT an availability exploit.
func TestWorkerEWildcardTopicDepthBudget(t *testing.T) {
 const limit = 8
 for _,tc := range []struct{name string;positions int; wantReject bool}{
  {"small_valid",2,false},
  {"at_limit",8,false},
  {"above_limit",9,true},
  {"bounded_large",64,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   payload := `{"topics":[`+strings.TrimSuffix(strings.Repeat("null,",tc.positions),",")+`]}`
   var crit FilterCriteria
   if err:=json.Unmarshal([]byte(payload),&crit);err!=nil {t.Fatalf("decode: %v",err)}
   err:=CheckLogQueryLimit(limit,crit.Addresses,crit.Topics)
   rejected:=err!=nil
   t.Logf("E_WILDCARD_DEPTH name=%s positions=%d limit=%d rejected=%v expected_reject=%v",tc.name,len(crit.Topics),limit,rejected,tc.wantReject)
   if rejected!=tc.wantReject {t.Errorf("E_WILDCARD_DEPTH_INVARIANT expected rejection=%v got=%v positions=%d",tc.wantReject,rejected,tc.positions)}
  })
 }
}
