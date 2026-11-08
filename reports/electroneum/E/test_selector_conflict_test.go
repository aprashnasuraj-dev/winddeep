package filters

import (
 "encoding/json"
 "testing"
)

// E-RPC-011: conflicting block selector ambiguity at the public eth_getLogs
// criteria decoder. A guard pass is not a vulnerability.
func TestWorkerEConflictingBlockSelectors(t *testing.T) {
 hash := "0x" + "1111111111111111111111111111111111111111111111111111111111111111"
 cases := []struct{name, payload string; reject bool}{
  {"range_only", `{"fromBlock":"0x1","toBlock":"0x2"}`, false},
  {"hash_only", `{"blockHash":"`+hash+`"}`, false},
  {"hash_and_from", `{"blockHash":"`+hash+`","fromBlock":"0x1"}`, true},
  {"hash_and_to", `{"blockHash":"`+hash+`","toBlock":"latest"}`, true},
  {"hash_and_both", `{"blockHash":"`+hash+`","fromBlock":"0x1","toBlock":"0x2"}`, true},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   var criteria FilterCriteria
   err:=json.Unmarshal([]byte(tc.payload),&criteria)
   rejected:=err!=nil
   t.Logf("E_SELECTOR_CONFLICT case=%s rejected=%v expected_reject=%v error=%v",tc.name,rejected,tc.reject,err)
   if rejected!=tc.reject { t.Fatalf("E_SELECTOR_INVARIANT case=%s rejected=%v expected=%v",tc.name,rejected,tc.reject) }
  })
 }
}
