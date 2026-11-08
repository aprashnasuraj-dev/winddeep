package filters

import (
 "context"
 "encoding/json"
 "fmt"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/core/rawdb"
)

// TestLiveEWildcardCapAgainstGetLogs exercises the public filter API's
// limit behavior using a bounded, in-process test backend. This is NOT a
// denial-of-service demonstration and is never run against a public RPC.
func TestLiveEWildcardCapAgainstGetLogs(t *testing.T) {
 const configuredCap=8
 api:=NewPublicFilterAPI(&testBackend{db:rawdb.NewMemoryDatabase()}, false, time.Minute, configuredCap, 1)
 for _,n:=range []int{2,8,9,16,32} {
  t.Run(fmt.Sprintf("positions_%d",n),func(t *testing.T){
   topics:=make([]interface{},n)
   raw,err:=json.Marshal(map[string]interface{}{"fromBlock":"0x0","toBlock":"0x0","topics":topics})
   if err!=nil{t.Fatal(err)}
   var criteria FilterCriteria
   if err:=json.Unmarshal(raw,&criteria);err!=nil {t.Fatalf("valid JSON decoder rejected: %v",err)}
   start:=time.Now()
   capErr:=CheckLogQueryLimit(configuredCap,criteria.Addresses,criteria.Topics)
   capElapsed:=time.Since(start)
   start=time.Now()
   _,apiErr:=api.GetLogs(context.Background(),criteria)
   queryElapsed:=time.Since(start)
   t.Logf("E_LIVE_ENTRY_COMPARISON n=%d limit=%d json_bytes=%d cap_rejected=%v query_error=%v cap_ns=%d query_ns=%d",n,configuredCap,len(raw),capErr!=nil,apiErr,capElapsed.Nanoseconds(),queryElapsed.Nanoseconds())
   if n==2 && capErr!=nil {t.Fatal("E_LIVE_BASELINE unexpected rejection")}
   if n>configuredCap {
    t.Logf("E_LIVE_LIMIT_POLICY_RESULT n=%d cap_bypass=%v api_error=%v observed_impact=none",n,capErr==nil,apiErr)
   }
  })
 }
}
