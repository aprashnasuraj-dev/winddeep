package rpc

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "runtime"
 "strings"
 "testing"
 "time"
)

type rBudgetReply struct {
 Result json.RawMessage `json:"result"`
 Error *jsonError `json:"error"`
}

func rBudgetRequest(t *testing.T, extraBytes int, unknownLength bool)(int,rBudgetReply,time.Duration,uint64){
 t.Helper()
 payload,err:=json.Marshal(map[string]interface{}{"jsonrpc":"2.0","id":1,"method":"rpc_modules","params":[]interface{}{},"padding":strings.Repeat("x",extraBytes)})
 if err!=nil{t.Fatal(err)}
 req:=httptest.NewRequest(http.MethodPost,"http://resource.invalid/rpc",bytes.NewReader(payload))
 req.Header.Set("Content-Type","application/json")
 if unknownLength{req.ContentLength=-1}
 server:=NewServer();defer server.Stop()
 var before,after runtime.MemStats
 runtime.GC();runtime.ReadMemStats(&before)
 start:=time.Now()
 rec:=httptest.NewRecorder();server.ServeHTTP(rec,req)
 elapsed:=time.Since(start)
 runtime.ReadMemStats(&after)
 var out rBudgetReply
 _=json.Unmarshal(rec.Body.Bytes(),&out)
 delta:=uint64(0);if after.TotalAlloc>before.TotalAlloc{delta=after.TotalAlloc-before.TotalAlloc}
 return rec.Code,out,elapsed,delta
}

func TestRRealisticRPCBodyBudgets(t *testing.T){
 // JSON overhead stays below the 5 MiB server limit.
 near:=4*1024*1024+768*1024
 for _,unknown:=range []bool{false,true}{
  code,out,elapsed,alloc:=rBudgetRequest(t,near,unknown)
  if code!=http.StatusOK||out.Error!=nil||len(out.Result)==0||string(out.Result)=="null"{
   t.Fatalf("R_PARSER_NEAR_LIMIT_VALID_REQUEST_FAIL unknown=%t code=%d err=%v result=%s",unknown,code,out.Error,out.Result)
  }
  if elapsed>5*time.Second{t.Fatalf("R_PARSER_NEAR_LIMIT_WALLTIME_BREACH unknown=%t elapsed=%s",unknown,elapsed)}
  t.Logf("R_PARSER_RPC_NEAR_LIMIT_PASS unknown_length=%t elapsed=%s total_alloc_delta=%d",unknown,elapsed,alloc)
 }
 over:=5*1024*1024+64*1024
 code,out,elapsed,alloc:=rBudgetRequest(t,over,true)
 if code==http.StatusOK&&out.Error==nil&&len(out.Result)>0&&string(out.Result)!="null"{
  t.Fatalf("R_PARSER_OVERSIZE_CHUNKED_VALID_SUCCESS code=%d result=%s",code,out.Result)
 }
 if elapsed>5*time.Second{t.Fatalf("R_PARSER_OVERSIZE_WALLTIME_BREACH elapsed=%s",elapsed)}
 t.Logf("R_PARSER_RPC_OVERSIZE_FAIL_CLOSED_PASS code=%d elapsed=%s total_alloc_delta=%d",code,elapsed,alloc)
}
