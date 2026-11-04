// Worker R deep audit D1: HTTP transport -> JSON-RPC batch -> service dispatch.
// Exercises the real Server in-process, bounded generated batches and bad methods.
package rpc

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

type rDeepReply struct {
 ID json.RawMessage `json:"id"`
 Result json.RawMessage `json:"result"`
 Error *struct{Code int `json:"code"`; Message string `json:"message"`} `json:"error"`
}

func rDeepRPCBatch(t *testing.T,script []byte) {
 t.Helper()
 if len(script)>128{return}
 if len(script)==0{script=[]byte{0,1,0,1,0}}
 server:=NewServer();defer server.Stop()
 reqs:=make([]map[string]interface{},0,len(script))
 wantError:=map[int]bool{}
 for i,b:=range script {
  id:=i+1
  method:="rpc_modules"
  if b%3==1 {method="rpc_nonexistent_method"}
  if b%3==2 {method="rpc_this_does_not_exist"}
  wantError[id]=method!="rpc_modules"
  reqs=append(reqs,map[string]interface{}{"jsonrpc":"2.0","id":id,"method":method,"params":[]interface{}{}})
 }
 raw,err:=json.Marshal(reqs);if err!=nil{t.Fatal(err)}
 if len(raw)>40000{t.Fatal("generated input unexpectedly large")}
 req:=httptest.NewRequest(http.MethodPost,"http://example.invalid/rpc",bytes.NewReader(raw))
 req.Header.Set("Content-Type","application/json")
 rec:=httptest.NewRecorder()
 server.ServeHTTP(rec,req)
 if rec.Code!=http.StatusOK{t.Fatalf("R_DEEP_RPC_HTTP_STATUS: %d",rec.Code)}
 var replies []rDeepReply
 if err:=json.Unmarshal(rec.Body.Bytes(),&replies);err!=nil{t.Fatalf("R_DEEP_RPC_INVALID_JSON: %v",err)}
 if len(replies)!=len(script){t.Fatalf("R_DEEP_RPC_RESPONSE_COUNT: got=%d want=%d",len(replies),len(script))}
 seen:=make(map[int]bool,len(script))
 for _,v:=range replies {
  var id int
  if err:=json.Unmarshal(v.ID,&id);err!=nil||id<1||id>len(script) {t.Fatalf("R_DEEP_RPC_CORRELATION: id=%s err=%v",v.ID,err)}
  if seen[id]{t.Fatalf("R_DEEP_RPC_DUPLICATE_ID: %d",id)}
  seen[id]=true
  hasError:=v.Error!=nil
  hasResult:=len(v.Result)>0 && string(v.Result)!="null"
  if hasError==hasResult{t.Fatalf("R_DEEP_RPC_RESULT_ERROR_EXCLUSION: id=%d error=%v result=%s",id,v.Error,v.Result)}
  if hasError!=wantError[id]{t.Fatalf("R_DEEP_RPC_METHOD_ISOLATION: id=%d expectedError=%t got=%t",id,wantError[id],hasError)}
 }
 if len(seen)!=len(script){t.Fatalf("R_DEEP_RPC_DROPPED_ID: got=%d",len(seen))}
 t.Logf("R_DEEP_RPC_BATCH_PASS requests=%d",len(script))
}

func TestRDeepRPCBatchBaseline(t *testing.T){
 for _,seq:=range [][]byte{{0,1,2,0,1,2},{0},{1},{2},{0,0,0,1,0,2},{1,1,2,2,0,0}}{rDeepRPCBatch(t,seq)}
 // Chunked/unknown ContentLength is still bounded by HTTP codec LimitReader.
 // The result should not be a successful rpc_modules response when the
 // actual body is larger than 5 MiB, regardless of declared length.
 server:=NewServer();defer server.Stop()
 oversize:="{"jsonrpc":"2.0","id":1,"method":"rpc_modules","params":[],"extra":""+strings.Repeat("a",5*1024*1024)+""}"
 req:=httptest.NewRequest(http.MethodPost,"http://example.invalid/rpc",strings.NewReader(oversize))
 req.Header.Set("Content-Type","application/json")
 req.ContentLength=-1
 rec:=httptest.NewRecorder();server.ServeHTTP(rec,req)
 var out rDeepReply
 if json.Unmarshal(rec.Body.Bytes(),&out)==nil && out.Error==nil && len(out.Result)>0 && string(out.Result)!="null"{
  t.Fatalf("R_DEEP_CHUNKED_OVERSIZE_ACCEPTED: response=%s",rec.Body.String()[:min(len(rec.Body.String()),256)])
 }
 t.Log("R_DEEP_HTTP_UNKNOWN_LENGTH_BUDGET_CONTROL_PASS")
 // Ensure a fresh request still succeeds after rejecting an oversized one.
 rDeepRPCBatch(t,[]byte{0,1,0})
}
func FuzzRDeepRPCBatch(f *testing.F){
 f.Add([]byte{0,1,2,0,1,2})
 f.Add([]byte{1,1,1,0,2,2})
 f.Add([]byte{0,0,0,0,0})
 f.Fuzz(func(t *testing.T,input []byte){
  if len(input)>128{return}
  rDeepRPCBatch(t,input)
 })
}
var _ = fmt.Sprintf
