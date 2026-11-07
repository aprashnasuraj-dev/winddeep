package rpc

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
)

type cPublicAPI struct{}
func (*cPublicAPI) Ping() string { return "public-ok" }
type cSignerAPI struct{ calls *int }
func (a *cSignerAPI) Sign() string { *a.calls++; return "UNAUTHORIZED_SIGN" }

func TestWorkerCRPCNamespaceIsolation(t *testing.T) {
 for _,seed := range []int{11,17,23} {
  t.Run(string(rune('A'+seed%26)),func(t *testing.T){
   var calls int
   public:=NewServer()
   if err:=public.RegisterName("net",&cPublicAPI{});err!=nil{t.Fatal(err)}
   privileged:=NewServer()
   if err:=privileged.RegisterName("net",&cPublicAPI{});err!=nil{t.Fatal(err)}
   if err:=privileged.RegisterName("personal",&cSignerAPI{calls:&calls});err!=nil{t.Fatal(err)}
   invoke:=func(s *Server,method string)(int,map[string]json.RawMessage){
    t.Helper()
    payload,_:=json.Marshal(map[string]interface{}{"jsonrpc":"2.0","id":seed,"method":method,"params":[]interface{}{}})
    req:=httptest.NewRequest(http.MethodPost,"http://localhost/",bytes.NewReader(payload))
    req.Header.Set("Content-Type","application/json")
    w:=httptest.NewRecorder();s.ServeHTTP(w,req)
    var result map[string]json.RawMessage
    if err:=json.Unmarshal(w.Body.Bytes(),&result);err!=nil{t.Fatalf("bad JSON response %s: %v",w.Body.String(),err)}
    return w.Code,result
   }
   status,baseline:=invoke(public,"net_ping")
   if status!=200||string(baseline["result"])!="\"public-ok\""{t.Fatalf("public baseline: %d %v",status,baseline)}
   status,attack:=invoke(public,"personal_sign")
   if status!=200||attack["error"]==nil||attack["result"]!=nil||calls!=0{t.Fatalf("public signer access: %d %v calls=%d",status,attack,calls)}
   t.Logf("C_RPC_PUBLIC_SIGNER_REJECTED seed=%d calls=%d",seed,calls)
   status,positive:=invoke(privileged,"personal_sign")
   if status!=200||string(positive["result"])!="\"UNAUTHORIZED_SIGN\""||calls!=1{t.Fatalf("privileged control: %d %v calls=%d",status,positive,calls)}
   t.Logf("C_RPC_PRIVILEGED_CONTROL seed=%d calls=%d",seed,calls)
   _,again:=invoke(public,"personal_sign")
   if again["error"]==nil||calls!=1{t.Fatalf("cross-server namespace leak: %v calls=%d",again,calls)}
   t.Logf("C_RPC_CROSS_SERVER_ISOLATION seed=%d calls=%d",seed,calls)
  })
 }
}

 
// TestWorkerCRPCBatchNamespaceBoundary checks a separate ingress mechanism:
// a mixed JSON-RPC batch must not inherit privileged method registration from
// another server or from a neighboring public request in the same batch.
func TestWorkerCRPCBatchNamespaceBoundary(t *testing.T) {
 for _, seed := range []int{31, 47, 59} {
  t.Run(string(rune('A'+seed%26)), func(t *testing.T) {
   var calls int
   public := NewServer()
   if err := public.RegisterName("net", &cPublicAPI{}); err != nil { t.Fatal(err) }
   privileged := NewServer()
   if err := privileged.RegisterName("personal", &cSignerAPI{calls:&calls}); err != nil { t.Fatal(err) }
   payload, err := json.Marshal([]map[string]interface{}{
    {"jsonrpc":"2.0","id":seed,"method":"net_ping","params":[]interface{}{}},
    {"jsonrpc":"2.0","id":seed+1,"method":"personal_sign","params":[]interface{}{}},
    {"jsonrpc":"2.0","id":seed+2,"method":"net_ping","params":[]interface{}{}},
   })
   if err != nil { t.Fatal(err) }
   invoke := func(s *Server) []map[string]json.RawMessage {
    t.Helper()
    req := httptest.NewRequest(http.MethodPost, "http://localhost/", bytes.NewReader(payload))
    req.Header.Set("Content-Type","application/json")
    w := httptest.NewRecorder()
    s.ServeHTTP(w,req)
    if w.Code != http.StatusOK { t.Fatalf("batch HTTP status=%d body=%s",w.Code,w.Body.String()) }
    var responses []map[string]json.RawMessage
    if err := json.Unmarshal(w.Body.Bytes(), &responses); err != nil { t.Fatalf("batch JSON: %v body=%s",err,w.Body.String()) }
    if len(responses)!=3 { t.Fatalf("batch response count=%d",len(responses)) }
    return responses
   }
   response := invoke(public)
   if string(response[0]["result"]) != `"public-ok"` || string(response[2]["result"]) != `"public-ok"` { t.Fatalf("public batch controls: %v",response) }
   if response[1]["error"] == nil || response[1]["result"] != nil || calls != 0 { t.Fatalf("C_RPC_BATCH_UNAUTHORIZED_SIGNER_CALL seed=%d calls=%d response=%v",seed,calls,response[1]) }
   t.Logf("C_RPC_BATCH_SIGNER_REJECTED seed=%d calls=%d",seed,calls)
   // Strong negative control: a separately registered privileged server
   // may invoke the method; this does not imply public exposure.
   controlPayload := []byte(`{"jsonrpc":"2.0","id":1,"method":"personal_sign","params":[]}`)
   req := httptest.NewRequest(http.MethodPost,"http://localhost/",bytes.NewReader(controlPayload))
   req.Header.Set("Content-Type","application/json")
   w := httptest.NewRecorder()
   privileged.ServeHTTP(w,req)
   var control map[string]json.RawMessage
   if err := json.Unmarshal(w.Body.Bytes(),&control);err!=nil{t.Fatal(err)}
   if string(control["result"]) != `"UNAUTHORIZED_SIGN"` || calls!=1 { t.Fatalf("privileged batch control failed: %v calls=%d",control,calls) }
   t.Logf("C_RPC_BATCH_PRIVILEGED_CONTROL seed=%d calls=%d",seed,calls)
  })
 }
}
