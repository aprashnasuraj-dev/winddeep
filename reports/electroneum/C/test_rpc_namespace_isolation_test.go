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
