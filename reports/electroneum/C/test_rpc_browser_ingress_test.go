package rpc

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
)

// C_BROWSER_INGRESS: a browser-reachable simple request must not execute
// a privileged RPC method. This is an ingress check, not proof of default
// personal namespace exposure or a canonical unauthorized spend.
type cBrowserSignerAPI struct { calls *int }
func (a *cBrowserSignerAPI) Sign() string { *a.calls = *a.calls + 1; return "UNAUTHORIZED_SIGN" }

func TestWorkerCBrowserSimpleRequestBoundary(t *testing.T) {
 for _, seed := range []int{61,67,71} {
  t.Run(string(rune('A'+seed%26)),func(t *testing.T){
   var calls int
   srv:=NewServer()
   if err:=srv.RegisterName("personal",&cBrowserSignerAPI{calls:&calls});err!=nil{t.Fatal(err)}
   payload:=[]byte(`{"jsonrpc":"2.0","id":1,"method":"personal_sign","params":[]}`)
   invoke:=func(method,ctype string)(int,string){
    t.Helper()
    req:=httptest.NewRequest(method,"http://localhost/",bytes.NewReader(payload))
    req.Header.Set("Origin","https://attacker.example")
    if ctype!=""{req.Header.Set("Content-Type",ctype)}
    w:=httptest.NewRecorder();srv.ServeHTTP(w,req)
    return w.Code,w.Body.String()
   }
   for _,tc:=range []struct{method,ctype string}{
    {http.MethodGet,""},{http.MethodPost,"text/plain"},
    {http.MethodPost,"application/x-www-form-urlencoded"},
   }{
    before:=calls
    status,body:=invoke(tc.method,tc.ctype)
    if calls!=before {t.Fatalf("C_BROWSER_SIMPLE_REQUEST_BREACH method=%s type=%s status=%d calls=%d body=%s",tc.method,tc.ctype,status,calls,body)}
    t.Logf("C_BROWSER_SIMPLE_REJECTED seed=%d method=%s type=%s status=%d calls=%d",seed,tc.method,tc.ctype,status,calls)
   }
   status,body:=invoke(http.MethodPost,"application/json")
   var response map[string]json.RawMessage
   if err:=json.Unmarshal([]byte(body),&response);err!=nil{t.Fatalf("control invalid response: %v body=%s",err,body)}
   if status!=http.StatusOK || string(response["result"])!=`"UNAUTHORIZED_SIGN"` || calls!=1 {
    t.Fatalf("C_BROWSER_CONTROL_FAILED status=%d calls=%d body=%s",status,calls,body)
   }
   t.Logf("C_BROWSER_JSON_CONTROL seed=%d calls=%d",seed,calls)
  })
 }
}
