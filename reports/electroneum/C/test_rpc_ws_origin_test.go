package rpc

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
 "github.com/gorilla/websocket"
)

type cWSOriginSigner struct { calls *int }
func (a *cWSOriginSigner) Sign() string { *a.calls++; return "SIGN_CALLED" }

// This checks origin enforcement before RPC dispatch. It does not establish
// production-default privileged namespace exposure.
func TestWorkerCWSOriginDispatchBoundary(t *testing.T) {
 for _, seed := range []int{101,103,107} {
  t.Run(string(rune('A'+seed%26)),func(t *testing.T) {
   calls:=0
   srv:=NewServer()
   if err:=srv.RegisterName("personal",&cWSOriginSigner{calls:&calls});err!=nil{t.Fatal(err)}
   ts:=httptest.NewServer(srv.WebsocketHandler([]string{"https://trusted.example"}))
   defer ts.Close()
   endpoint:="ws"+strings.TrimPrefix(ts.URL,"http")
   dial:=func(origin string)(*websocket.Conn,*http.Response,error){
    header:=http.Header{}
    if origin!="" {header.Set("Origin",origin)}
    d:=websocket.Dialer{HandshakeTimeout:3*time.Second}
    return d.Dial(endpoint,header)
   }
   for _,origin:=range []string{"https://attacker.example","null","https://trusted.example.attacker.example"}{
    conn,resp,err:=dial(origin)
    if conn!=nil {conn.Close()}
    if err==nil {t.Fatalf("C_WS_ORIGIN_BREACH seed=%d origin=%s",seed,origin)}
    if resp==nil || resp.StatusCode!=http.StatusForbidden {t.Fatalf("C_WS_UNEXPECTED_REJECTION seed=%d origin=%s status=%v err=%v",seed,origin,resp,err)}
    if calls!=0 {t.Fatalf("C_WS_HANDLER_INVOKED seed=%d origin=%s calls=%d",seed,origin,calls)}
    t.Logf("C_WS_ORIGIN_REJECTED seed=%d origin=%s status=%d calls=%d",seed,origin,resp.StatusCode,calls)
   }
   conn,_,err:=dial("https://trusted.example")
   if err!=nil {t.Fatal(err)}
   defer conn.Close()
   if err:=conn.WriteJSON(map[string]interface{}{"jsonrpc":"2.0","id":1,"method":"personal_sign","params":[]interface{}{}});err!=nil{t.Fatal(err)}
   var result map[string]interface{}
   conn.SetReadDeadline(time.Now().Add(3*time.Second))
   if err:=conn.ReadJSON(&result);err!=nil{t.Fatal(err)}
   if result["result"]!="SIGN_CALLED" || calls!=1 {t.Fatalf("C_WS_CONTROL_FAIL result=%v calls=%d",result,calls)}
   t.Logf("C_WS_ALLOWED_CONTROL seed=%d calls=%d",seed,calls)
  })
 }
}
