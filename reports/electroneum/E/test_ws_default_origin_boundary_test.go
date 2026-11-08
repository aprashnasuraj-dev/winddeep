package rpc

import (
 "net/http"
 "net/http/httptest"
 "net/url"
 "strings"
 "testing"
 "github.com/gorilla/websocket"
)

// E-RPC-022: default WebSocket origin enforcement against an untrusted website.
// This is a boundary discrimination test, not evidence of an exploitable flaw.
func TestWorkerEWebsocketDefaultOriginBoundary(t *testing.T) {
 for state, host := range []string{"outsider.invalid","other-origin.invalid","subdomain.outsider.invalid"} {
  srv:=NewServer()
  endpoint:=httptest.NewServer(srv.WebsocketHandler(nil))
  wsURL:="ws"+strings.TrimPrefix(endpoint.URL,"http")
  u,err:=url.Parse(endpoint.URL);if err!=nil {t.Fatal(err)}
  for _,tc:=range []struct{name,origin string;allow bool}{
   {"honest","http://"+u.Host,true},
   {"outsider","https://"+host,false},
  } {
   h:=http.Header{};h.Set("Origin",tc.origin)
   conn,resp,err:=websocket.DefaultDialer.Dial(wsURL,h)
   accepted:=err==nil
   if conn!=nil {conn.Close()}
   if accepted!=tc.allow {
    status:=0;if resp!=nil {status=resp.StatusCode}
    t.Fatalf("E_WS_ORIGIN_DIFFERENTIAL state=%d case=%s accepted=%v status=%d err=%v",state,tc.name,accepted,status,err)
   }
   t.Logf("E_WS_ORIGIN_BOUNDARY state=%d case=%s accepted=%v",state,tc.name,accepted)
  }
  endpoint.Close();srv.Stop()
 }
}
