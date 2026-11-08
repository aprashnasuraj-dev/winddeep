package rpc

import (
 "encoding/json"
 "fmt"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
 "github.com/gorilla/websocket"
)

type eReconnectService struct{}
func (*eReconnectService) Echo(v string) string { return v }

// E-RPC-021: a new WS connection must never inherit another connection's
// response or notification stream, even when JSON-RPC identifiers are reused.
func TestWorkerEWebsocketReconnectIsolation(t *testing.T) {
 server:=NewServer(); defer server.Stop()
 if err:=server.RegisterName("ereconnect",&eReconnectService{});err!=nil {t.Fatal(err)}
 endpoint:=httptest.NewServer(server.WebsocketHandler([]string{"*"}));defer endpoint.Close()
 wsURL:="ws"+strings.TrimPrefix(endpoint.URL,"http")
 for state:=0;state<3;state++ {
  var previous *websocket.Conn
  for session:=0;session<3;session++ {
   c,_,err:=websocket.DefaultDialer.Dial(wsURL,nil)
   if err!=nil {t.Fatal(err)}
   if previous!=nil {previous.Close()}
   previous=c
   expected:=fmt.Sprintf("state-%d-session-%d",state,session)
   // Deliberately reuse id=1 across fresh connections.
   request:=fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"ereconnect_echo","params":[%q]}`,expected)
   if err:=c.WriteMessage(websocket.TextMessage,[]byte(request));err!=nil {t.Fatal(err)}
   c.SetReadDeadline(time.Now().Add(3*time.Second))
   _,data,err:=c.ReadMessage();if err!=nil {t.Fatal(err)}
   var got struct {ID int `json:"id"`;Result string `json:"result"`;Error json.RawMessage `json:"error"`}
   if err:=json.Unmarshal(data,&got);err!=nil {t.Fatalf("decode %s: %v",data,err)}
   if got.ID!=1||got.Result!=expected||(len(got.Error)>0&&string(got.Error)!="null") {
    t.Fatalf("E_WS_RECONNECT_DIFFERENTIAL state=%d session=%d got=%s want=%s",state,session,data,expected)
   }
  }
  previous.Close()
  t.Logf("E_WS_RECONNECT state=%d reconnects=3 response-isolation=held",state)
 }
}
