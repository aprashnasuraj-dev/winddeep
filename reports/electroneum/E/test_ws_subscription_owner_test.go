package rpc

import (
 "context"
 "encoding/json"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "github.com/gorilla/websocket"
)

// E-RPC-023: an untrusted second WS session must not cancel a first session's subscription.
// The service is inert and produces no chain events; this tests RPC subscription ownership only.
type workerEOwnerService struct{}
func (*workerEOwnerService) Subscribe(ctx context.Context) (*Subscription,error) {
 n,ok:=NotifierFromContext(ctx)
 if !ok { return nil, ErrNotificationsUnsupported }
 return n.CreateSubscription(),nil
}
func workerECall(t *testing.T,c *websocket.Conn,id int,method string,params ...interface{}) json.RawMessage {
 t.Helper()
 if params==nil { params=[]interface{}{} }
 if err:=c.WriteJSON(map[string]interface{}{"jsonrpc":"2.0","id":id,"method":method,"params":params});err!=nil {t.Fatal(err)}
 _=c.SetReadDeadline(time.Now().Add(3*time.Second))
 var msg struct {ID int `json:"id"`; Result json.RawMessage `json:"result"`; Error *struct{Code int;Message string} `json:"error"`}
 if err:=c.ReadJSON(&msg);err!=nil {t.Fatal(err)}
 if msg.ID!=id {t.Fatalf("E_WS_OWNER_RESPONSE_MISMATCH got=%d want=%d",msg.ID,id)}
 if msg.Error!=nil {t.Fatalf("E_WS_OWNER_RPC_ERROR method=%s code=%d message=%s",method,msg.Error.Code,msg.Error.Message)}
 return msg.Result
}
func TestWorkerEWebsocketSubscriptionOwnership(t *testing.T) {
 for state:=0;state<3;state++ {
  srv:=NewServer()
  if err:=srv.RegisterName("owner",new(workerEOwnerService));err!=nil {t.Fatal(err)}
  endpoint:=httptest.NewServer(srv.WebsocketHandler([]string{"*"}))
  url:="ws"+strings.TrimPrefix(endpoint.URL,"http")
  a,_,err:=websocket.DefaultDialer.Dial(url,nil);if err!=nil {t.Fatal(err)}
  b,_,err:=websocket.DefaultDialer.Dial(url,nil);if err!=nil {t.Fatal(err)}
  var subscription string
  if err:=json.Unmarshal(workerECall(t,a,1,"owner_subscribe"),&subscription);err!=nil {t.Fatal(err)}
  if subscription=="" {t.Fatal("empty subscription")}
  var denied bool
  if err:=json.Unmarshal(workerECall(t,b,2,"owner_unsubscribe",subscription),&denied);err!=nil {t.Fatal(err)}
  if denied {t.Fatalf("E_WS_OWNER_VIOLATION state=%d outsider canceled another connection subscription",state)}
  var ownerAllowed bool
  if err:=json.Unmarshal(workerECall(t,a,3,"owner_unsubscribe",subscription),&ownerAllowed);err!=nil {t.Fatal(err)}
  if !ownerAllowed {t.Fatalf("E_WS_OWNER_CONTROL_FAIL state=%d",state)}
  t.Logf("E_WS_OWNER_BOUNDARY state=%d outsider_canceled=%v owner_canceled=%v",state,denied,ownerAllowed)
  a.Close();b.Close();endpoint.Close();srv.Stop()
 }
}
