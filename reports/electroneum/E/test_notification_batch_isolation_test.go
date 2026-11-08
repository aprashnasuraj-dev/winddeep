package rpc

import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "net/http/httptest"
 "sync"
 "testing"
)

type eNotifyService struct{}
func (*eNotifyService) Echo(v string) string { return v }

// E-RPC-020: a JSON-RPC notification has no id and must never yield a
// response or consume the adjacent ordinary request's response slot.
func TestWorkerEMixedNotificationBatchIsolation(t *testing.T) {
 srv:=NewServer(); defer srv.Stop()
 if err:=srv.RegisterName("enotify",&eNotifyService{});err!=nil {t.Fatal(err)}
 endpoint:=httptest.NewServer(srv); defer endpoint.Close()
 client:=&http.Client{}
 for state:=0;state<3;state++ {
  var wg sync.WaitGroup
  failures:=make(chan string,12)
  for worker:=0;worker<4;worker++ {
   wg.Add(1)
   go func(worker int) {
    defer wg.Done()
    for step:=0;step<3;step++ {
     value:=fmt.Sprintf("s%d-w%d-step%d",state,worker,step)
     payload:=fmt.Sprintf(`[{"jsonrpc":"2.0","method":"enotify_echo","params":["notify-%s"]},{"jsonrpc":"2.0","id":%d,"method":"enotify_echo","params":[%q]}]`,value,worker+1,value)
     resp,err:=client.Post(endpoint.URL,"application/json",bytes.NewBufferString(payload))
     if err!=nil {failures<-fmt.Sprintf("http %v",err);continue}
     body,err:=io.ReadAll(io.LimitReader(resp.Body,4096));resp.Body.Close()
     if err!=nil {failures<-fmt.Sprintf("read %v",err);continue}
     var items []struct {ID int `json:"id"`; Result string `json:"result"`; Error json.RawMessage `json:"error"`}
     if err:=json.Unmarshal(body,&items);err!=nil {failures<-fmt.Sprintf("decode %q %v",body,err);continue}
     if len(items)!=1||items[0].ID!=worker+1||items[0].Result!=value||len(items[0].Error)>0&&string(items[0].Error)!="null" {
      failures<-fmt.Sprintf("state=%d worker=%d response=%s",state,worker,body)
     }
    }
   }(worker)
  }
  wg.Wait();close(failures)
  for failure:=range failures {t.Errorf("E_NOTIFICATION_DIFFERENTIAL %s",failure)}
  if t.Failed(){return}
  t.Logf("E_NOTIFICATION_BATCH state=%d honest=12 notification=12 response-isolation=held",state)
 }
}
