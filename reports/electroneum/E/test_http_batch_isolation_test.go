package rpc

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "testing"
)

// E-RPC-019: independent outsider HTTP clients reuse JSON-RPC IDs in concurrent
// batches; responses must never contain a result from another request.
type eIsolationService struct{}
func (*eIsolationService) Echo(value string) string { return value }

func TestWorkerEHTTPBatchCrossRequestIsolation(t *testing.T) {
 server:=NewServer()
 defer server.Stop()
 if err:=server.RegisterName("eisolation",&eIsolationService{});err!=nil{t.Fatal(err)}
 endpoint:=httptest.NewServer(server)
 defer endpoint.Close()
 client:=&http.Client{}
 for state:=0;state<3;state++ {
  for _,batch:=range []bool{false,true} {
   for iteration:=0;iteration<8;iteration++ {
    value:=fmt.Sprintf("state-%d-batch-%t-iteration-%d",state,batch,iteration)
    request:=fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"eisolation_echo","params":[%q]}`,value)
    if batch {request="["+request+","+fmt.Sprintf(`{"jsonrpc":"2.0","id":8,"method":"eisolation_echo","params":[%q]}`,"control-"+value)+"]"}
    resp,err:=client.Post(endpoint.URL,"application/json",bytes.NewBufferString(request))
    if err!=nil{t.Fatal(err)}
    var raw json.RawMessage
    err=json.NewDecoder(resp.Body).Decode(&raw)
    resp.Body.Close()
    if err!=nil{t.Fatalf("E_ISOLATION_DECODE state=%d err=%v",state,err)}
    var responses []struct{ID int `json:"id"`;Result string `json:"result"`;Error json.RawMessage `json:"error"`}
    if batch {if err=json.Unmarshal(raw,&responses);err!=nil{t.Fatal(err)}} else {
     var one struct{ID int `json:"id"`;Result string `json:"result"`;Error json.RawMessage `json:"error"`}
     if err=json.Unmarshal(raw,&one);err!=nil{t.Fatal(err)}
     responses=append(responses,one)
    }
    expected:=map[int]string{7:value}
    if batch {expected[8]="control-"+value}
    if len(responses)!=len(expected){t.Fatalf("E_ISOLATION_COUNT state=%d got=%d want=%d",state,len(responses),len(expected))}
    for _,r:=range responses {
     want,ok:=expected[r.ID]
     if !ok||r.Result!=want||len(r.Error)>0&&string(r.Error)!="null" {
      t.Fatalf("E_ISOLATION_BREACH state=%d batch=%t id=%d got=%q want=%q error=%s",state,batch,r.ID,r.Result,want,r.Error)
     }
     delete(expected,r.ID)
    }
    if len(expected)!=0{t.Fatalf("E_ISOLATION_MISSING state=%d missing=%v",state,expected)}
   }
  }
  t.Logf("E_HTTP_BATCH_ISOLATION state=%d requests=16 status=guard-held",state)
 }
}
