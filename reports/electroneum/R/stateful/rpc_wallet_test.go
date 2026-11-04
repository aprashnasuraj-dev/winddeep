// Certified-source, in-process RPC-to-wallet boundary fuzz.
// Imported into scratch internal/ethapi alongside reverse_c_personal_rpc_test.go.
// Forced personal registration is deliberate: it tests handler-to-wallet behavior,
// NOT exposure by default network listeners. All credentials are synthetic.
package ethapi

import (
 "bytes"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/accounts"
 "github.com/electroneum/electroneum-sc/rpc"
)

const auditRSyntheticPassword = "R_AUDIT_FAKE_PASSWORD_NOT_A_REAL_SECRET"

type auditRWallet struct {
 reverseCWallet
 opens int
}
func (w *auditRWallet) Open(passphrase string) error {
 if passphrase!=auditRSyntheticPassword{return errors.New("synthetic wallet denied unexpected passphrase")}
 w.opens++
 return nil
}
type auditRRPCReply struct {
 JSONRPC string          `json:"jsonrpc"`
 ID      json.RawMessage `json:"id"`
 Result  json.RawMessage `json:"result"`
 Error   *struct{
   Code int `json:"code"`
   Message string `json:"message"`
 } `json:"error"`
}

func auditRCallRPC(t *testing.T, s *rpc.Server, id int, method string, params []interface{}) auditRRPCReply {
 t.Helper()
 body,err:=json.Marshal(map[string]interface{}{"jsonrpc":"2.0","id":id,"method":method,"params":params})
 if err!=nil{t.Fatal(err)}
 req:=httptest.NewRequest(http.MethodPost,"http://127.0.0.1/rpc",bytes.NewReader(body))
 req.Header.Set("Content-Type","application/json")
 rec:=httptest.NewRecorder()
 s.ServeHTTP(rec,req)
 if rec.Code!=http.StatusOK{t.Fatalf("RPC HTTP status=%d body=%s",rec.Code,rec.Body.String())}
 if strings.Contains(rec.Body.String(),auditRSyntheticPassword){t.Fatal("R_WALLET_CONFIDENTIALITY_FAIL: fake passphrase leaked into RPC response")}
 var reply auditRRPCReply
 if err:=json.Unmarshal(rec.Body.Bytes(),&reply);err!=nil{t.Fatalf("invalid RPC response: %v data=%s",err,rec.Body.String())}
 if reply.JSONRPC!="2.0" || string(reply.ID)!=string(json.RawMessage([]byte(strings.TrimSpace(string(mustRMarshal(id)))))){t.Fatalf("RPC response correlation invalid id=%s expect=%d version=%q",reply.ID,id,reply.JSONRPC)}
 return reply
}
func mustRMarshal(x int) []byte{v,_:=json.Marshal(x);return v}
func auditRWalletScenario(t *testing.T, script []byte) {
 t.Helper()
 u:=accounts.URL{Scheme:"reverse",Path:"unsupported"}
 wallet:=&auditRWallet{reverseCWallet:reverseCWallet{url:u}}
 am:=accounts.NewManager(&accounts.Config{},&reverseCWalletBackend{wallets:[]accounts.Wallet{wallet}})
 defer am.Close()
 api:=NewPrivateAccountAPI(&reverseCEthBackend{am:am},new(AddrLocker))
 server:=rpc.NewServer();defer server.Stop()
 if err:=server.RegisterName("personal",api);err!=nil{t.Fatalf("real PrivateAccountAPI RPC registration failed: %v",err)}
 actions:=script
 if len(actions)==0{actions=[]byte{0,1,2,3,4}}
 if len(actions)>24{actions=actions[:24]}
 expectedOpenCount:=0
 for i,raw:=range actions {
  action:=raw%5
  var method string
  var args []interface{}
  expectError:=false
  switch action{
  case 0:
   method="personal_initializeWallet";args=[]interface{}{"reverse://missing"};expectError=true
  case 1:
   method="personal_initializeWallet";args=[]interface{}{u.String()};expectError=true
  case 2:
   method="personal_openWallet";args=[]interface{}{u.String(),auditRSyntheticPassword}
  case 3:
   method="personal_openWallet";args=[]interface{}{"reverse://missing",auditRSyntheticPassword};expectError=true
  case 4:
   method="personal_listWallets";args=[]interface{}{}
  }
  response:=auditRCallRPC(t,server,i+1,method,args)
  if expectError {
   if response.Error==nil{t.Fatalf("R_WALLET_FAIL_CLOSED_FAIL: action=%d expected error, got result=%s",action,response.Result)}
   if len(response.Result)>0&&string(response.Result)!="null"{t.Fatalf("R_WALLET_ERROR_RESULT_LEAK: action=%d returned result=%s",action,response.Result)}
  }else if response.Error!=nil {
   t.Fatalf("valid action=%d unexpectedly failed: %s",action,response.Error.Message)
  }
  if action==2{expectedOpenCount++}
  if wallet.opens!=expectedOpenCount{t.Fatalf("wallet state mismatch opens=%d expected=%d action=%d",wallet.opens,expectedOpenCount,action)}
 }
 t.Logf("R_WALLET_RPC_STATEFUL_BOUNDARY_PASS actions=%d real_wallet_opens=%d",len(actions),wallet.opens)
}
func TestRWalletRPCStatefulControls(t *testing.T){
 for _,seq:=range [][]byte{{0,1,2,3,4},{2,2,3,1,4},{4,3,0,2,1,3,4}}{auditRWalletScenario(t,seq)}
}
func FuzzRWalletRPCSequence(f *testing.F){
 f.Add([]byte{0,1,2,3,4})
 f.Add([]byte{2,2,2,0,1,3,4})
 f.Add([]byte{4,4,1,3,2,0})
 f.Fuzz(func(t *testing.T, script []byte){
  if len(script)>96{return}
  auditRWalletScenario(t,script)
 })
}
