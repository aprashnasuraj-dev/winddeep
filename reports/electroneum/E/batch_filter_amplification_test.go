package filters

// Isolated, bounded security regression experiment for the *real* Electroneum
// HTTP JSON-RPC server and filter manager. This never contacts a live network.
import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "runtime"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/rpc"
)

func TestBatchFilterAmplificationHTTPRealTarget(t *testing.T) {
 backend := &testBackend{}
 api := NewPublicFilterAPI(backend, false, 5*time.Minute, 1000, 0)
 server := rpc.NewServer()
 defer server.Stop()
 if err:=server.RegisterName("eth", api); err!=nil { t.Fatal(err) }
 baselineG := runtime.NumGoroutine()
 var beforeMem runtime.MemStats
 runtime.ReadMemStats(&beforeMem)
 var allIDs []rpc.ID
 for _, n:=range []int{1, 16, 128, 512} {
  batch:=make([]map[string]interface{},n)
  for i:=range batch {
   batch[i]=map[string]interface{}{
    "jsonrpc":"2.0","method":"eth_newBlockFilter",
    "params":[]interface{}{},"id":i+1,
   }
  }
  body,err:=json.Marshal(batch)
  if err!=nil {t.Fatal(err)}
  req:=httptest.NewRequest(http.MethodPost,"http://127.0.0.1/",bytes.NewReader(body))
  req.Header.Set("Content-Type","application/json")
  resp:=httptest.NewRecorder()
  server.ServeHTTP(resp,req)
  if resp.Code!=http.StatusOK {t.Fatalf("HTTP status=%d body=%s",resp.Code,resp.Body.String())}
  var answers []struct {
   Result rpc.ID `json:"result"`
   Error json.RawMessage `json:"error"`
  }
  if err:=json.Unmarshal(resp.Body.Bytes(),&answers); err!=nil {t.Fatalf("JSON replies: %v body=%s",err,resp.Body.String())}
  if len(answers)!=n {t.Fatalf("responses=%d want=%d",len(answers),n)}
  for _,v:=range answers {
   if len(v.Error)>0 && string(v.Error)!="null" {t.Fatalf("RPC error: %s",string(v.Error))}
   if v.Result=="" {t.Fatal("empty filter id")}
   allIDs=append(allIDs,v.Result)
  }
  api.filtersMu.Lock()
  held:=len(api.filters)
  api.filtersMu.Unlock()
  if held!=len(allIDs) {t.Fatalf("batch=%d accepted=%d held=%d",n,len(allIDs),held)}
  t.Logf("REAL_ETN_HTTP_BATCH_ACCEPTED batch=%d request_bytes=%d persistent_filters=%d goroutines_now=%d",n,len(body),held,runtime.NumGoroutine())
 }
 peak:=runtime.NumGoroutine()
 var peakMem runtime.MemStats
 runtime.ReadMemStats(&peakMem)
 t.Logf("REAL_ETN_MEMORY_ACCOUNTING stack_inuse_before=%d stack_inuse_peak=%d stack_delta=%d heap_alloc_before=%d heap_alloc_peak=%d heap_delta=%d", beforeMem.StackInuse, peakMem.StackInuse, int64(peakMem.StackInuse)-int64(beforeMem.StackInuse), beforeMem.HeapAlloc, peakMem.HeapAlloc, int64(peakMem.HeapAlloc)-int64(beforeMem.HeapAlloc))
 if peak <= baselineG+100 {t.Logf("GOROUTINE_SAMPLE_NONDETERMINISTIC baseline=%d peak=%d",baselineG,peak)} else {
  t.Logf("REAL_ETN_FILTER_WORKER_AMPLIFICATION baseline_goroutines=%d peak_goroutines=%d delta=%d persistent_filters=%d",baselineG,peak,peak-baselineG,len(allIDs))
 }
 // Defeating control: normal explicit unsubscribe releases state. A remote
 // caller can simply not unsubscribe and need not hold the HTTP connection.
 for _,id:=range allIDs {
  if !api.UninstallFilter(id) {t.Fatalf("failed cleanup id=%s",id)}
 }
 api.filtersMu.Lock()
 remains:=len(api.filters)
 api.filtersMu.Unlock()
 if remains!=0 {t.Fatalf("cleanup failure retained=%d",remains)}
 t.Logf("REAL_ETN_EXPLICIT_UNINSTALL_CLEANUP_PASS filters=%d",remains)

 // Existing query-count guard is real, but protects addresses/topics
 // within a single log query, not batch count or number of filter calls.
 if err:=CheckLogQueryLimit(1000,make([]common.Address,1001),nil);err==nil{
  t.Fatal("configured log query cap not enforced")
 }
 t.Logf("REAL_ETN_PER_QUERY_ADDRESS_CAP_CONTROL_PASS cap=%d over=%d",1000,1001)
 if len(allIDs)!=657 {t.Fatal(fmt.Sprintf("unexpected count %d",len(allIDs)))}
}
