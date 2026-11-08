package filters

import (
 "context"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/core/rawdb"
)

// E-RPC-017: bounded adversarial client races filter expiry with polling.
// Unlike explicit uninstall, the timeout scheduler is the competing actor.
// This test detects a stuck request; it does not establish a DoS or severity.
func TestWorkerEFilterExpiryPollingBounded(t *testing.T) {
 const rounds=24
 for i:=0;i<rounds;i++ {
  api:=NewPublicFilterAPI(&testBackend{db:rawdb.NewMemoryDatabase()},false,2*time.Millisecond,8,1)
  id,err:=api.NewFilter(FilterCriteria{})
  if err!=nil {t.Fatalf("E_EXPIRY_CREATE round=%d err=%v",i,err)}
  if i%3==0 {time.Sleep(time.Millisecond)}
  if i%3==1 {time.Sleep(2*time.Millisecond)}
  done:=make(chan error,1)
  go func(){_,e:=api.GetFilterChanges(id);done<-e}()
  select {
  case e:=<-done:
   t.Logf("E_EXPIRY_POLL round=%d error=%v",i,e)
  case <-time.After(250*time.Millisecond):
   t.Fatalf("E_EXPIRY_STUCK round=%d invariant=bounded_poll",i)
  }
  _=api.UninstallFilter(id)
 }
 _=context.Background()
}
