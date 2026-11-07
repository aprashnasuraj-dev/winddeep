package filters

import (
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/rpc"
)

// E-RPC-008: a filter polling request must not hold the global filter lock
// indefinitely when its expiration races a poll. Synthetic isolated API only.
func TestWorkerEExpiredFilterPollDoesNotBlock(t *testing.T) {
 for _, delay := range []time.Duration{0, 2*time.Millisecond, 20*time.Millisecond} {
  t.Run(delay.String(), func(t *testing.T) {
   id := rpc.NewID()
   f := &filter{typ: BlocksSubscription, deadline: time.NewTimer(time.Millisecond)}
   api := &PublicFilterAPI{filters: map[rpc.ID]*filter{id:f}, timeout: time.Second}
   defer f.deadline.Stop()
   time.Sleep(delay)
   done := make(chan struct{})
   go func(){ defer close(done); _, _ = api.GetFilterChanges(id) }()
   select {
   case <-done:
    t.Logf("E_FILTER_EXPIRY_POLL_BOUNDARY delay=%s completed=true",delay)
   case <-time.After(500*time.Millisecond):
    t.Errorf("E_FILTER_EXPIRY_POLL_BOUNDARY delay=%s completed=false: global filter mutex may be blocked",delay)
   }
  })
 }
}
