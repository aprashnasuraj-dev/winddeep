// Independent Reverse R: certified downloader queue reset, timeout and stale peer
// reply admission. Only synthetic local receipt queues, no network or real chain.
package downloader

import (
 "sort"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
)

func TestReverseDReceiptRestartAndExpiry(t *testing.T) {
 t.Run("cancel_reset_rejects_old_reply_and_reimports",func(t *testing.T){
  f:=reverseDNewReceiptFixture(t)
  peer:=dummyPeer("reverse-reset-old-peer")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil || len(req.Headers)!=3 {t.Fatal("expected three receipt requests")}
  raw,hashes:=reverseDReceiptData(t,f,req.Headers)
  firstHashes:=append([]common.Hash(nil),hashes...)
  firstHashes[1][0]^=0x80
  n,err:=f.q.DeliverReceipts(peer.id,raw,firstHashes)
  if n!=1 || err==nil || f.q.PendingReceipts()!=2 {
   t.Fatalf("expected accepted prefix=1 and two pending; accepted=%d err=%v pending=%d",n,err,f.q.PendingReceipts())
  }
  // Save trusted headers from the old session before Reset discards all caches.
  headers:=make([]*types.Header,0,len(f.q.blockTaskPool))
  for _,header:=range f.q.blockTaskPool {headers=append(headers,header)}
  sort.Slice(headers,func(i,j int)bool{return headers[i].Number.Cmp(headers[j].Number)<0})
  if len(headers)!=6 {t.Fatalf("expected 6 scheduled chain headers, got %d",len(headers))}
  hashesByHeight:=make([]common.Hash,len(headers))
  for i,h:=range headers {hashesByHeight[i]=h.Hash()}
  f.q.Close()
  f.q.Reset(10,10)
  f.q.Prepare(1,SnapSync)
  if f.q.PendingReceipts()!=0 || f.q.InFlightReceipts() {
   t.Fatalf("stale session tasks survive reset pending=%d",f.q.PendingReceipts())
  }
  staleAccepted,staleErr:=f.q.DeliverReceipts(peer.id,raw,hashes)
  if staleErr==nil||staleAccepted!=0 {
   t.Fatalf("previous-session response accepted after reset: accepted=%d err=%v",staleAccepted,staleErr)
  }
  if got:=f.q.Schedule(headers,hashesByHeight,1);len(got)!=6 {t.Fatalf("fresh schedule incomplete got=%d",len(got))}
  if f.q.PendingReceipts()!=3 {t.Fatalf("fresh receipt tasks not restored pending=%d",f.q.PendingReceipts())}
  newPeer:=dummyPeer("reverse-reset-new-peer")
  freshReq,_,_:=f.q.ReserveReceipts(newPeer,3)
  if freshReq==nil||len(freshReq.Headers)!=3 {t.Fatal("fresh queue failed to reserve three receipt tasks")}
  freshRaw,freshHashes:=reverseDReceiptData(t,f,freshReq.Headers)
  accepted,err:=f.q.DeliverReceipts(newPeer.id,freshRaw,freshHashes)
  if accepted!=3||err!=nil||f.q.PendingReceipts()!=0 {t.Fatalf("restart failed accepted=%d err=%v pending=%d",accepted,err,f.q.PendingReceipts())}
  t.Log("REVERSE_D_RESET_OLD_PEER_REJECTED_FRESH_REIMPORT_PASS prefix=1 fresh=3")
 })
 t.Run("expiry_requeues_and_rejects_late_reply",func(t *testing.T){
  f:=reverseDNewReceiptFixture(t)
  peer:=dummyPeer("reverse-expired-peer")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3 {t.Fatal("missing expiry request")}
  raw,hashes:=reverseDReceiptData(t,f,req.Headers)
  count:=f.q.ExpireReceipts(peer.id)
  if count<=0||f.q.PendingReceipts()!=3 {
   t.Fatalf("timeout did not restore all tasks expired=%d pending=%d",count,f.q.PendingReceipts())
  }
  accepted,err:=f.q.DeliverReceipts(peer.id,raw,hashes)
  if accepted!=0||err==nil {t.Fatalf("late expired peer reply accepted count=%d err=%v",accepted,err)}
  retryPeer:=dummyPeer("reverse-after-expiry")
  again,_,_:=f.q.ReserveReceipts(retryPeer,3)
  if again==nil||len(again.Headers)!=3 {t.Fatal("after-timeout re-reservation failed")}
  freshRaw,freshHash:=reverseDReceiptData(t,f,again.Headers)
  n,e:=f.q.DeliverReceipts(retryPeer.id,freshRaw,freshHash)
  if n!=3||e!=nil||f.q.PendingReceipts()!=0 {t.Fatalf("post-timeout valid retry failed accepted=%d err=%v",n,e)}
  t.Log("REVERSE_D_EXPIRED_RESPONSE_REJECTED_RETRY_PASS")
 })
}
