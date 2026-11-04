// Peer reservation -> receipt RLP -> queue -> revoke/expire/reset state fuzz.
// No sockets or live network. Uses certified queue and trusted header roots.
package downloader

import (
 "fmt"
 "sort"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
)

func auditRDownloaderScenario(t *testing.T, sequence []byte) {
 t.Helper()
 if len(sequence)==0{sequence=[]byte{0,1,2,3,4,5}}
 if len(sequence)>20{sequence=sequence[:20]}
 f:=reverseDNewReceiptFixture(t)
 // Preserve six source-generated headers for reset/replay transitions.
 headers:=make([]*types.Header,0,len(f.q.blockTaskPool))
 for _,header:=range f.q.blockTaskPool{headers=append(headers,header)}
 sort.Slice(headers,func(i,j int)bool{return headers[i].Number.Cmp(headers[j].Number)<0})
 if len(headers)!=6{t.Fatalf("invalid receipt chain fixture headers=%d",len(headers))}
 hashes:=make([]common.Hash,len(headers))
 for i,h:=range headers{hashes[i]=h.Hash()}
 var activeID string
 var savedRaw []rlp.RawValue
 var savedHashes []common.Hash
 serial:=0
 reserve:=func(){
  if activeID!=""||f.q.PendingReceipts()==0{return}
  serial++
  p:=dummyPeer(fmt.Sprintf("r-fuzz-peer-%d",serial))
  req,_,_:=f.q.ReserveReceipts(p,3)
  if req==nil{return}
  activeID=p.id
  savedRaw,savedHashes=reverseDReceiptData(t,f,req.Headers)
 }
 rejectStale:=func(id string,raw []rlp.RawValue,digests []common.Hash){
  n,err:=f.q.DeliverReceipts(id,raw,digests)
  if err==nil||n!=0{t.Fatalf("R_DOWNLOADER_STALE_RESPONSE_ADMITTED: peer=%s count=%d err=%v",id,n,err)}
 }
 for step,b:=range sequence {
  if f.q.PendingReceipts()<0||f.q.PendingReceipts()>3{t.Fatalf("queue pending invariant before step=%d pending=%d",step,f.q.PendingReceipts())}
  reserve()
  switch b%6{
  case 0: // Revoke active peer and forbid stale delivery
   if activeID!="" {
    id:=activeID; raw:=savedRaw; hs:=savedHashes
    f.q.Revoke(id); activeID="";rejectStale(id,raw,hs)
   }
  case 1: // Expire inflight session, reject late reply
   if activeID!=""{
    id:=activeID;raw:=savedRaw;hs:=savedHashes
    count:=f.q.ExpireReceipts(id)
    if count<1{t.Fatalf("expired inflight peer %s without requeue",id)}
    activeID="";rejectStale(id,raw,hs)
   }
  case 2: // Honest receipt delivery and duplicate/replay rejection
   if activeID!=""{
    id:=activeID;raw:=savedRaw;hs:=savedHashes
    count,err:=f.q.DeliverReceipts(id,raw,hs)
    if err!=nil||count!=len(raw){t.Fatalf("R_DOWNLOADER_VALID_DELIVERY_FAIL: count=%d want=%d err=%v",count,len(raw),err)}
    activeID="";rejectStale(id,raw,hs)
   }
  case 3: // Poison receipt commitment: reject, requeue valid prefix/suffix
   if activeID!=""{
    hs:=append([]common.Hash(nil),savedHashes...)
    hs[0][0]^=0x40
    count,err:=f.q.DeliverReceipts(activeID,savedRaw,hs)
    if err==nil||count!=0{t.Fatalf("R_DOWNLOADER_BAD_COMMITMENT_ADMITTED: n=%d err=%v",count,err)}
    activeID=""
   }
  case 4: // Malformed RLP, followed by future honest recovery
   if activeID!=""{
    raw:=append([]rlp.RawValue(nil),savedRaw...)
    raw[0]=rlp.RawValue{0xff}
    count,err:=f.q.DeliverReceipts(activeID,raw,savedHashes)
    if err==nil||count!=0{t.Fatalf("R_DOWNLOADER_MALFORMED_RLP_ADMITTED: n=%d err=%v",count,err)}
    activeID=""
   }
  case 5: // Simulate cancelled download restart
   oldID:=activeID;oldRaw:=savedRaw;oldHashes:=savedHashes
   f.q.Close()
   f.q.Reset(10,10)
   f.q.Prepare(1,SnapSync)
   if f.q.PendingReceipts()!=0||f.q.InFlightReceipts(){t.Fatalf("R_DOWNLOADER_RESET_KEPT_INFLIGHT: pending=%d",f.q.PendingReceipts())}
   if oldID!=""{rejectStale(oldID,oldRaw,oldHashes)}
   if got:=f.q.Schedule(headers,hashes,1);len(got)!=6{t.Fatalf("restart replay lost headers: got=%d",len(got))}
   if f.q.PendingReceipts()!=3{t.Fatalf("restart failed to recover receipt tasks=%d",f.q.PendingReceipts())}
   activeID=""
  }
  if f.q.PendingReceipts()<0||f.q.PendingReceipts()>3{t.Fatalf("queue pending invariant after step=%d pending=%d",step,f.q.PendingReceipts())}
 }
 // Every generated action sequence must eventually recover valid receipts.
 if activeID!=""{f.q.Revoke(activeID);activeID=""}
 for attempts:=0;attempts<8&&f.q.PendingReceipts()>0;attempts++{
  reserve()
  if activeID==""{t.Fatalf("R_DOWNLOADER_STUCK_PENDING_TASKS: pending=%d",f.q.PendingReceipts())}
  id:=activeID;raw:=savedRaw;hs:=savedHashes
  count,err:=f.q.DeliverReceipts(id,raw,hs)
  if err!=nil||count!=len(raw){t.Fatalf("R_DOWNLOADER_RETRY_RECOVERY_FAIL: count=%d want=%d err=%v",count,len(raw),err)}
  activeID="";rejectStale(id,raw,hs)
 }
 if f.q.PendingReceipts()!=0||f.q.InFlightReceipts(){t.Fatalf("R_DOWNLOADER_FINAL_LIVENESS_FAIL: pending=%d inflight=%v",f.q.PendingReceipts(),f.q.InFlightReceipts())}
 t.Logf("R_DOWNLOADER_STATEFUL_RECOVERY_PASS steps=%d",len(sequence))
}
func TestRDownloaderStatefulControls(t *testing.T){
 auditRConcurrentPeerRace(t)
 for _,s:=range [][]byte{{0,2,1,2},{1,0,5,2},{3,4,5,2},{2,2,5,1,2}}{auditRDownloaderScenario(t,s)}
}
func FuzzRDownloaderCancelRace(f *testing.F){
 f.Add([]byte{0,1,2,3,4,5})
 f.Add([]byte{5,1,0,3,4,2})
 f.Add([]byte{3,4,2,5,5,2})
 f.Fuzz(func(t *testing.T,sequence []byte){
  if len(sequence)>48{return}
  auditRDownloaderScenario(t,sequence)
 })
}

// Concurrent cancellation-vs-delivery linearizability. Both operations enter
// from one barrier, so either winning order is allowed, but no lost work or
// double-acceptance is allowed. Run with -race to detect unsynchronized access.
func auditRConcurrentPeerRace(t *testing.T) {
 t.Helper()
 for round:=0;round<24;round++{
  f:=reverseDNewReceiptFixture(t)
  peer:=dummyPeer(fmt.Sprintf("r-concurrent-peer-%d",round))
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3{t.Fatal("race fixture failed to reserve 3 receipt tasks")}
  raw,hashes:=reverseDReceiptData(t,f,req.Headers)
  start:=make(chan struct{})
  done:=make(chan struct{},2)
  var accepted int
  var deliverErr error
  go func(){
   <-start
   if round%2==0{f.q.Revoke(peer.id)}else{f.q.ExpireReceipts(peer.id)}
   done<-struct{}{}
  }()
  go func(){
   <-start
   accepted,deliverErr=f.q.DeliverReceipts(peer.id,raw,hashes)
   done<-struct{}{}
  }()
  close(start);<-done;<-done
  pending:=f.q.PendingReceipts()
  if accepted==3{
   if deliverErr!=nil||pending!=0{
    t.Fatalf("R_DOWNLOADER_CONCURRENT_DOUBLE_SPEND: delivered=3 pending=%d err=%v",pending,deliverErr)
   }
  }else if accepted==0{
   if deliverErr==nil||pending!=3{
    t.Fatalf("R_DOWNLOADER_CONCURRENT_LOST_WORK: rejected delivery pending=%d err=%v",pending,deliverErr)
   }
   retry:=dummyPeer(fmt.Sprintf("r-concurrent-retry-%d",round))
   req2,_,_:=f.q.ReserveReceipts(retry,3)
   if req2==nil||len(req2.Headers)!=3{t.Fatal("requeued tasks unavailable after concurrent revoke")}
   raw2,h2:=reverseDReceiptData(t,f,req2.Headers)
   n,err:=f.q.DeliverReceipts(retry.id,raw2,h2)
   if n!=3||err!=nil||f.q.PendingReceipts()!=0{
    t.Fatalf("R_DOWNLOADER_CONCURRENT_RETRY_FAILED: count=%d err=%v",n,err)
   }
  }else{
   t.Fatalf("R_DOWNLOADER_CONCURRENT_PARTIAL_ACCEPT: accepted=%d err=%v pending=%d",accepted,deliverErr,pending)
  }
 }
 t.Log("R_DOWNLOADER_CONCURRENT_REVOKE_EXPIRE_DELIVER_LINEARIZABLE_PASS trials=24")
}
