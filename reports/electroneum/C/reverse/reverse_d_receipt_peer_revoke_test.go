// Independent reverse audit R — D receipt queue reordering, revocation,
// duplicate/replayed response, malformed payload and valid-prefix retry tests.
// This is copied into a disposable certified Electroneum eth/downloader scratch
// package. No real peer, network or mainnet blocks are used.
package downloader

import (
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
 "github.com/electroneum/electroneum-sc/trie"
)

type reverseDQueueFixture struct {
 q *queue
 receipts []types.Receipts
}
func reverseDNewReceiptFixture(t *testing.T) reverseDQueueFixture {
 t.Helper()
 blocks,receipts:=makeChain(6,0,genesis,false)
 headers:=make([]*types.Header,len(blocks))
 hashes:=make([]common.Hash,len(blocks))
 for i,b:=range blocks {headers[i]=b.Header(); hashes[i]=headers[i].Hash()}
 q:=newQueue(10,10);q.Prepare(1,SnapSync);q.Schedule(headers,hashes,1)
 if n:=q.PendingReceipts();n!=3 {t.Fatalf("expected 3 receipt tasks, got %d",n)}
 return reverseDQueueFixture{q,receipts}
}
func reverseDReceiptData(t *testing.T,f reverseDQueueFixture,heads []*types.Header)([]rlp.RawValue,[]common.Hash) {
 t.Helper()
 raw:=make([]rlp.RawValue,len(heads));hashes:=make([]common.Hash,len(heads))
 for i,h:=range heads {
  index:=int(h.Number.Uint64())-1
  if index<0||index>=len(f.receipts) {t.Fatalf("invalid receipt height %d",index)}
  var err error
  raw[i],err=rlp.EncodeToBytes(f.receipts[index])
  if err!=nil {t.Fatal(err)}
  hashes[i]=types.DeriveSha(f.receipts[index],trie.NewStackTrie(nil))
  if hashes[i]!=h.ReceiptHash {t.Fatalf("independent trusted-header commitment mismatch height=%d",index+1)}
 }
 return raw,hashes
}

func TestReverseDReceiptPeerRevocationAndReplay(t *testing.T){
 t.Run("revoke_inflight_then_reassign",func(t *testing.T){
  f:=reverseDNewReceiptFixture(t)
  p1,p2:=dummyPeer("reverse-r-revoked"),dummyPeer("reverse-r-reassigned")
  req,_,_:=f.q.ReserveReceipts(p1,3)
  if req==nil||len(req.Headers)!=3||!f.q.InFlightReceipts(){t.Fatal("expected three in-flight requested receipts")}
  oldRaw,oldHash:=reverseDReceiptData(t,f,req.Headers)
  f.q.Revoke(p1.id)
  if f.q.InFlightReceipts()||f.q.PendingReceipts()!=3 {t.Fatalf("revoke lost or retained tasks pending=%d",f.q.PendingReceipts())}
  n,err:=f.q.DeliverReceipts(p1.id,oldRaw,oldHash)
  if err==nil||n!=0 {t.Fatalf("stale peer accepted after revoke n=%d err=%v",n,err)}
  retried,_,_:=f.q.ReserveReceipts(p2,3)
  if retried==nil||len(retried.Headers)!=3 {t.Fatal("reassigned peer did not receive all tasks")}
  data,hashes:=reverseDReceiptData(t,f,retried.Headers)
  accepted,e:=f.q.DeliverReceipts(p2.id,data,hashes)
  if e!=nil||accepted!=3||f.q.PendingReceipts()!=0 {
   t.Fatalf("new peer re-delivery invalid accepted=%d err=%v pending=%d",accepted,e,f.q.PendingReceipts())
  }
  t.Log("REVERSE_D_RECEIPT_REVOKED_STALE_PEER_REJECTED_PASS reassigned=3")
 })
 t.Run("partial_prefix_second_peer_revoked_then_third_peer_retries",func(t *testing.T){
  f:=reverseDNewReceiptFixture(t)
  p1,p2,p3:=dummyPeer("reverse-r-prefix"),dummyPeer("reverse-r-revoked-suffix"),dummyPeer("reverse-r-final-suffix")
  req,_,_:=f.q.ReserveReceipts(p1,3)
  if req==nil||len(req.Headers)!=3{t.Fatal("initial receipt request missing")}
  raw,hashes:=reverseDReceiptData(t,f,req.Headers)
  bad:=hashes[1];bad[0]^=0x80;hashes[1]=bad
  got,err:=f.q.DeliverReceipts(p1.id,raw,hashes)
  if err==nil||got!=1||f.q.PendingReceipts()!=2 {
   t.Fatalf("bad second receipt accepted or prefix lost accepted=%d err=%v pending=%d",got,err,f.q.PendingReceipts())
  }
  pending,_,_:=f.q.ReserveReceipts(p2,2)
  if pending==nil||len(pending.Headers)!=2{t.Fatalf("two suffix tasks not reassigned")}
  retryRaw,retryHashes:=reverseDReceiptData(t,f,pending.Headers)
  f.q.Revoke(p2.id)
  staleCount,staleErr:=f.q.DeliverReceipts(p2.id,retryRaw,retryHashes)
  if staleErr==nil||staleCount!=0 {t.Fatalf("revoked suffix accepted=%d err=%v",staleCount,staleErr)}
  final,_,_:=f.q.ReserveReceipts(p3,2)
  if final==nil||len(final.Headers)!=2 {t.Fatal("valid suffix unavailable after second revoke")}
  finalRaw,finalHashes:=reverseDReceiptData(t,f,final.Headers)
  accepted,e:=f.q.DeliverReceipts(p3.id,finalRaw,finalHashes)
  if e!=nil||accepted!=2||f.q.PendingReceipts()!=0{
   t.Fatalf("valid suffix lost after double retry accepted=%d err=%v pending=%d",accepted,e,f.q.PendingReceipts())
  }
  t.Log("REVERSE_D_RECEIPT_PREFIX_REVOKE_RETRY_PASS accepted=1+2")
 })
 t.Run("replay_after_success_is_rejected",func(t *testing.T){
  f:=reverseDNewReceiptFixture(t)
  p:=dummyPeer("reverse-r-replay")
  req,_,_:=f.q.ReserveReceipts(p,3)
  if req==nil||len(req.Headers)!=3 {t.Fatal("missing replay control request")}
  raw,hashes:=reverseDReceiptData(t,f,req.Headers)
  accepted,err:=f.q.DeliverReceipts(p.id,raw,hashes)
  if err!=nil||accepted!=3 {t.Fatalf("honest peer initial receipt failed %d %v",accepted,err)}
  replayAccepted,replayErr:=f.q.DeliverReceipts(p.id,raw,hashes)
  if replayErr==nil||replayAccepted!=0||f.q.PendingReceipts()!=0 {
   t.Fatalf("replayed receipts accepted=%d err=%v pending=%d",replayAccepted,replayErr,f.q.PendingReceipts())
  }
  t.Log("REVERSE_D_RECEIPT_DUPLICATE_REPLAY_REJECTED_PASS")
 })
 t.Run("invalid_rlp_requeues_and_valid_retry_succeeds",func(t *testing.T){
  f:=reverseDNewReceiptFixture(t)
  p1,p2:=dummyPeer("reverse-r-bad-rlp"),dummyPeer("reverse-r-rlp-retry")
  req,_,_:=f.q.ReserveReceipts(p1,3)
  if req==nil||len(req.Headers)!=3 {t.Fatal("missing request")}
  raw,hashes:=reverseDReceiptData(t,f,req.Headers)
  raw[0]=rlp.RawValue{0xff}
  badAccepted,badErr:=f.q.DeliverReceipts(p1.id,raw,hashes)
  if badErr==nil||badAccepted!=0||f.q.PendingReceipts()!=3 {
   t.Fatalf("invalid RLP not rejected and all requeued accepted=%d err=%v pending=%d",badAccepted,badErr,f.q.PendingReceipts())
  }
  req2,_,_:=f.q.ReserveReceipts(p2,3)
  if req2==nil||len(req2.Headers)!=3 {t.Fatal("recovery request not available")}
  cleanRaw,cleanHashes:=reverseDReceiptData(t,f,req2.Headers)
  accepted,err:=f.q.DeliverReceipts(p2.id,cleanRaw,cleanHashes)
  if err!=nil||accepted!=3||f.q.PendingReceipts()!=0 {
   t.Fatalf("after malformed input recovery failed accepted=%d err=%v pending=%d",accepted,err,f.q.PendingReceipts())
  }
  t.Log("REVERSE_D_RECEIPT_INVALID_RLP_NO_LOSS_PASS")
 })
}
