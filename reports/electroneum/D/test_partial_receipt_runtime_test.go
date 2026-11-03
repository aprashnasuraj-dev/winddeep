// Worker D: certified-source synthetic receipt partial-prefix and retry behavior.
// Uses only the in-process downloader queue, no network peers or public chain.
package downloader

import (
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
 "github.com/electroneum/electroneum-sc/trie"
)

type workerDReceiptQueueFixture struct {
 q *queue
 headers []*types.Header
 receipts []types.Receipts
}

func workerDNewReceiptQueue(t *testing.T) workerDReceiptQueueFixture {
 t.Helper()
 blocks,receipts:=makeChain(6,0,genesis,false)
 headers:=make([]*types.Header,len(blocks))
 hashes:=make([]common.Hash,len(blocks))
 for i,b:=range blocks {
  headers[i]=b.Header()
  hashes[i]=headers[i].Hash()
 }
 q:=newQueue(10,10)
 q.Prepare(1,SnapSync)
 q.Schedule(headers,hashes,1)
 if count:=q.PendingReceipts();count!=3 {t.Fatalf("expected three nonempty receipt tasks, got %d",count)}
 return workerDReceiptQueueFixture{q:q,headers:headers,receipts:receipts}
}

func workerDEncodedReceipts(t *testing.T, f workerDReceiptQueueFixture, headers []*types.Header) ([]rlp.RawValue,[]common.Hash) {
 t.Helper()
 raw:=make([]rlp.RawValue,len(headers))
 hashes:=make([]common.Hash,len(headers))
 for i,h:=range headers {
  index:=int(h.Number.Uint64())-1
  if index<0||index>=len(f.receipts) {t.Fatalf("bad receipt index %d",index)}
  var err error
  raw[i],err=rlp.EncodeToBytes(f.receipts[index])
  if err!=nil {t.Fatal(err)}
  hashes[i]=types.DeriveSha(f.receipts[index],trie.NewStackTrie(nil))
  if hashes[i]!=h.ReceiptHash {t.Fatalf("fixture receipt/header root mismatch at %d",h.Number.Uint64())}
 }
 return raw,hashes
}

func TestWorkerDReceiptPartialDelivery(t *testing.T) {
 t.Run("honest_all_valid",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("worker-d-honest")
  req,_,throttled:=f.q.ReserveReceipts(peer,3)
  if throttled||req==nil||len(req.Headers)!=3 {t.Fatalf("expected 3 reserved receipts: req=%v throttle=%v",req,throttled)}
  raw,hashes:=workerDEncodedReceipts(t,f,req.Headers)
  accepted,err:=f.q.DeliverReceipts(peer.id,raw,hashes)
  if err!=nil||accepted!=3 {t.Fatalf("valid batch accepted=%d err=%v",accepted,err)}
  if f.q.PendingReceipts()!=0 {t.Fatalf("valid batch left pending receipts %d",f.q.PendingReceipts())}
  t.Log("D_RECEIPT_POSITIVE_BATCH_PASS accepted=3")
 })
 t.Run("valid_prefix_invalid_second_then_retry",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("worker-d-malformed")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3 {t.Fatalf("request unavailable or wrong length")}
  raw,hashes:=workerDEncodedReceipts(t,f,req.Headers)
  // Semantic corruption of the second receipt's status changes its trie root;
  // the honest header remains unchanged. This is an invalid peer response.
  second:=int(req.Headers[1].Number.Uint64())-1
  original:=f.receipts[second]
  if len(original)==0 {t.Fatal("second receipt list unexpectedly empty")}
  altered:=make(types.Receipts,len(original))
  copy(altered,original)
  receiptCopy:=*altered[0]
  receiptCopy.Status ^= 1
  altered[0]=&receiptCopy
  raw[1],_=rlp.EncodeToBytes(altered)
  hashes[1]=types.DeriveSha(altered,trie.NewStackTrie(nil))
  if hashes[1]==req.Headers[1].ReceiptHash {t.Fatal("adversarial second response did not change commitment")}
  accepted,err:=f.q.DeliverReceipts(peer.id,raw,hashes)
  if err==nil||accepted!=1 {t.Fatalf("expected one valid prefix and partial rejection; accepted=%d err=%v",accepted,err)}
  if n:=f.q.PendingReceipts();n!=2 {t.Fatalf("accepted prefix still pending or suffix lost; remaining=%d",n)}
  retryPeer:=dummyPeer("worker-d-retry")
  retry,_,_:=f.q.ReserveReceipts(retryPeer,3)
  if retry==nil||len(retry.Headers)!=2 {t.Fatalf("expected two suffix receipts requeued, got %v",retry)}
  goodRaw,goodHashes:=workerDEncodedReceipts(t,f,retry.Headers)
  accepted2,err2:=f.q.DeliverReceipts(retryPeer.id,goodRaw,goodHashes)
  if err2!=nil||accepted2!=2||f.q.PendingReceipts()!=0 {
   t.Fatalf("retry incomplete: accepted=%d err=%v pending=%d",accepted2,err2,f.q.PendingReceipts())
  }
  t.Log("D_RECEIPT_PARTIAL_SUFFIX_RETRY_PASS first=1 retried=2")
 })
 t.Run("invalid_first_keeps_all_pending",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("worker-d-invalid-first")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3 {t.Fatal("expected receipt request")}
  raw,hashes:=workerDEncodedReceipts(t,f,req.Headers)
  altered:=hashes[0]
  altered[0]^=1
  hashes[0]=altered // Invalid-root admission control.
  accepted,err:=f.q.DeliverReceipts(peer.id,raw,hashes)
  if err==nil||accepted!=0 {t.Fatalf("invalid first should reject all; accepted=%d err=%v",accepted,err)}
  if n:=f.q.PendingReceipts();n!=3 {t.Fatalf("invalid-first dropped tasks: pending=%d",n)}
  t.Log("D_RECEIPT_INVALID_FIRST_REJECTED pending=3")
 })
}
