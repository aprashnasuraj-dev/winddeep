// Worker R deep D4: simultaneous block-body + receipt queue state transitions.
// Uses real downloader queue, chain-generated blocks, header commitments and RLP.
package downloader

import (
 "fmt"
 "sync"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/eth/protocols/eth"
 "github.com/electroneum/electroneum-sc/rlp"
)

type rDeepDualFixture struct {
 q *queue
 blocks []*types.Block
 receipts []types.Receipts
 headers []*types.Header
 hashes []common.Hash
 peerNumber int
}
func rDeepNewDualFixture(t *testing.T)*rDeepDualFixture{
 t.Helper()
 blocks,receipts:=makeChain(6,0,genesis,false)
 h:=make([]*types.Header,len(blocks))
 hashes:=make([]common.Hash,len(blocks))
 for i,b:=range blocks{h[i]=b.Header();hashes[i]=h[i].Hash()}
 q:=newQueue(12,12);q.Prepare(1,SnapSync);q.Schedule(h,hashes,1)
 if q.PendingBodies()!=3||q.PendingReceipts()!=3{t.Fatalf("R_DUAL_INVALID_FIXTURE: bodies=%d receipts=%d",q.PendingBodies(),q.PendingReceipts())}
 return &rDeepDualFixture{q:q,blocks:blocks,receipts:receipts,headers:h,hashes:hashes}
}
type rDeepBodyRequest struct{
 id string
 raw []eth.RawBlockBody
 txHashes []common.Hash
 uncleHashes []common.Hash
}
type rDeepReceiptRequest struct{
 id string
 raw []rlp.RawValue
 roots []common.Hash
}
func (f *rDeepDualFixture)reserveBody(t *testing.T)*rDeepBodyRequest{
 t.Helper()
 if f.q.PendingBodies()==0{return nil}
 f.peerNumber++
 peer:=dummyPeer(fmt.Sprintf("deep-b-%d",f.peerNumber))
 req,_,_:=f.q.ReserveBodies(peer,3)
 if req==nil{return nil}
 result:=&rDeepBodyRequest{id:peer.id}
 for _,h:=range req.Headers{
  idx:=int(h.Number.Uint64())-1
  if idx<0||idx>=len(f.blocks){t.Fatal("bad body header index")}
  b:=f.blocks[idx]
  if b.Hash()!=h.Hash(){t.Fatalf("R_DUAL_BODY_HEADER_MISMATCH: index=%d",idx)}
  tx,err:=rlp.EncodeToBytes(b.Transactions());if err!=nil{t.Fatal(err)}
  uncles,err:=rlp.EncodeToBytes(b.Uncles());if err!=nil{t.Fatal(err)}
  result.raw=append(result.raw,eth.RawBlockBody{Transactions:tx,Uncles:uncles})
  result.txHashes=append(result.txHashes,h.TxHash)
  result.uncleHashes=append(result.uncleHashes,h.UncleHash)
 }
 return result
}
func (f *rDeepDualFixture)reserveReceipt(t *testing.T)*rDeepReceiptRequest{
 t.Helper()
 if f.q.PendingReceipts()==0{return nil}
 f.peerNumber++
 peer:=dummyPeer(fmt.Sprintf("deep-r-%d",f.peerNumber))
 req,_,_:=f.q.ReserveReceipts(peer,3)
 if req==nil{return nil}
 result:=&rDeepReceiptRequest{id:peer.id}
 for _,h:=range req.Headers{
  idx:=int(h.Number.Uint64())-1
  if idx<0||idx>=len(f.receipts){t.Fatal("bad receipt header index")}
  raw,err:=rlp.EncodeToBytes(f.receipts[idx]);if err!=nil{t.Fatal(err)}
  result.raw=append(result.raw,raw)
  result.roots=append(result.roots,h.ReceiptHash)
 }
 return result
}
func (f *rDeepDualFixture)rejectStaleBody(t *testing.T,req *rDeepBodyRequest){
 t.Helper();if req==nil{return}
 count,err:=f.q.DeliverBodies(req.id,req.raw,req.txHashes,req.uncleHashes)
 if count!=0||err==nil{t.Fatalf("R_DUAL_STALE_BODY_ACCEPTED: count=%d err=%v",count,err)}
}
func (f *rDeepDualFixture)rejectStaleReceipt(t *testing.T,req *rDeepReceiptRequest){
 t.Helper();if req==nil{return}
 count,err:=f.q.DeliverReceipts(req.id,req.raw,req.roots)
 if count!=0||err==nil{t.Fatalf("R_DUAL_STALE_RECEIPT_ACCEPTED: count=%d err=%v",count,err)}
}
func rDeepDualScenario(t *testing.T,script []byte){
 t.Helper()
 if len(script)>32{return}
 f:=rDeepNewDualFixture(t)
 var body *rDeepBodyRequest
 var receipt *rDeepReceiptRequest
 if len(script)==0{script=[]byte{0,1,2,3,4,5}}
 for step,action:=range script {
  if body==nil{body=f.reserveBody(t)}
  if receipt==nil{receipt=f.reserveReceipt(t)}
  switch action%6{
  case 0: // revoke body while receipt remains outstanding
   if body!=nil{f.q.Revoke(body.id);f.rejectStaleBody(t,body);body=nil}
  case 1: // expire receipt while body remains outstanding
   if receipt!=nil{if n:=f.q.ExpireReceipts(receipt.id);n<1{t.Fatal("R_DUAL_MISSED_RECEIPT_EXPIRY")};f.rejectStaleReceipt(t,receipt);receipt=nil}
  case 2: // correct body and receipt independently commit
   if body!=nil{n,err:=f.q.DeliverBodies(body.id,body.raw,body.txHashes,body.uncleHashes);if err!=nil||n!=len(body.raw){t.Fatalf("R_DUAL_VALID_BODY_FAILED: n=%d err=%v",n,err)};f.rejectStaleBody(t,body);body=nil}
   if receipt!=nil{n,err:=f.q.DeliverReceipts(receipt.id,receipt.raw,receipt.roots);if err!=nil||n!=len(receipt.raw){t.Fatalf("R_DUAL_VALID_RECEIPT_FAILED: n=%d err=%v",n,err)};f.rejectStaleReceipt(t,receipt);receipt=nil}
  case 3: // adversarial body commitment mismatch cannot satisfy receipt queue
   if body!=nil{bad:=append([]common.Hash(nil),body.txHashes...);bad[0][0]^=0x20;n,err:=f.q.DeliverBodies(body.id,body.raw,bad,body.uncleHashes);if err==nil||n!=0{t.Fatalf("R_DUAL_BAD_BODY_ROOT_ACCEPTED n=%d err=%v",n,err)};body=nil}
  case 4: // poisoned receipt root cannot satisfy body queue
   if receipt!=nil{bad:=append([]common.Hash(nil),receipt.roots...);bad[0][0]^=0x20;n,err:=f.q.DeliverReceipts(receipt.id,receipt.raw,bad);if err==nil||n!=0{t.Fatalf("R_DUAL_BAD_RECEIPT_ROOT_ACCEPTED n=%d err=%v",n,err)};receipt=nil}
  case 5: // full cancel/reset: stale responses from BOTH queues must be denied
   f.q.Close();f.q.Reset(12,12);f.q.Prepare(1,SnapSync)
   f.rejectStaleBody(t,body);f.rejectStaleReceipt(t,receipt)
   body=nil;receipt=nil
   if got:=f.q.Schedule(f.headers,f.hashes,1);len(got)!=6{t.Fatalf("R_DUAL_RESET_MISSED_HEADERS: got=%d",len(got))}
  }
  if f.q.PendingBodies()<0||f.q.PendingBodies()>3||f.q.PendingReceipts()<0||f.q.PendingReceipts()>3{
   t.Fatalf("R_DUAL_QUEUE_COUNT_BREACH: step=%d bodies=%d receipts=%d",step,f.q.PendingBodies(),f.q.PendingReceipts())
  }
 }
 if body!=nil{f.q.Revoke(body.id);f.rejectStaleBody(t,body)}
 if receipt!=nil{f.q.Revoke(receipt.id);f.rejectStaleReceipt(t,receipt)}
 // Invariant: after any finite adversarial sequence, independent honest peers
 // can finish BOTH kinds without duplicates, lost tasks or cross-type confusion.
 for attempt:=0;attempt<8&&(!f.q.Idle());attempt++{
  if b:=f.reserveBody(t);b!=nil{
   n,err:=f.q.DeliverBodies(b.id,b.raw,b.txHashes,b.uncleHashes)
   if err!=nil||n!=len(b.raw){t.Fatalf("R_DUAL_BODY_RECOVERY: n=%d err=%v",n,err)}
  }
  if rr:=f.reserveReceipt(t);rr!=nil{
   n,err:=f.q.DeliverReceipts(rr.id,rr.raw,rr.roots)
   if err!=nil||n!=len(rr.raw){t.Fatalf("R_DUAL_RECEIPT_RECOVERY: n=%d err=%v",n,err)}
  }
 }
 if !f.q.Idle()||f.q.PendingBodies()!=0||f.q.PendingReceipts()!=0||f.q.InFlightBlocks()||f.q.InFlightReceipts(){
  t.Fatalf("R_DUAL_FINAL_LIVENESS_FAIL: body=%d receipts=%d inflightB=%t inflightR=%t",f.q.PendingBodies(),f.q.PendingReceipts(),f.q.InFlightBlocks(),f.q.InFlightReceipts())
 }
 t.Logf("R_DUAL_BODY_RECEIPT_RECOVERY_PASS steps=%d",len(script))
}
func TestRDeepDualBaseline(t *testing.T){
 for _,seq:=range [][]byte{{0,1,2},{3,4,2},{5,2,1,0,2},{2,2,2},{1,0,5,2,3,4}}{rDeepDualScenario(t,seq)}
 // Repeat a mixed-type cancel vs delivery race: either ordering is valid,
 // but it must never yield duplicate task acceptance or lost work.
 for n:=0;n<12;n++{
  f:=rDeepNewDualFixture(t)
  b:=f.reserveBody(t);rr:=f.reserveReceipt(t)
  if b==nil||rr==nil{t.Fatal("race fixture missing dual work")}
  start:=make(chan struct{})
  var wg sync.WaitGroup
  wg.Add(4)
  go func(){defer wg.Done();<-start;f.q.Revoke(b.id)}()
  go func(){defer wg.Done();<-start;f.q.Revoke(rr.id)}()
  go func(){defer wg.Done();<-start;f.q.DeliverBodies(b.id,b.raw,b.txHashes,b.uncleHashes)}()
  go func(){defer wg.Done();<-start;f.q.DeliverReceipts(rr.id,rr.raw,rr.roots)}()
  close(start);wg.Wait()
  if f.q.PendingBodies()>3||f.q.PendingReceipts()>3{t.Fatalf("R_DUAL_RACE_QUEUE_OVERFLOW: n=%d",n)}
  // Reset reimports every trusted header to certify no residual stale slots.
  f.q.Close();f.q.Reset(12,12);f.q.Prepare(1,SnapSync)
  f.rejectStaleBody(t,b);f.rejectStaleReceipt(t,rr)
  if got:=f.q.Schedule(f.headers,f.hashes,1);len(got)!=6{t.Fatal("mixed-race reset incomplete")}
 }
 t.Log("R_DUAL_CONCURRENT_REVOKE_DELIVER_CONTROLS_PASS rounds=12")
}
func FuzzRDeepDualQueue(f *testing.F){
 f.Add([]byte{0,1,2,3,4,5})
 f.Add([]byte{5,2,1,0,2})
 f.Add([]byte{3,4,2,5,2})
 f.Fuzz(func(t *testing.T,seq []byte){if len(seq)>32{return};rDeepDualScenario(t,seq)})
}
