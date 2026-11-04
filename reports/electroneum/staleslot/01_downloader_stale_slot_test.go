// Electroneum downloader stale-slot hypothesis: actual target-runtime matrix.
// This file is installed alongside base_receipt_fixture_test.go in ./eth/downloader.
// It proves local queue behavior, NOT external attacker reachability or consensus DoS.
package downloader

import (
 "fmt"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/rlp"
)

func dStaleSlotAttempt(q *queue, id string, raw []rlp.RawValue, hashes []common.Hash) (accepted int, err error, panicked any) {
 defer func(){panicked=recover()}()
 accepted,err=q.DeliverReceipts(id,raw,hashes)
 return
}

func TestDStaleSlotSafeControls(t *testing.T) {
 t.Run("valid_complete_receipts",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("normal-receipts")
  req,_,throttled:=f.q.ReserveReceipts(peer,3)
  if req==nil||throttled||len(req.Headers)!=3{t.Fatalf("reservation missing: req=%v throttle=%t",req,throttled)}
  raw,roots:=workerDEncodedReceipts(t,f,req.Headers)
  n,err,p:=dStaleSlotAttempt(f.q,peer.id,raw,roots)
  if p!=nil||err!=nil||n!=3{t.Fatalf("normal valid delivery: accepted=%d err=%v panic=%v",n,err,p)}
  t.Log("STALE_SLOT_BASELINE_VALID_DELIVERY_PASS accepted=3")
 })
 t.Run("prepare_same_offset_does_not_invalidate",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("same-offset")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3{t.Fatal("no reservation")}
  raw,roots:=workerDEncodedReceipts(t,f,req.Headers)
  f.q.Prepare(1,SnapSync)
  n,err,p:=dStaleSlotAttempt(f.q,peer.id,raw,roots)
  if p!=nil||err!=nil||n!=3{t.Fatalf("same-offset delivery: accepted=%d err=%v panic=%v",n,err,p)}
  t.Log("STALE_SLOT_PREPARE_SAME_OFFSET_PASS accepted=3")
 })
 t.Run("resync_reset_before_prepare_discards_old_pending",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("reset-before-prepare")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3{t.Fatal("no reservation")}
  raw,roots:=workerDEncodedReceipts(t,f,req.Headers)
  // Mirrors Downloader.synchronise: Reset precedes syncWithPeer.Prepare.
  f.q.Reset(10,10)
  f.q.Prepare(2,SnapSync)
  n,err,p:=dStaleSlotAttempt(f.q,peer.id,raw,roots)
  if p!=nil||err==nil||n!=0{t.Fatalf("old peer response unexpectedly accepted/crashed: accepted=%d err=%v panic=%v",n,err,p)}
  t.Logf("STALE_SLOT_RESYNC_RESET_BLOCKS_STALE_RESPONSE_PASS accepted=%d err=%v",n,err)
 })
 t.Run("invalid_receipt_root_is_rejected_before_reconstruction",func(t *testing.T){
  f:=workerDNewReceiptQueue(t)
  peer:=dummyPeer("bad-root")
  req,_,_:=f.q.ReserveReceipts(peer,3)
  if req==nil||len(req.Headers)!=3{t.Fatal("no reservation")}
  raw,roots:=workerDEncodedReceipts(t,f,req.Headers)
  roots[0]=common.HexToHash("0x1234")
  if roots[0]==req.Headers[0].ReceiptHash{t.Fatal("invalid root unexpectedly equals header")}
  f.q.Prepare(2,SnapSync)
  n,err,p:=dStaleSlotAttempt(f.q,peer.id,raw,roots)
  if p!=nil||err==nil||n!=0{t.Fatalf("bad root was not rejected: n=%d err=%v panic=%v",n,err,p)}
  t.Log("STALE_SLOT_BAD_RECEIPT_ROOT_REJECTED_PASS")
 })
}

func TestDStaleSlotConditionalPanic(t *testing.T) {
 f:=workerDNewReceiptQueue(t)
 peer:=dummyPeer("advance-with-pending")
 req,_,_:=f.q.ReserveReceipts(peer,3)
 if req==nil||len(req.Headers)!=3{t.Fatal("no three-header reservation")}
 raw,roots:=workerDEncodedReceipts(t,f,req.Headers)
 oldNumber:=req.Headers[0].Number.Uint64()
 if oldNumber!=1{t.Fatalf("unexpected first header: %d",oldNumber)}
 f.q.Prepare(oldNumber+1,SnapSync)
 slot,stale,lookupErr:=f.q.resultCache.GetDeliverySlot(oldNumber)
 if lookupErr!=nil||slot!=nil||!stale{t.Fatalf("expected stale nil slot with nil error: slot=%v stale=%t err=%v",slot,stale,lookupErr)}
 t.Logf("STALE_SLOT_PRECONDITION_VERIFIED header=%d advanced_offset=%d slot_nil=%t stale=%t err_nil=%t",oldNumber,f.q.resultCache.resultOffset,slot==nil,stale,lookupErr==nil)
 n,err,p:=dStaleSlotAttempt(f.q,peer.id,raw,roots)
 if p==nil{t.Fatalf("STALE_SLOT_ORIGINAL_EXPECTED_PANIC_NOT_SEEN accepted=%d err=%v",n,err)}
 if msg:=fmt.Sprint(p);!strings.Contains(strings.ToLower(msg),"nil pointer"){t.Fatalf("unrelated panic: %T: %v",p,p)}
 t.Logf("STALE_SLOT_TARGET_PANIC_OBSERVED panic_type=%T panic=%v",p,p)
 t.Log("STALE_SLOT_SCOPING local_queue_prepare_overlap=true external_sync_reachability_unproven")
}

// Deliberately strict: it MUST fail on original source with an exact named marker
// and pass on a scratch-only fail-closed guard. Never mask failures as successes.
func TestDStaleSlotFailClosedOracle(t *testing.T) {
 f:=workerDNewReceiptQueue(t)
 peer:=dummyPeer("strict-oracle")
 req,_,_:=f.q.ReserveReceipts(peer,3)
 if req==nil||len(req.Headers)!=3{t.Fatal("no reservation")}
 raw,roots:=workerDEncodedReceipts(t,f,req.Headers)
 f.q.Prepare(req.Headers[0].Number.Uint64()+1,SnapSync)
 accepted,err,p:=dStaleSlotAttempt(f.q,peer.id,raw,roots)
 if p!=nil{t.Fatalf("STALE_SLOT_FAIL_CLOSED_ORACLE_PANIC: %T: %v",p,p)}
 if err==nil||accepted!=0{t.Fatalf("STALE_SLOT_FAIL_CLOSED_ORACLE_MISMATCH accepted=%d err=%v",accepted,err)}
 t.Log("STALE_SLOT_FAIL_CLOSED_ORACLE_PASS accepted=0 structured_error=true")
}
