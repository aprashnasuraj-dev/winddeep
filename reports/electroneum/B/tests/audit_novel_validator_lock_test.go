package validator

import (
 "runtime"
 "sync"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
)

// Source-target test. The selector hook only positions the deterministic
// interleaving; it does not change GetByIndex, Size or CalcProposer code.
func TestAuditNovelValidatorPendingWriterDeadlock(t *testing.T) {
 old:=runtime.GOMAXPROCS(4);defer runtime.GOMAXPROCS(old)
 addresses:=[]common.Address{
  common.HexToAddress("0x0000000000000000000000000000000000000001"),
  common.HexToAddress("0x0000000000000000000000000000000000000002"),
 }
 t.Run("no-writer-control",func(t *testing.T){
  v:=newDefaultSet(addresses,istanbul.NewRoundRobinProposerPolicy())
  done:=make(chan struct{})
  go func(){v.CalcProposer(addresses[0],1);close(done)}()
  select {case <-done:t.Log("CONTROL_NO_CONTENTION_CALC_COMPLETED");case <-time.After(time.Second):t.Fatal("no-writer control stalled")}
 })
 t.Run("writer-pending",func(t *testing.T){
  v:=newDefaultSet(addresses,istanbul.NewRoundRobinProposerPolicy())
  entered:=make(chan struct{});proceed:=make(chan struct{})
  var once sync.Once
  v.selector=func(set istanbul.ValidatorSet,last common.Address,round uint64)istanbul.Validator {
   once.Do(func(){close(entered)})
   <-proceed
   return roundRobinProposer(set,last,round)
  }
  calcDone:=make(chan struct{})
  go func(){v.CalcProposer(addresses[0],1);close(calcDone)}()
  select {case <-entered:case <-time.After(time.Second):t.Fatal("CalcProposer never entered selector")}
  writerStarted:=make(chan struct{});writerDone:=make(chan struct{})
  go func(){close(writerStarted);v.AddValidator(common.HexToAddress("0x0000000000000000000000000000000000000003"));close(writerDone)}()
  <-writerStarted
  time.Sleep(50*time.Millisecond)
  readerDone:=make(chan struct{})
  go func(){_ = v.Size();close(readerDone)}()
  select {case <-readerDone:t.Fatal("pending-writer precondition was not established");case <-time.After(75*time.Millisecond):}
  close(proceed)
  select {case <-calcDone:t.Fatal("CalcProposer did not stall under writer contention");case <-time.After(200*time.Millisecond):t.Log("DEADLOCK_CONFIRMED: nested read acquisition blocks behind pending writer while outer read lock remains held")}
  select {case <-writerDone:t.Fatal("writer unexpectedly completed");default:t.Log("WRITER_BLOCKED_CONFIRMED")}
  // Only isolated test-process goroutines intentionally remain parked.
 })
}

// Must be run with 'go test -race'. A race report is the EXPECTED outcome:
// CalcProposer writes proposer under RLock, not Lock.
func TestAuditNovelValidatorProposerDataRace(t *testing.T){
 old:=runtime.GOMAXPROCS(4);defer runtime.GOMAXPROCS(old)
 addresses:=[]common.Address{
  common.HexToAddress("0x0000000000000000000000000000000000000011"),
  common.HexToAddress("0x0000000000000000000000000000000000000012"),
  common.HexToAddress("0x0000000000000000000000000000000000000013"),
 }
 v:=newDefaultSet(addresses,istanbul.NewRoundRobinProposerPolicy())
 var wg sync.WaitGroup
 for worker:=0;worker<4;worker++ {
  wg.Add(1)
  go func(id int){
   defer wg.Done()
   for i:=0;i<1000;i++{v.CalcProposer(addresses[(id+i)%len(addresses)],uint64((id+i)%5))}
  }(worker)
 }
 wg.Wait()
 t.Log("PROPOSER_CONCURRENT_WRITER_TEST_COMPLETED; check race detector for actual finding")
}
