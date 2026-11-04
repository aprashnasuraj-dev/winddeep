// Reverse Worker R: B round-width defects vs actual post-signature admission.
// Copied only into certified scratch consensus/istanbul/core.
package core

import (
 "math"
 "math/big"
 "testing"
)

func reverseBHugeRound(bit uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1),bit) }

func TestReverseBRoundAliasReachability(t *testing.T) {
 t.Run("low_level_2pow64_map_alias_exists",func(t *testing.T){
  rcs:=newRoundChangeSet(newTestValidatorSet(4))
  rcs.NewRound(big.NewInt(0))
  before:=len(rcs.roundChanges)
  rcs.NewRound(reverseBHugeRound(64))
  after:=len(rcs.roundChanges)
  if before!=1||after!=1 {t.Fatalf("expected direct Uint64 alias 0 vs 2^64, before=%d after=%d",before,after)}
  t.Log("REVERSE_B_LOW_LEVEL_2POW64_ALIAS_CONFIRMED")
 })

 t.Run("fplus1_distinct_sources_cannot_admit_2pow64_from_round0",func(t *testing.T){
  c:=newRoundChangeTestCore(4,5000,0)
  huge:=reverseBHugeRound(64)
  need:=c.valSet.F()+1
  if need<2 {t.Fatalf("unexpected F+1=%d",need)}
  initial:=roundChangeSetEntries(c)
  for i:=0;i<need;i++ {
   src:=c.valSet.List()[i].Address()
   rc:=makeRoundChange(5000,0,src)
   rc.Round=new(big.Int).Set(huge)
   if err:=c.handleRoundChange(rc);err!=nil {t.Fatalf("huge round handler error source=%d: %v",i,err)}
  }
  if got:=roundChangeSetEntries(c);got!=initial {t.Fatalf("huge round allocated state: before=%d after=%d",initial,got)}
  if got:=c.roundChangeSet.getRCMessagesForGivenRound(big.NewInt(0));got!=0 {t.Fatalf("2^64 aliased into round0 messages=%d",got)}
  if c.current.Round().Sign()!=0 {t.Fatalf("consensus advanced unexpectedly to %s",c.current.Round())}
  t.Logf("REVERSE_B_2POW64_FPLUS1_ADMISSION_BLOCKED_PASS threshold=%d maxFutureGap=%d",need,MaxFutureRoundGap)
 })

 t.Run("future_window_exact_boundary",func(t *testing.T){
  c:=newRoundChangeTestCore(4,5000,0)
  src:=c.valSet.List()[1].Address()
  allowed:=new(big.Int).SetUint64(MaxFutureRoundGap)
  rc:=makeRoundChange(5000,0,src);rc.Round=allowed
  if err:=c.handleRoundChange(rc);err!=nil {t.Fatal(err)}
  if c.roundChangeSet.getRCMessagesForGivenRound(allowed)!=1 {t.Fatal("exact MaxFutureRoundGap not admitted")}
  denied:=new(big.Int).SetUint64(MaxFutureRoundGap+1)
  rc2:=makeRoundChange(5000,0,src);rc2.Round=denied
  if err:=c.handleRoundChange(rc2);err!=nil {t.Fatal(err)}
  if c.roundChangeSet.getRCMessagesForGivenRound(denied)!=0 {t.Fatal("round beyond MaxFutureRoundGap admitted")}
  t.Log("REVERSE_B_FUTURE_ROUND_BOUNDARY_PASS")
 })
}

func TestReverseBRound63ReconstructionReachability(t *testing.T){
 t.Run("low_level_signed_reconstruction_defect",func(t *testing.T){
  rcs:=newRoundChangeSet(newTestValidatorSet(4))
  r:=new(big.Int).SetUint64(uint64(1)<<63)
  rcs.NewRound(r)
  got:=rcs.MaxRound(0)
  if got==nil {t.Fatal("MaxRound returned nil")}
  if got.Sign()>=0 {t.Fatalf("expected signed reconstruction defect, got %s",got)}
  t.Logf("REVERSE_B_2POW63_SIGNED_RECONSTRUCTION_CONFIRMED observed=%s",got)
 })

 t.Run("actual_handler_blocks_2pow63_from_low_round",func(t *testing.T){
  c:=newRoundChangeTestCore(4,5000,0)
  target:=new(big.Int).SetUint64(uint64(1)<<63)
  need:=c.valSet.F()+1
  for i:=0;i<need;i++ {
   rc:=makeRoundChange(5000,0,c.valSet.List()[i].Address())
   rc.Round=new(big.Int).Set(target)
   if err:=c.handleRoundChange(rc);err!=nil {t.Fatal(err)}
  }
  if got:=c.roundChangeSet.getRCMessagesForGivenRound(target);got!=0 {t.Fatalf("2^63 messages admitted=%d",got)}
  if c.current.Round().Sign()!=0 {t.Fatalf("unexpected round transition %s",c.current.Round())}
  t.Logf("REVERSE_B_2POW63_HANDLER_REJECTS_PASS maxInt64=%d",int64(math.MaxInt64))
 })
}


func TestReverseB32AdmissionBarrier(t *testing.T){
 c:=newRoundChangeTestCore(4,5000,0)
 target:=new(big.Int).Lsh(big.NewInt(1),32)
 need:=c.valSet.F()+1
 for i:=0;i<need;i++ {
  rc:=makeRoundChange(5000,0,c.valSet.List()[i].Address())
  rc.Round=new(big.Int).Set(target)
  if err:=c.handleRoundChange(rc);err!=nil{t.Fatal(err)}
 }
 if got:=c.roundChangeSet.getRCMessagesForGivenRound(target);got!=0 {t.Fatalf("2^32 ROUND-CHANGE admitted=%d",got)}
 if c.current.Round().Sign()!=0 {t.Fatalf("current round changed to %s",c.current.Round())}
 t.Logf("REVERSE_B32_FPLUS1_IMMEDIATE_ADMISSION_BLOCKED_PASS threshold=%d maxFutureGap=%d",need,MaxFutureRoundGap)
}
