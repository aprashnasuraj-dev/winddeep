// Worker B: full-width round-number invariant characterization.
// Copy only into a disposable scratch copy of the immutable certified source.
// This test does NOT assert high rounds are attacker-reachable in production QBFT.
package core

import (
 "math"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
)

func TestWorkerBRoundChangeArithmetic(t *testing.T) {
 t.Run("small_rounds_correct_control",func(t *testing.T){
  r:=newRoundChangeSet(nil)
  r.NewRound(big.NewInt(0))
  r.NewRound(big.NewInt(1))
  got:=r.MinRoundAboveWithAtLeast(big.NewInt(0),0)
  if got==nil || got.Cmp(big.NewInt(1))!=0 {t.Fatalf("normal round ordering violated: got=%v",got)}
  high:=r.MaxRound(0)
  if high==nil || high.Cmp(big.NewInt(1))!=0 {t.Fatalf("normal max round violated: got=%v",high)}
  t.Log("B_ROUND_SMALL_CONTROL_PASS")
 })
 t.Run("signed_63_bit_conversion",func(t *testing.T){
  r:=newRoundChangeSet(nil)
  r.NewRound(new(big.Int).SetUint64(math.MaxInt64))
  expected:=new(big.Int).SetUint64(uint64(1)<<63)
  r.NewRound(expected)
  got:=r.MinRoundAboveWithAtLeast(new(big.Int).SetUint64(math.MaxInt64),0)
  if got==nil {t.Fatal("missing candidate at 2^63")}
  if got.Cmp(expected)==0 {t.Fatal("expected source-level signed conversion was not observed; re-audit semantics")}
  t.Logf("B_ROUND_SIGNED_CONVERSION observed=%s expected=%s",got.String(),expected.String())
  max:=r.MaxRound(0)
  if max==nil {t.Fatal("MaxRound failed")}
  if max.Cmp(expected)==0 {t.Fatal("unexpectedly returned expected full-width max")}
  t.Logf("B_ROUND_MAX_DISCREPANCY observed=%s expected=%s",max.String(),expected.String())
 })
 t.Run("unsigned_64_bit_map_alias",func(t *testing.T){
  r:=newRoundChangeSet(nil)
  r.NewRound(big.NewInt(0))
  high:=new(big.Int).Lsh(big.NewInt(1),64)
  r.NewRound(high)
  if len(r.roundChanges)!=1 {t.Fatalf("expected Uint64() key alias; got %d keys",len(r.roundChanges))}
  t.Log("B_ROUND_64_MAP_ALIAS: source stores 0 and 2^64 under same key; reachability unproven")
 })
}

 
// This test intentionally characterizes the admission/delivery discrepancy.
// It does not demonstrate a network liveness exploit: message authentication,
// memory budgets and later round checks remain independent defenses.
func TestWorkerBFutureSequenceRoundChangeAdmission(t *testing.T) {
    currentSeq := big.NewInt(100)
    currentRound := big.NewInt(2)
    c := &core{current: newRoundState(&istanbul.View{Sequence:currentSeq,Round:currentRound},nil,nil,nil,nil,nil,nil)}
    maxRound := new(big.Int).Add(currentRound,new(big.Int).SetUint64(MaxFutureRoundGap))
    maxSeq := new(big.Int).Add(currentSeq,new(big.Int).SetUint64(MaxFutureSequenceGap))
    hugeRound := new(big.Int).Lsh(big.NewInt(1),128)
    cases := []struct{name string; code uint64; seq,round *big.Int; admitted bool; future bool}{
      {"same_sequence_normal_rc",qbfttypes.RoundChangeCode,new(big.Int).Set(currentSeq),new(big.Int).Set(maxRound),true,false},
      {"same_sequence_huge_rc_rejected",qbfttypes.RoundChangeCode,new(big.Int).Set(currentSeq),new(big.Int).Set(hugeRound),false,false},
      {"future_sequence_huge_rc_admitted",qbfttypes.RoundChangeCode,new(big.Int).Add(currentSeq,big.NewInt(1)),new(big.Int).Set(hugeRound),true,true},
      {"future_sequence_max_huge_rc_admitted",qbfttypes.RoundChangeCode,new(big.Int).Set(maxSeq),new(big.Int).Set(hugeRound),true,true},
      {"future_sequence_over_window_rejected",qbfttypes.RoundChangeCode,new(big.Int).Add(maxSeq,big.NewInt(1)),new(big.Int).Set(hugeRound),false,true},
      {"future_sequence_prepare_huge_round",qbfttypes.PrepareCode,new(big.Int).Add(currentSeq,big.NewInt(1)),new(big.Int).Set(hugeRound),true,true},
      {"past_sequence_rejected",qbfttypes.RoundChangeCode,new(big.Int).Sub(currentSeq,big.NewInt(1)),new(big.Int).Set(hugeRound),false,false},
    }
    for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
      v:=istanbul.View{Sequence:tc.seq,Round:tc.round}
      admitted:=c.withinBacklogFutureWindow(tc.code,v)
      if admitted!=tc.admitted {t.Fatalf("admission=%v want=%v",admitted,tc.admitted)}
      future:=c.checkMessage(tc.code,&v)==errFutureMessage
      if future!=tc.future {t.Fatalf("delivery future=%v want=%v",future,tc.future)}
      if admitted&&future {t.Log("B_BACKLOG_ADMITTED_BUT_DELIVERY_FUTURE")}
    })}
    // Independent oracle: at delivery, an RC at a future sequence cannot
    // advance this sequence. A separate round cap applies only at admission
    // for same-sequence RC. Mutation control: applying the same cap to all
    // future-sequence RC would reject the two huge-round admitted controls.
    future:=istanbul.View{Sequence:new(big.Int).Add(currentSeq,big.NewInt(1)),Round:hugeRound}
    if !c.withinBacklogFutureWindow(qbfttypes.RoundChangeCode,future) {t.Fatal("source no longer admits high-round future-sequence RC; revisit candidate")}
    strictOracle:=future.Round.Cmp(maxRound)<=0
    if strictOracle {t.Fatal("mutation control failed to distinguish current admission")}
    t.Log("B_FUTURE_RC_WINDOW_DISCREPANCY_CHARACTERIZED; authentication and liveness impact untested")
}
