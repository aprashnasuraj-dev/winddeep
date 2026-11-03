// Worker B: full-width round-number invariant characterization.
// Copy only into a disposable scratch copy of the immutable certified source.
// This test does NOT assert high rounds are attacker-reachable in production QBFT.
package core

import (
 "math"
 "math/big"
 "testing"
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
