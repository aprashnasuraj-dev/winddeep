package feeoracle

import (
 "math/big"
 "testing"
)

// Independent financial-policy oracle, NOT an Electroneum certified-runtime test.
// Assumed policy: reimburse min(actual gas fee, fixed cap), using 21,000 gas.
// Demonstrates direction of fee-reimbursement error; does not prove a relying party exists.
func TestReceiptFeeReimbursementDirection(t *testing.T) {
 n := new(big.Int).Lsh(big.NewInt(1), 64)
 cases := []struct{name string; price *big.Int}{
  {"Nminus1", new(big.Int).Sub(new(big.Int).Set(n), big.NewInt(1))},
  {"N", new(big.Int).Set(n)},
  {"Nplus1", new(big.Int).Add(new(big.Int).Set(n), big.NewInt(1))},
  {"Nplus17", new(big.Int).Add(new(big.Int).Set(n), big.NewInt(17))},
 }
 gas := big.NewInt(21000)
 cap := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).Set(n), big.NewInt(3)), gas)
 for _, c := range cases {
  t.Run(c.name, func(t *testing.T) {
   actual := new(big.Int).Mul(c.price, gas)
   receiptPrice := new(big.Int).SetUint64(c.price.Uint64())
   reported := new(big.Int).Mul(receiptPrice, gas)
   if actual.Cmp(cap) > 0 {actual.Set(cap)}
   if reported.Cmp(cap) > 0 {reported.Set(cap)}
   if reported.Cmp(actual) > 0 {t.Fatalf("unexpected overpayment: reported=%s actual=%s", reported, actual)}
   gap := new(big.Int).Sub(actual, reported)
   if c.price.Cmp(n) < 0 && gap.Sign() != 0 {t.Fatalf("unexpected gap: %s", gap)}
   if c.price.Cmp(n) >= 0 && gap.Sign() == 0 {t.Fatal("expected underpayment")}
   t.Logf("price=%s reported_reimbursement_wei=%s correct_reimbursement_wei=%s underpayment_wei=%s", c.price, reported, actual, gap)
  })
 }
}
