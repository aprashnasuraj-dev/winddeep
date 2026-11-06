package feeoracle

import ("math/big"; "testing")

// Independent arithmetic/funding discriminator, NOT certified target runtime.
// Run: go test -count=1 -v reports/electroneum/E/fee_funding_oracle_test.go
func TestFeeFundingBoundary(t *testing.T) {
 n:=new(big.Int).Lsh(big.NewInt(1),64); gas:=big.NewInt(21000); base:=big.NewInt(1000000000)
 cases:=[]struct{name string; cap,tip *big.Int; funded, truncated bool}{
 {"Nminus1_funded",new(big.Int).Sub(new(big.Int).Set(n),big.NewInt(1)),new(big.Int).Sub(new(big.Int).Set(n),big.NewInt(1)),true,false},
 {"N_funded",new(big.Int).Set(n),new(big.Int).Set(n),true,true},
 {"Nplus1_funded",new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),new(big.Int).Set(n),true,true},
 {"Nplus1_unfunded",new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),new(big.Int).Set(n),false,true},
 {"Nplus1_low_tip",new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),big.NewInt(1),true,false},
 }
 for _,c:=range cases {t.Run(c.name,func(t *testing.T){
  if c.cap.BitLen()>256||c.tip.BitLen()>256||c.cap.Cmp(c.tip)<0 {t.Fatal("invalid fee fields")}
  required:=new(big.Int).Mul(gas,c.cap); balance:=new(big.Int).Set(required)
  if !c.funded {balance.Sub(balance,big.NewInt(1))}
  acceptedByFunding:=balance.Cmp(required)>=0
  if acceptedByFunding!=c.funded {t.Fatal("funding oracle failed")}
  effective:=new(big.Int).Add(base,c.tip);if effective.Cmp(c.cap)>0 {effective.Set(c.cap)}
  observed:=new(big.Int).SetUint64(effective.Uint64());loss:=effective.Cmp(observed)!=0
  if loss!=c.truncated {t.Fatalf("width oracle failed: effective=%s receipt=%s",effective,observed)}
  t.Logf("cap=%s tip=%s required_wei=%s funded=%t effective=%s receipt64=%s delta_wei=%s",c.cap,c.tip,required,c.funded,effective,observed,new(big.Int).Mul(gas,new(big.Int).Sub(effective,observed)))
 })}
}