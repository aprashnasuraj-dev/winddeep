// Independent necessary-condition oracle, NOT certified Electroneum runtime or proof of consensus admission.
package feeoracle
import("math/big";"testing")
func TestFeeAdmissionNecessaryConditions(t *testing.T){
 n:=new(big.Int).Lsh(big.NewInt(1),64); base:=big.NewInt(1000000000); gas:=big.NewInt(21000)
 cases:=[]struct{name string; cap,tip,balance *big.Int; wantOK,wantOverflow bool}{
 {"funded_boundary_Nminus1",new(big.Int).Sub(new(big.Int).Set(n),big.NewInt(1)),new(big.Int).Sub(new(big.Int).Set(n),big.NewInt(1)),nil,true,false},
 {"funded_boundary_N",new(big.Int).Set(n),new(big.Int).Set(n),nil,true,true},
 {"funded_boundary_Nplus1",new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),nil,true,true},
 {"underfunded_Nplus1",new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),big.NewInt(0),false,true},
 {"low_tip_high_cap",new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),big.NewInt(1),nil,true,false},
 {"tip_exceeds_cap",new(big.Int).Set(n),new(big.Int).Add(new(big.Int).Set(n),big.NewInt(1)),nil,false,true},
 {"cap_below_base",big.NewInt(1),big.NewInt(1),nil,false,false},
 {"cap_exceeds_256bits",new(big.Int).Lsh(big.NewInt(1),256),big.NewInt(1),nil,false,false},
 }
 for _,c:=range cases{t.Run(c.name,func(t *testing.T){
  upfront:=new(big.Int).Mul(c.cap,gas);balance:=new(big.Int).Set(upfront);if c.balance!=nil{balance.Set(c.balance)}
  ok:=c.cap.BitLen()<=256&&c.tip.BitLen()<=256&&c.cap.Cmp(c.tip)>=0&&c.cap.Cmp(base)>=0&&balance.Cmp(upfront)>=0
  tipEffective:=new(big.Int).Sub(c.cap,base);if tipEffective.Cmp(c.tip)>0{tipEffective.Set(c.tip)}
  effective:=new(big.Int).Add(base,tipEffective)
  overflow:=effective.Cmp(n)>=0
  if ok!=c.wantOK||overflow!=c.wantOverflow{t.Fatalf("ok=%v want=%v overflow=%v want=%v",ok,c.wantOK,overflow,c.wantOverflow)}
  t.Logf("necessary_admission=%v effective_wei=%s upfront_wei=%s overflow=%v",ok,effective,upfront,overflow)
 })}
}
