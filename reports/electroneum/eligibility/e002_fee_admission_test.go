// E002: enforce the distinction between an actual RPC serialization error
// and an economically admissible transaction under default fee caps.
// Copy into a disposable certified-source internal/ethapi package.
package ethapi

import (
 "math/big"
 "testing"
)

func TestEligibilityE002HighFeeDefaultAdmissionControls(t *testing.T){
 high:=new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1),64),big.NewInt(12345))
 const gas uint64=21000
 const defaultRPCTxFeeCap float64=100000
 total:=new(big.Int).Mul(high,new(big.Int).SetUint64(gas))
 if err:=checkTxFee(high,gas,defaultRPCTxFeeCap);err==nil{
  t.Fatal("oversized transaction unexpectedly bypassed default configured RPC tx fee cap")
 }
 t.Logf("ELIGIBILITY_E002_DEFAULT_RPC_CAP_REJECTS_HIGH_FEE_PASS gas_price=%s gas=%d total_base_units=%s",high,gas,total)
 if err:=checkTxFee(high,gas,0);err!=nil{
  t.Fatalf("cap=0 should remove the RPC fee-cap check: %v",err)
 }
 t.Log("ELIGIBILITY_E002_DISABLED_RPC_CAP_ALLOWS_FEE_CHECK_PASS not_block_inclusion")
 if err:=checkTxFee(big.NewInt(10),gas,defaultRPCTxFeeCap);err!=nil{
  t.Fatalf("reasonable fee control rejected: %v",err)
 }
 t.Log("ELIGIBILITY_E002_STANDARD_FEE_POSITIVE_CONTROL_PASS")
 // A disabled RPC fee cap is not proof that a signed transaction with this
 // enormous price can be funded, admitted, included, or reflected by an explorer.
}
