package core

import (
 "math"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

// TestWorkerATransactionCostOverflowOracle checks whether attacker-chosen
// gasLimit, gasPrice and value can wrap the transaction-cost primitive.
// A primitive mismatch is NOT canonical admission or a reportable exploit.
func TestWorkerATransactionCostOverflowOracle(t *testing.T) {
 keyBytes:=make([]byte,32);keyBytes[31]=47
 key,err:=crypto.ToECDSA(keyBytes);if err!=nil {t.Fatal(err)}
 to:=common.Address{0x47}
 max:=new(big.Int).SetUint64(math.MaxUint64)
 cases:=[]struct{name string; gas uint64; price,value *big.Int}{
  {"honest",21000,big.NewInt(1),big.NewInt(7)},
  {"zero_price",21000,big.NewInt(0),big.NewInt(7)},
  {"uint64_product_boundary",math.MaxUint64,new(big.Int).Set(max),big.NewInt(7)},
  {"uint256_value_boundary",21000,big.NewInt(1),new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1),256),big.NewInt(1))},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  tx:=types.NewTransaction(0,to,tc.value,tc.gas,tc.price,nil)
  signed,err:=types.SignTx(tx,types.HomesteadSigner{},key);if err!=nil {t.Fatal(err)}
  recovered,err:=types.Sender(types.HomesteadSigner{},signed);if err!=nil {t.Fatal(err)}
  expectedSender:=crypto.PubkeyToAddress(key.PublicKey)
  if recovered!=expectedSender {t.Fatalf("A_COST_BREACH case=%s signer_mismatch",tc.name)}
  oracle:=new(big.Int).Mul(new(big.Int).SetUint64(tc.gas),tc.price)
  oracle.Add(oracle,tc.value)
  got:=signed.Cost()
  if got.Cmp(oracle)!=0 {t.Fatalf("A_COST_BREACH case=%s expected=%s actual=%s",tc.name,oracle,got)}
  t.Logf("A_COST_ORACLE case=%s expected=%s actual=%s signed=true",tc.name,oracle,got)
 })}
}
