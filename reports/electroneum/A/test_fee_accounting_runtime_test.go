// Worker A: certified-source actual ApplyMessage fee/supply delta checks.
// Tests isolated state transition semantics; NOT production signed-tx builder/import parity.
package core

import (
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/params"
)

func workerAFeeEVM(t *testing.T) (*vm.EVM,*state.StateDB,common.Address,common.Address,common.Address) {
 t.Helper()
 st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil)
 if err!=nil {t.Fatal(err)}
 sender,to,miner:=common.Address{1},common.Address{2},common.Address{3}
 st.SetBalance(sender,big.NewInt(1000000000))
 cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0)}
 context:=vm.BlockContext{
  CanTransfer:CanTransfer,Transfer:Transfer,
  GetHash:func(uint64) common.Hash{return common.Hash{}},
  Coinbase:miner,BlockNumber:big.NewInt(1),BaseFee:big.NewInt(8),
  GasLimit:1000000,
 }
 return vm.NewEVM(context,vm.TxContext{},st,cfg,vm.Config{}),st,sender,to,miner
}

func workerAFeeMessage(sender,to common.Address,price,cap,tip int64,priority common.PublicKey, data []byte) types.Message {
 return types.NewMessage(sender,&to,0,big.NewInt(0),50000,big.NewInt(price),big.NewInt(cap),big.NewInt(tip),data,nil,true,priority)
}

func TestWorkerAFeeAndBurnStateTransition(t *testing.T) {
 t.Run("valid_legacy_london",func(t *testing.T) {
  evm,st,sender,to,miner:=workerAFeeEVM(t)
  msg:=workerAFeeMessage(sender,to,10,10,2,common.PublicKey{},nil)
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err!=nil||result==nil||result.Err!=nil {t.Fatalf("valid transition result=%v err=%v",result,err)}
  used:=new(big.Int).SetUint64(result.UsedGas)
  debit:=new(big.Int).Mul(used,big.NewInt(10))
  expectedSender:=new(big.Int).Sub(big.NewInt(1000000000),debit)
  expectedMiner:=new(big.Int).Mul(used,big.NewInt(2))
  if st.GetBalance(sender).Cmp(expectedSender)!=0||st.GetBalance(miner).Cmp(expectedMiner)!=0 {
   t.Fatalf("independent gas ledger mismatch sender=%s/%s miner=%s/%s",st.GetBalance(sender),expectedSender,st.GetBalance(miner),expectedMiner)
  }
  sum:=new(big.Int).Add(st.GetBalance(sender),st.GetBalance(miner))
  sum.Add(sum,st.GetBalance(to))
  burned:=new(big.Int).Mul(used,big.NewInt(8))
  expectedTotal:=new(big.Int).Sub(big.NewInt(1000000000),burned)
  if sum.Cmp(expectedTotal)!=0 {t.Fatalf("independent base fee burn mismatch sum=%s expected=%s",sum,expectedTotal)}
  // Deliberately weakened oracle (tip counted as full gas price) must differ.
  wrongTip:=new(big.Int).Mul(used,big.NewInt(10))
  if wrongTip.Cmp(expectedMiner)==0 {t.Fatal("weakened tip oracle did not detect base-fee diversion")}
  t.Logf("A_FEE_LONDON_LEDGER_PASS gas=%d burned=%s tip=%s",result.UsedGas,burned,expectedMiner)
 })
 t.Run("evm_revert_still_pays_gas",func(t *testing.T){
  evm,st,sender,to,miner:=workerAFeeEVM(t)
  // PUSH1 0, PUSH1 0, REVERT
  st.SetCode(to,[]byte{0x60,0,0x60,0,0xfd})
  msg:=workerAFeeMessage(sender,to,10,10,2,common.PublicKey{},nil)
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err!=nil||result==nil||!result.Failed() {t.Fatalf("expected EVM failure with nil core error, result=%v err=%v",result,err)}
  used:=new(big.Int).SetUint64(result.UsedGas)
  expectedSender:=new(big.Int).Sub(big.NewInt(1000000000),new(big.Int).Mul(used,big.NewInt(10)))
  expectedMiner:=new(big.Int).Mul(used,big.NewInt(2))
  if st.GetBalance(sender).Cmp(expectedSender)!=0||st.GetBalance(miner).Cmp(expectedMiner)!=0||st.GetBalance(to).Sign()!=0 {
   t.Fatalf("reverted receipt fee ledger mismatch sender=%s miner=%s to=%s",st.GetBalance(sender),st.GetBalance(miner),st.GetBalance(to))
  }
  t.Logf("A_FEE_REVERT_GAS_CHARGED_PASS gas=%d",result.UsedGas)
 })
 t.Run("core_insufficient_funds_rejected",func(t *testing.T){
  evm,st,sender,to,miner:=workerAFeeEVM(t)
  st.SetBalance(sender,big.NewInt(1))
  msg:=workerAFeeMessage(sender,to,10,10,2,common.PublicKey{},nil)
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err==nil||result!=nil {t.Fatalf("insufficient funds accepted: result=%v err=%v",result,err)}
  if st.GetBalance(sender).Cmp(big.NewInt(1))!=0||st.GetBalance(miner).Sign()!=0 {
   t.Fatal("core rejection changed economic balances")
  }
  t.Log("A_FEE_CORE_REJECTION_PRESERVES_BALANCES")
 })
 t.Run("priority_waiver_no_debit",func(t *testing.T){
  evm,st,sender,to,miner:=workerAFeeEVM(t)
  pk:=testPriorityPubKey()
  st.SetPriorityTransactors(common.PriorityTransactorMap{pk:{EntityName:"Fixture",IsGasPriceWaiver:true}})
  msg:=workerAFeeMessage(sender,to,0,0,0,pk,nil)
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err!=nil||result==nil||result.Err!=nil {t.Fatalf("waiver priority rejected: result=%v err=%v",result,err)}
  if st.GetBalance(sender).Cmp(big.NewInt(1000000000))!=0||st.GetBalance(miner).Sign()!=0 {
   t.Fatalf("waiver charged fee sender=%s miner=%s",st.GetBalance(sender),st.GetBalance(miner))
  }
  t.Log("A_FEE_WAIVER_ZERO_DEBIT_PASS")
 })
}
