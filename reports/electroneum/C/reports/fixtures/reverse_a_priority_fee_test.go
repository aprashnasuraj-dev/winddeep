// Reverse Worker R: A fee/priority cache parity and supply accounting.
// Copied only into certified scratch core package. Synthetic state, no chain/network.
package core

import (
 "math/big"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/accounts/abi"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/contracts/prioritytransactors"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

func reverseARegistryRuntime(t *testing.T, output []byte) []byte {
 t.Helper()
 if len(output)>65535 {t.Fatal("ABI output too large")}
 // if calldata size !=0 jump to return block; empty calldata deliberately REVERTs.
 code:=[]byte{0x36,0x60,0x09,0x57,0x60,0x00,0x60,0x00,0xfd,0x5b}
 off:=len(code)+15
 l:=len(output)
 code=append(code,
  0x61,byte(l>>8),byte(l),
  0x61,byte(off>>8),byte(off),
  0x60,0x00,0x39,
  0x61,byte(l>>8),byte(l),
  0x60,0x00,0xf3,
 )
 return append(code,output...)
}

func reverseAPriorityFixture(t *testing.T)(*vm.EVM,*state.StateDB,*params.ChainConfig,common.Address,common.Address,common.Address,common.PublicKey){
 t.Helper()
 st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil)
 if err!=nil{t.Fatal(err)}
 sender:=common.Address{1}; miner:=common.Address{2}; registry:=common.Address{3}
 st.SetBalance(sender,big.NewInt(1_000_000_000))
 k,err:=crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000123")
 if err!=nil{t.Fatal(err)}
 var pk common.PublicKey
 copy(pk[:],crypto.FromECDSAPub(&k.PublicKey))
 parsed,err:=abi.JSON(strings.NewReader(prioritytransactors.ETNPriorityTransactorsInterfaceMetaData.ABI))
 if err!=nil{t.Fatal(err)}
 metas:=[]prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{{
  IsGasPriceWaiver:true,PublicKey:common.Bytes2Hex(pk[:]),Name:"ReverseR",
 }}
 out,err:=parsed.Methods["getTransactors"].Outputs.Pack(metas)
 if err!=nil{t.Fatalf("pack getTransactors output: %v",err)}
 st.SetCode(registry,reverseARegistryRuntime(t,out))
 cfg:=&params.ChainConfig{
  ChainID:big.NewInt(1),HomesteadBlock:big.NewInt(0),EIP150Block:big.NewInt(0),
  EIP155Block:big.NewInt(0),EIP158Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0),
  ConstantinopleBlock:big.NewInt(0),PetersburgBlock:big.NewInt(0),IstanbulBlock:big.NewInt(0),
  BerlinBlock:big.NewInt(0),LondonBlock:big.NewInt(0),PriorityTransactorsContractAddress:registry,
 }
 ctx:=vm.BlockContext{CanTransfer:CanTransfer,Transfer:Transfer,GetHash:func(uint64)common.Hash{return common.Hash{}},
  Coinbase:miner,BlockNumber:big.NewInt(1),Time:big.NewInt(1),Difficulty:big.NewInt(1),BaseFee:big.NewInt(8),GasLimit:1_000_000}
 evm:=vm.NewEVM(ctx,vm.TxContext{},st,cfg,vm.Config{})
 initial:=GetPriorityTransactors(evm)
 if got,ok:=initial[pk];!ok||!got.IsGasPriceWaiver {t.Fatalf("real registry static read failed: entries=%d",len(initial))}
 st.SetPriorityTransactors(initial)
 return evm,st,cfg,sender,miner,registry,pk
}

func reverseAMessage(from,to common.Address,gas uint64,data []byte) types.Message {
 return types.NewMessage(from,&to,0,big.NewInt(0),gas,big.NewInt(10),big.NewInt(10),big.NewInt(2),data,nil,true,common.PublicKey{})
}
func reverseATx(to common.Address,gas uint64,data []byte)*types.Transaction{
 return types.NewTransaction(0,to,big.NewInt(0),gas,big.NewInt(10),data)
}

func TestReverseAPriorityCacheTransactionBoundaries(t *testing.T){
 t.Run("evm_revert_registry_target_refreshes_from_reverted_state",func(t *testing.T){
  evm,st,cfg,sender,miner,registry,pk:=reverseAPriorityFixture(t)
  used:=uint64(0)
  receipt,err:=applyTransaction(reverseAMessage(sender,registry,100000,nil),cfg,nil,&miner,new(GasPool).AddGas(1_000_000),st,big.NewInt(1),common.Hash{9},reverseATx(registry,100000,nil),&used,evm)
  if err!=nil{t.Fatalf("EVM revert became core error: %v",err)}
  if receipt.Status!=types.ReceiptStatusFailed {t.Fatalf("expected failed receipt, got %d",receipt.Status)}
  if got,ok:=st.GetPriorityTransactorByKey(pk);!ok||!got.IsGasPriceWaiver {t.Fatal("reverted registry-target tx poisoned/cleared cached privilege list")}
  t.Log("REVERSE_A_REGISTRY_EVM_REVERT_CACHE_REBUILT_FROM_REVERTED_STATE_PASS")
 })
 t.Run("successful_registry_target_refreshes_same_state",func(t *testing.T){
  evm,st,cfg,sender,miner,registry,pk:=reverseAPriorityFixture(t)
  used:=uint64(0)
  // Non-empty calldata takes the contract's successful constant-return branch.
  receipt,err:=applyTransaction(reverseAMessage(sender,registry,100000,[]byte{1}),cfg,nil,&miner,new(GasPool).AddGas(1_000_000),st,big.NewInt(1),common.Hash{9},reverseATx(registry,100000,[]byte{1}),&used,evm)
  if err!=nil||receipt.Status!=types.ReceiptStatusSuccessful {t.Fatalf("success control err=%v receipt=%v",err,receipt)}
  if _,ok:=st.GetPriorityTransactorByKey(pk);!ok {t.Fatal("successful registry target lost priority cache")}
  t.Log("REVERSE_A_REGISTRY_SUCCESS_CACHE_REFRESH_PASS")
 })
 t.Run("core_error_before_refresh_preserves_cache_when_miner_snapshot_reverts",func(t *testing.T){
  evm,st,cfg,sender,miner,registry,pk:=reverseAPriorityFixture(t)
  snap:=st.Snapshot();used:=uint64(0)
  _,err:=applyTransaction(reverseAMessage(sender,registry,100,nil),cfg,nil,&miner,new(GasPool).AddGas(1_000_000),st,big.NewInt(1),common.Hash{9},reverseATx(registry,100,nil),&used,evm)
  if err==nil {t.Fatal("intrinsic-gas core error was accepted")}
  st.RevertToSnapshot(snap) // miner commitTransaction behavior
  if _,ok:=st.GetPriorityTransactorByKey(pk);!ok {t.Fatal("core error path mutated non-journaled priority cache")}
  t.Log("REVERSE_A_CORE_ERROR_SNAPSHOT_CACHE_PRESERVED_PASS")
 })
}

func TestReverseALondonSupplyAccounting(t *testing.T){
 evm,st,cfg,sender,miner,registry,_:=reverseAPriorityFixture(t)
 _=cfg; _=registry
 to:=common.Address{4}
 st.SetBalance(sender,big.NewInt(1_000_000_000))
 msg:=types.NewMessage(sender,&to,0,big.NewInt(0),50000,big.NewInt(10),big.NewInt(10),big.NewInt(2),nil,nil,true,common.PublicKey{})
 before:=new(big.Int).Set(st.GetBalance(sender))
 result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
 if err!=nil||result==nil||result.Err!=nil {t.Fatalf("ordinary London transition failed result=%v err=%v",result,err)}
 used:=new(big.Int).SetUint64(result.UsedGas)
 senderWant:=new(big.Int).Sub(before,new(big.Int).Mul(new(big.Int).Set(used),big.NewInt(10)))
 minerWant:=new(big.Int).Mul(new(big.Int).Set(used),big.NewInt(2))
 burnWant:=new(big.Int).Mul(new(big.Int).Set(used),big.NewInt(8))
 if st.GetBalance(sender).Cmp(senderWant)!=0||st.GetBalance(miner).Cmp(minerWant)!=0 {t.Fatalf("fee ledger mismatch sender=%s/%s miner=%s/%s",st.GetBalance(sender),senderWant,st.GetBalance(miner),minerWant)}
 total:=new(big.Int).Add(st.GetBalance(sender),st.GetBalance(miner));total.Add(total,st.GetBalance(to))
 expectedTotal:=new(big.Int).Sub(before,burnWant)
 if total.Cmp(expectedTotal)!=0 {t.Fatalf("base fee not burned as expected total=%s want=%s",total,expectedTotal)}
 t.Logf("REVERSE_A_LONDON_FEE_BURN_TIP_LEDGER_PASS gas=%d burn=%s tip=%s",result.UsedGas,burnWant,minerWant)
}


func TestReverseALondonRevertAndWaiverAccounting(t *testing.T){
 t.Run("evm_revert_charges_gas_burns_basefee_and_preserves_value_state",func(t *testing.T){
  evm,st,_,sender,miner,_,_:=reverseAPriorityFixture(t)
  target:=common.Address{5}
  st.SetCode(target,[]byte{0x60,0x00,0x60,0x00,0xfd}) // REVERT(0,0)
  st.SetBalance(sender,big.NewInt(1_000_000_000))
  before:=new(big.Int).Set(st.GetBalance(sender))
  msg:=types.NewMessage(sender,&target,0,big.NewInt(0),50000,big.NewInt(10),big.NewInt(10),big.NewInt(2),nil,nil,true,common.PublicKey{})
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err!=nil||result==nil||!result.Failed(){t.Fatalf("expected EVM revert with nil core error result=%v err=%v",result,err)}
  used:=new(big.Int).SetUint64(result.UsedGas)
  senderWant:=new(big.Int).Sub(before,new(big.Int).Mul(new(big.Int).Set(used),big.NewInt(10)))
  tipWant:=new(big.Int).Mul(new(big.Int).Set(used),big.NewInt(2))
  burnWant:=new(big.Int).Mul(new(big.Int).Set(used),big.NewInt(8))
  if st.GetBalance(sender).Cmp(senderWant)!=0||st.GetBalance(miner).Cmp(tipWant)!=0||st.GetBalance(target).Sign()!=0 {
   t.Fatalf("revert ledger mismatch sender=%s/%s miner=%s/%s target=%s",st.GetBalance(sender),senderWant,st.GetBalance(miner),tipWant,st.GetBalance(target))
  }
  total:=new(big.Int).Add(st.GetBalance(sender),st.GetBalance(miner));total.Add(total,st.GetBalance(target))
  if want:=new(big.Int).Sub(before,burnWant);total.Cmp(want)!=0 {t.Fatalf("revert basefee burn mismatch total=%s want=%s",total,want)}
  t.Logf("REVERSE_A_EVM_REVERT_FEE_BURN_PASS gas=%d burn=%s tip=%s",result.UsedGas,burnWant,tipWant)
 })

 t.Run("priority_waiver_zero_fee_has_no_sender_or_miner_delta",func(t *testing.T){
  evm,st,_,sender,miner,_,pk:=reverseAPriorityFixture(t)
  target:=common.Address{6}
  st.SetBalance(sender,big.NewInt(1_000_000_000))
  before:=new(big.Int).Set(st.GetBalance(sender))
  msg:=types.NewMessage(sender,&target,0,big.NewInt(0),50000,big.NewInt(0),big.NewInt(0),big.NewInt(0),nil,nil,true,pk)
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err!=nil||result==nil||result.Failed(){t.Fatalf("waiver tx failed result=%v err=%v",result,err)}
  if st.GetBalance(sender).Cmp(before)!=0||st.GetBalance(miner).Sign()!=0 {
   t.Fatalf("waiver produced fee delta sender=%s/%s miner=%s",st.GetBalance(sender),before,st.GetBalance(miner))
  }
  t.Logf("REVERSE_A_PRIORITY_WAIVER_ZERO_FEE_PASS gas=%d",result.UsedGas)
 })

 t.Run("waiver_with_nonzero_fee_fields_rejected_before_execution",func(t *testing.T){
  evm,st,_,sender,miner,_,pk:=reverseAPriorityFixture(t)
  target:=common.Address{7}
  before:=new(big.Int).Set(st.GetBalance(sender))
  snap:=st.Snapshot()
  msg:=types.NewMessage(sender,&target,0,big.NewInt(0),50000,big.NewInt(1),big.NewInt(1),big.NewInt(1),nil,nil,true,pk)
  result,err:=ApplyMessage(evm,msg,new(GasPool).AddGas(50000))
  if err==nil||result!=nil {t.Fatalf("malformed waiver fee fields accepted result=%v err=%v",result,err)}
  st.RevertToSnapshot(snap)
  if st.GetBalance(sender).Cmp(before)!=0||st.GetBalance(miner).Sign()!=0 {t.Fatal("rejected waiver changed economic state after caller rollback")}
  t.Log("REVERSE_A_PRIORITY_WAIVER_NONZERO_FEE_REJECTED_PASS")
 })
}
