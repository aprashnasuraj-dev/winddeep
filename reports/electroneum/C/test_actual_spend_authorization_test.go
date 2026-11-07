// Class C: real certified ApplyTransaction authorization and state accounting.
// Synthetic keys, in-memory StateDB, no network, no canonical QBFT block.
package core

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

func TestWorkerCActualSpendAuthorization(t *testing.T) {
 for _,seed:=range []byte{11,17,23} {
  t.Run(string(rune('A'+seed%26)),func(t *testing.T){
   keybytes:=make([]byte,32);keybytes[31]=seed
   key,err:=crypto.ToECDSA(keybytes);if err!=nil{t.Fatal(err)}
   owner:=crypto.PubkeyToAddress(key.PublicKey)
   recipient:=common.Address{0x81};other:=common.Address{0x82};miner:=common.Address{0x83}
   cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
   st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if err!=nil{t.Fatal(err)}
   const initial int64=10000000
   st.SetBalance(owner,big.NewInt(initial))
   header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
   var used uint64
   signer:=types.MakeSigner(cfg,big.NewInt(1))
   sign:=func(nonce uint64,domain int64,to common.Address,value int64)*types.Transaction{
    t.Helper()
    tx,e:=types.SignNewTx(key,types.NewLondonSigner(big.NewInt(domain)),&types.DynamicFeeTx{ChainID:big.NewInt(domain),Nonce:nonce,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),Gas:21000,To:&to,Value:big.NewInt(value)})
    if e!=nil{t.Fatal(e)}
    raw,e:=tx.MarshalBinary();if e!=nil{t.Fatal(e)}
    var decoded types.Transaction
    if e=decoded.UnmarshalBinary(raw);e!=nil{t.Fatal(e)}
    return &decoded
   }
   apply:=func(tx *types.Transaction)(*types.Receipt,error){
    return ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,tx,&used,vm.Config{})
   }
   snapshot:=func()string{
    return st.GetBalance(owner).String()+"/"+st.GetBalance(recipient).String()+"/"+st.GetBalance(other).String()+"/"+st.GetBalance(miner).String()+"/"+new(big.Int).SetUint64(st.GetNonce(owner)).String()+"/"+new(big.Int).SetUint64(used).String()
   }
   reject:=func(label string,tx *types.Transaction){
    t.Helper();before:=snapshot()
    receipt,e:=apply(tx)
    if e==nil||receipt!=nil{t.Fatalf("%s accepted: receipt=%v err=%v",label,receipt,e)}
    if after:=snapshot();after!=before{t.Fatalf("%s mutated owner ledger: %s -> %s",label,before,after)}
    t.Logf("C_AUTH_REJECT_%s seed=%d error=%v",label,seed,e)
   }
   valid:=sign(0,1337,recipient,1000)
   recovered,e:=types.Sender(signer,valid);if e!=nil||recovered!=owner{t.Fatalf("honest signer %s %v",recovered,e)}
   receipt,e:=apply(valid);if e!=nil||receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful{t.Fatalf("honest transfer %v %v",receipt,e)}
   if st.GetNonce(owner)!=1||st.GetBalance(owner).Cmp(big.NewInt(initial-211000))!=0||st.GetBalance(recipient).Cmp(big.NewInt(1000))!=0||st.GetBalance(miner).Cmp(big.NewInt(42000))!=0{t.Fatalf("independent honest accounting mismatch: %s",snapshot())}
   t.Logf("C_AUTH_HONEST_ACCEPTED seed=%d ledger=%s",seed,snapshot())
   reject("DUPLICATE_NONCE",valid)
   // Future nonce is not executable even if a txpool could queue it.
   reject("FUTURE_NONCE",sign(2,1337,recipient,1000))
   // After the first transfer the owner has 9,789,000. The next
   // transaction must reserve 210,000 gas before transferring value.
   // 9,579,001 exceeds the exact affordability boundary by one wei.
   reject("INSUFFICIENT_BOUNDARY",sign(1,1337,recipient,9579001))
   reject("CROSS_CHAIN",sign(1,1338,recipient,1000))
   reject("INSUFFICIENT",sign(1,1337,recipient,initial+1))
   // Valid ECDSA bytes from original tx but signed payload changes: recovery must
   // not authorize the original owner; a different recovered sender has zero funds.
   v,r,s:=valid.RawSignatureValues()
   for _,tc:=range []struct{name string;to common.Address;value int64}{{"ALTERED_RECIPIENT",other,1000},{"ALTERED_VALUE",recipient,1001}}{
    // DynamicFeeTx retains original chain ID and signature values.
    forged:=types.NewTx(&types.DynamicFeeTx{ChainID:big.NewInt(1337),Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),Gas:21000,To:&tc.to,Value:big.NewInt(tc.value),V:new(big.Int).Set(v),R:new(big.Int).Set(r),S:new(big.Int).Set(s)})
    from,e:=types.Sender(signer,forged)
    if e==nil&&from==owner{t.Fatalf("%s recovered owner after mutation",tc.name)}
    reject(tc.name,forged)
   }
   receipt,e=apply(sign(1,1337,recipient,2000))
   if e!=nil||receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful{t.Fatalf("second honest transfer %v %v",receipt,e)}
   if st.GetNonce(owner)!=2||used!=42000||st.GetBalance(owner).Cmp(big.NewInt(initial-423000))!=0||st.GetBalance(recipient).Cmp(big.NewInt(3000))!=0||st.GetBalance(other).Sign()!=0||st.GetBalance(miner).Cmp(big.NewInt(84000))!=0{t.Fatalf("independent final accounting mismatch: %s",snapshot())}
   sum:=new(big.Int).Add(st.GetBalance(owner),st.GetBalance(recipient));sum.Add(sum,st.GetBalance(other));sum.Add(sum,st.GetBalance(miner))
   if sum.Cmp(big.NewInt(initial-336000))!=0{t.Fatalf("gas burn conservation got %s",sum)}
   t.Logf("C_AUTH_LEDGER_ORACLE_PASS seed=%d ledger=%s burned=336000",seed,snapshot())
   // Independent exact-affordability positive boundary: total funds exactly
   // equal transfer value plus gas limit * fee cap. A one-wei excess is
   // rejected above; this control must execute with zero owner balance.
   boundaryState,be:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil)
   if be!=nil{t.Fatal(be)}
   boundaryState.SetBalance(owner,big.NewInt(initial))
   boundaryHeader:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
   var boundaryUsed uint64
   exactValue:=initial-int64(21000*10)
   exactTx:=sign(0,1337,recipient,exactValue)
   boundaryReceipt,be:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),boundaryState,boundaryHeader,exactTx,&boundaryUsed,vm.Config{})
   if be!=nil||boundaryReceipt==nil||boundaryReceipt.Status!=types.ReceiptStatusSuccessful{
    t.Fatalf("exact affordability rejected seed=%d receipt=%v err=%v",seed,boundaryReceipt,be)
   }
   if boundaryState.GetBalance(owner).Sign()!=0||
    boundaryState.GetBalance(recipient).Cmp(big.NewInt(exactValue))!=0||
    boundaryState.GetBalance(miner).Cmp(big.NewInt(42000))!=0||
    boundaryState.GetNonce(owner)!=1||boundaryUsed!=21000{
    t.Fatalf("exact affordability ledger mismatch seed=%d owner=%s recipient=%s miner=%s nonce=%d gas=%d",
     seed,boundaryState.GetBalance(owner),boundaryState.GetBalance(recipient),
     boundaryState.GetBalance(miner),boundaryState.GetNonce(owner),boundaryUsed)
   }
   boundarySum:=new(big.Int).Add(boundaryState.GetBalance(owner),boundaryState.GetBalance(recipient))
   boundarySum.Add(boundarySum,boundaryState.GetBalance(miner))
   if boundarySum.Cmp(big.NewInt(initial-168000))!=0{t.Fatalf("exact affordability burn mismatch seed=%d sum=%s",seed,boundarySum)}
   t.Logf("C_AUTH_EXACT_AFFORDABILITY_PASS seed=%d recipient=%d burned=168000",seed,exactValue)

  })
 }
}
