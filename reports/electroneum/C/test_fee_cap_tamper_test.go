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

// Hostile RPC middleware changes maxFeePerGas after the owner signs a
// transaction. The owner's actual account must never pay the modified fee.
func TestWorkerCFeeCapTamperNoOwnerDebit(t *testing.T) {
 for _,tc:=range []struct{seed byte;funds,originalCap,hostileCap int64}{
  {111,10000000,10,90},{113,20000000,12,150},{127,30000000,15,300},
 } {
  kb:=make([]byte,32);kb[31]=tc.seed
  key,err:=crypto.ToECDSA(kb);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  to,miner:=common.Address{0x41},common.Address{0x42}
  chain:=big.NewInt(1337)
  cfg:=&params.ChainConfig{ChainID:chain,LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
  st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if err!=nil{t.Fatal(err)}
  st.SetBalance(owner,big.NewInt(tc.funds))
  signer:=types.NewLondonSigner(chain)
  signed,err:=types.SignNewTx(key,signer,&types.DynamicFeeTx{ChainID:chain,Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(tc.originalCap),Gas:21000,To:&to,Value:big.NewInt(1234)})
  if err!=nil{t.Fatal(err)}
  raw,err:=signed.MarshalBinary();if err!=nil{t.Fatal(err)}
  var honest types.Transaction
  if err=honest.UnmarshalBinary(raw);err!=nil{t.Fatal(err)}
  sender,err:=types.Sender(signer,&honest);if err!=nil||sender!=owner{t.Fatalf("honest signer mismatch: %v",err)}
  v,r,s:=honest.RawSignatureValues()
  tampered:=types.NewTx(&types.DynamicFeeTx{ChainID:chain,Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(tc.hostileCap),Gas:21000,To:&to,Value:big.NewInt(1234),V:new(big.Int).Set(v),R:new(big.Int).Set(r),S:new(big.Int).Set(s)})
  hostileRaw,err:=tampered.MarshalBinary();if err!=nil{t.Fatal(err)}
  var hostile types.Transaction
  if err=hostile.UnmarshalBinary(hostileRaw);err!=nil{t.Fatal(err)}
  hostileSender,recoveryErr:=types.Sender(signer,&hostile)
  if recoveryErr==nil&&hostileSender==owner{t.Fatalf("C_FEE_OWNER_BINDING_BROKEN seed=%d",tc.seed)}
  header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
  before:=new(big.Int).Set(st.GetBalance(owner))
  var used uint64
  receipt,applyErr:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,&hostile,&used,vm.Config{})
  if st.GetBalance(owner).Cmp(before)!=0||st.GetNonce(owner)!=0{
   t.Fatalf("C_FEE_UNAUTHORIZED_DEBIT seed=%d before=%s after=%s nonce=%d err=%v",tc.seed,before,st.GetBalance(owner),st.GetNonce(owner),applyErr)
  }
  if receipt!=nil&&receipt.Status==types.ReceiptStatusSuccessful&&recoveryErr==nil&&hostileSender==owner{
   t.Fatalf("C_FEE_UNAUTHORIZED_ACCEPT seed=%d",tc.seed)
  }
  t.Logf("C_FEE_TAMPER_ORACLE seed=%d original_cap=%d hostile_cap=%d owner_balance=%s owner_nonce=%d recovered=%s recovery_err=%v apply_err=%v",tc.seed,tc.originalCap,tc.hostileCap,st.GetBalance(owner),st.GetNonce(owner),hostileSender,recoveryErr,applyErr)
 }
}
