// Certified scratch-only signed EIP-1559 transaction processing boundary.
// Not a full consensus-validated canonical block import.
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
func TestWorkerASignedFee64Processing(t *testing.T) {
 keyBytes:=make([]byte,32);keyBytes[31]=1
 key,err:=crypto.ToECDSA(keyBytes);if err!=nil {t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 to,miner:=common.Address{2},common.Address{3}
 cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
 signer:=types.MakeSigner(cfg,big.NewInt(1))
 for _,offset:=range []int64{-1,0,1} {
  for _,mode:=range []string{"success","revert","unfunded"} {
   t.Run(mode+"_"+big.NewInt(offset).String(),func(t *testing.T){
    st,e:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if e!=nil {t.Fatal(e)}
    gasLimit:=uint64(21000);if mode=="revert" {gasLimit=50000;st.SetCode(to,[]byte{0x60,0,0x60,0,0xfd})}
    boundary:=new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1),64),new(big.Int).SetUint64(gasLimit))
    cap:=new(big.Int).Add(boundary,big.NewInt(offset))
    escrow:=new(big.Int).Mul(cap,new(big.Int).SetUint64(gasLimit))
    initial:=new(big.Int).Add(escrow,big.NewInt(1000000))
    if mode=="unfunded" {initial.Sub(escrow,big.NewInt(1))}
    st.SetBalance(sender,initial)
    tx,e:=types.SignNewTx(key,signer,&types.DynamicFeeTx{ChainID:big.NewInt(1337),Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:cap,Gas:gasLimit,To:&to,Value:big.NewInt(0)})
    if e!=nil {t.Fatal(e)}
    wire,e:=tx.MarshalBinary();if e!=nil {t.Fatal(e)}
    var decoded types.Transaction
    if e=decoded.UnmarshalBinary(wire);e!=nil {t.Fatal(e)}
    recovered,e:=types.Sender(signer,&decoded);if e!=nil||recovered!=sender {t.Fatalf("sender recovery %v %v",recovered,e)}
    header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
    used:=uint64(0)
    receipt,e:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(gasLimit),st,header,&decoded,&used,vm.Config{})
    if mode=="unfunded" {
     if e==nil||receipt!=nil {t.Fatalf("unfunded accepted: receipt=%v err=%v",receipt,e)}
     if st.GetBalance(sender).Cmp(initial)!=0||st.GetBalance(miner).Sign()!=0 {t.Fatal("rejected transaction changed balances")}
     t.Logf("REJECT signed offset=%d escrow=%s",offset,escrow);return
    }
    if e!=nil||receipt==nil {t.Fatalf("signed processing failed: %v",e)}
    if mode=="revert" && receipt.Status!=types.ReceiptStatusFailed {t.Fatalf("revert status=%d",receipt.Status)}
    if mode=="success" && receipt.Status!=types.ReceiptStatusSuccessful {t.Fatalf("success status=%d",receipt.Status)}
    gas:=new(big.Int).SetUint64(receipt.GasUsed)
    fee:=new(big.Int).Mul(gas,big.NewInt(10))
    tip:=new(big.Int).Mul(gas,big.NewInt(2))
    burn:=new(big.Int).Mul(gas,big.NewInt(8))
    expectedSender:=new(big.Int).Sub(initial,fee)
    if st.GetBalance(sender).Cmp(expectedSender)!=0||st.GetBalance(miner).Cmp(tip)!=0||st.GetBalance(to).Sign()!=0 {t.Fatalf("ledger mismatch sender=%s miner=%s gas=%d",st.GetBalance(sender),st.GetBalance(miner),receipt.GasUsed)}
    total:=new(big.Int).Add(st.GetBalance(sender),st.GetBalance(miner))
    if total.Cmp(new(big.Int).Sub(initial,burn))!=0 {t.Fatal("burn conservation mismatch")}
    if used!=receipt.GasUsed {t.Fatal("cumulative gas mismatch")}
    t.Logf("PASS signed mode=%s offset=%d gas=%d fee=%s burn=%s tip=%s",mode,offset,receipt.GasUsed,fee,burn,tip)
   })
  }
 }
}
