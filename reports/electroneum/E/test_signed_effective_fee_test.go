// Class E: signed, funded, isolated state-transition boundary. Not a canonical block import.
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
func TestWorkerEActualEffectiveFeeWidth(t *testing.T) {
 keyBytes:=make([]byte,32);keyBytes[31]=9
 key,err:=crypto.ToECDSA(keyBytes);if err!=nil {t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 to,miner:=common.Address{2},common.Address{3}
 cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
 signer:=types.MakeSigner(cfg,big.NewInt(1))
 n:=new(big.Int).Lsh(big.NewInt(1),64)
 for _,offset:=range []int64{-1,0,1} {
  for _,funded:=range []bool{true,false} {
   label:="funded";if !funded {label="underfunded"}
   t.Run(label+"_"+big.NewInt(offset).String(),func(t *testing.T){
    st,e:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if e!=nil {t.Fatal(e)}
    price:=new(big.Int).Add(new(big.Int).Set(n),big.NewInt(offset))
    tip:=new(big.Int).Sub(new(big.Int).Set(price),big.NewInt(1))
    gas:=uint64(21000)
    escrow:=new(big.Int).Mul(new(big.Int).Set(price),new(big.Int).SetUint64(gas))
    initial:=new(big.Int).Add(new(big.Int).Set(escrow),big.NewInt(1000000))
    if !funded {initial.Sub(escrow,big.NewInt(1))}
    st.SetBalance(sender,new(big.Int).Set(initial))
    tx,e:=types.SignNewTx(key,signer,&types.DynamicFeeTx{ChainID:big.NewInt(1337),Nonce:0,GasTipCap:tip,GasFeeCap:price,Gas:gas,To:&to,Value:big.NewInt(0)})
    if e!=nil {t.Fatal(e)}
    wire,e:=tx.MarshalBinary();if e!=nil {t.Fatal(e)}
    var decoded types.Transaction
    if e=decoded.UnmarshalBinary(wire);e!=nil {t.Fatal(e)}
    recovered,e:=types.Sender(signer,&decoded);if e!=nil||recovered!=sender {t.Fatalf("signed sender recovery: %v %v",recovered,e)}
    header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(1)}
    used:=uint64(0)
    receipt,e:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(gas),st,header,&decoded,&used,vm.Config{})
    if !funded {
     if e==nil||receipt!=nil {t.Fatalf("underfunded accepted: receipt=%v error=%v",receipt,e)}
     if st.GetBalance(sender).Cmp(initial)!=0 {t.Fatal("underfunded changed sender balance")}
     t.Logf("REJECT price=%s",price);return
    }
    if e!=nil||receipt==nil {t.Fatalf("signed transaction processing failed price=%s error=%v",price,e)}
    if receipt.Status!=types.ReceiptStatusSuccessful||receipt.GasUsed!=gas {t.Fatalf("unexpected receipt status=%d gas=%d",receipt.Status,receipt.GasUsed)}
    expectedSender:=new(big.Int).Sub(new(big.Int).Set(initial),escrow)
    expectedMiner:=new(big.Int).Mul(new(big.Int).Set(tip),new(big.Int).SetUint64(gas))
    if st.GetBalance(sender).Cmp(expectedSender)!=0||st.GetBalance(miner).Cmp(expectedMiner)!=0 {
     t.Fatalf("ledger mismatch sender=%s miner=%s expectedSender=%s expectedMiner=%s",st.GetBalance(sender),st.GetBalance(miner),expectedSender,expectedMiner)
    }
    actualFee:=new(big.Int).Sub(initial,st.GetBalance(sender))
    if actualFee.Cmp(escrow)!=0 {t.Fatalf("fee oracle mismatch got=%s expected=%s",actualFee,escrow)}
    t.Logf("SIGNED_EFFECTIVE_FEE price=%s fee=%s receiptGas=%d uint64Narrow=%d",price,actualFee,receipt.GasUsed,price.Uint64())
   })
  }
 }
}
