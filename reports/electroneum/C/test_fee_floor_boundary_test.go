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

// Outsider-controlled RPC middleware forwards a correctly signed but under-base-fee
// transaction; the owner has NOT authorized any higher gas cap. Tests actual
// state-transition enforcement, not a mocked RPC backend or QBFT import.
func TestWorkerCFeeFloorBoundary(t *testing.T) {
 for i,tc:=range []struct{seed byte;chain int64;base int64;fund int64}{
  {31,1337,8,1000000},{37,2337,12,2000000},{41,3337,20,3000000},
 } {
  t.Run(string(rune('A'+i)),func(t *testing.T){
   b:=make([]byte,32);b[31]=tc.seed
   key,e:=crypto.ToECDSA(b);if e!=nil{t.Fatal(e)}
   owner:=crypto.PubkeyToAddress(key.PublicKey)
   recipient:=common.Address{0x94};miner:=common.Address{0x95}
   cfg:=&params.ChainConfig{ChainID:big.NewInt(tc.chain),LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
   st,e:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if e!=nil{t.Fatal(e)}
   st.SetBalance(owner,big.NewInt(tc.fund))
   header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(tc.base)}
   signer:=types.MakeSigner(cfg,big.NewInt(1))
   sign:=func(cap int64)*types.Transaction{
    tx,err:=types.SignNewTx(key,types.NewLondonSigner(big.NewInt(tc.chain)),&types.DynamicFeeTx{ChainID:big.NewInt(tc.chain),Nonce:0,GasTipCap:big.NewInt(1),GasFeeCap:big.NewInt(cap),Gas:21000,To:&recipient,Value:big.NewInt(100)})
    if err!=nil{t.Fatal(err)}
    raw,err:=tx.MarshalBinary();if err!=nil{t.Fatal(err)}
    var decoded types.Transaction
    if err=decoded.UnmarshalBinary(raw);err!=nil{t.Fatal(err)}
    from,err:=types.Sender(signer,&decoded);if err!=nil||from!=owner{t.Fatalf("signed control invalid %s %v",from,err)}
    return &decoded
   }
   var used uint64
   bad:=sign(tc.base-1)
   receipt,err:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,bad,&used,vm.Config{})
   if err==nil||receipt!=nil{t.Fatalf("below-base-fee accepted receipt=%v err=%v",receipt,err)}
   if st.GetNonce(owner)!=0||st.GetBalance(owner).Cmp(big.NewInt(tc.fund))!=0||st.GetBalance(recipient).Sign()!=0||used!=0{
    t.Fatalf("rejected transaction mutated state: nonce=%d owner=%s recipient=%s gas=%d",st.GetNonce(owner),st.GetBalance(owner),st.GetBalance(recipient),used)
   }
   t.Logf("C_FEE_FLOOR_REJECT chain=%d base=%d cap=%d error=%v",tc.chain,tc.base,tc.base-1,err)
   good:=sign(tc.base+1)
   receipt,err=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,good,&used,vm.Config{})
   if err!=nil||receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful{t.Fatalf("honest fee control failed receipt=%v err=%v",receipt,err)}
   expected:=tc.fund-100-21000*(tc.base+1)
   if st.GetNonce(owner)!=1||st.GetBalance(owner).Cmp(big.NewInt(expected))!=0||st.GetBalance(recipient).Cmp(big.NewInt(100))!=0||used!=21000{
    t.Fatalf("independent oracle mismatch owner=%s nonce=%d recipient=%s gas=%d expected=%d",st.GetBalance(owner),st.GetNonce(owner),st.GetBalance(recipient),used,expected)
   }
   t.Logf("C_FEE_FLOOR_HONEST_ORACLE chain=%d nonce=1 owner=%d recipient=100 gas=21000",tc.chain,expected)
  })
 }
}
