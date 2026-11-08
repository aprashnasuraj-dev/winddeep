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

// TestWorkerCIntrinsicGasBoundary tests a signed outsider-submitted typed
// transaction with a syntactically valid payload but insufficient intrinsic gas.
// No public network, unlocked wallet, or mocked transition backend is used.
// This tests state transition only, NOT default RPC or canonical QBFT inclusion.
func TestWorkerCIntrinsicGasBoundary(t *testing.T) {
 cases:=[]struct{seed byte;chain int64;fund int64;payload []byte}{
  {53,1337,10000000,[]byte{0,1,0}},
  {59,2337,12000000,[]byte{1,2,3,4}},
  {61,3337,14000000,[]byte{0,0,5,6,7}},
 }
 for i,tc:=range cases {
  t.Run(string(rune('A'+i)),func(t *testing.T){
   keyBytes:=make([]byte,32);keyBytes[31]=tc.seed
   key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
   owner:=crypto.PubkeyToAddress(key.PublicKey)
   recipient:=common.Address{0x77};miner:=common.Address{0x78}
   cfg:=&params.ChainConfig{ChainID:big.NewInt(tc.chain),LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
   st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if err!=nil{t.Fatal(err)}
   st.SetBalance(owner,big.NewInt(tc.fund))
   header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
   signer:=types.MakeSigner(cfg,big.NewInt(1))
   intrinsic:=uint64(21000)
   for _,b:=range tc.payload {if b==0{intrinsic+=4}else{intrinsic+=16}}
   sign:=func(gas uint64)*types.Transaction{
    t.Helper()
    tx,e:=types.SignNewTx(key,types.NewLondonSigner(big.NewInt(tc.chain)),&types.DynamicFeeTx{
     ChainID:big.NewInt(tc.chain),Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),
     Gas:gas,To:&recipient,Value:big.NewInt(100),Data:tc.payload,
    });if e!=nil{t.Fatal(e)}
    raw,e:=tx.MarshalBinary();if e!=nil{t.Fatal(e)}
    var decoded types.Transaction
    if e=decoded.UnmarshalBinary(raw);e!=nil{t.Fatal(e)}
    from,e:=types.Sender(signer,&decoded);if e!=nil||from!=owner{t.Fatalf("signer mismatch %s %v",from,e)}
    return &decoded
   }
   var used uint64
   bad:=sign(intrinsic-1)
   receipt,err:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(1000000),st,header,bad,&used,vm.Config{})
   if err==nil||receipt!=nil{t.Fatalf("under-intrinsic transaction accepted receipt=%v err=%v",receipt,err)}
   if st.GetNonce(owner)!=0||st.GetBalance(owner).Cmp(big.NewInt(tc.fund))!=0||st.GetBalance(recipient).Sign()!=0||st.GetBalance(miner).Sign()!=0||used!=0{
    t.Fatalf("rejected tx mutated state: owner=%s nonce=%d recipient=%s miner=%s gas=%d",st.GetBalance(owner),st.GetNonce(owner),st.GetBalance(recipient),st.GetBalance(miner),used)
   }
   t.Logf("C_INTRINSIC_REJECT chain=%d gas=%d intrinsic=%d err=%v",tc.chain,intrinsic-1,intrinsic,err)
   good:=sign(intrinsic)
   receipt,err=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(1000000),st,header,good,&used,vm.Config{})
   if err!=nil||receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful{t.Fatalf("valid control failed receipt=%v err=%v",receipt,err)}
   expected:=tc.fund-100-int64(intrinsic)*10
   if st.GetNonce(owner)!=1||st.GetBalance(owner).Cmp(big.NewInt(expected))!=0||st.GetBalance(recipient).Cmp(big.NewInt(100))!=0||used!=intrinsic{
    t.Fatalf("honest oracle failed owner=%s nonce=%d recipient=%s gas=%d expected=%d",st.GetBalance(owner),st.GetNonce(owner),st.GetBalance(recipient),used,expected)
   }
   t.Logf("C_INTRINSIC_HONEST_ORACLE chain=%d owner=%d nonce=1 recipient=100 gas=%d",tc.chain,expected,used)
  })
 }
}
