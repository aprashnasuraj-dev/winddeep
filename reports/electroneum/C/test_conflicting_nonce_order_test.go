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

// Stateful hostile RPC intermediary: submits two different, correctly signed
// transfers with the SAME nonce, in both orders. This is not a QBFT import.
func TestWorkerCConflictingNonceOrdering(t *testing.T) {
 for _,tc:=range []struct{seed byte;funds int64;firstB bool}{
  {61,10000000,false},{67,15000000,true},{71,20000000,false},
 }{
  keyBytes:=make([]byte,32);keyBytes[31]=tc.seed
  key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  a,b,miner:=common.Address{0xa1},common.Address{0xb1},common.Address{0xc1}
  cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
  st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if err!=nil{t.Fatal(err)}
  st.SetBalance(owner,big.NewInt(tc.funds))
  header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
  makeTx:=func(to common.Address,value int64)*types.Transaction{
   tx,e:=types.SignNewTx(key,types.NewLondonSigner(big.NewInt(1337)),&types.DynamicFeeTx{ChainID:big.NewInt(1337),Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),Gas:21000,To:&to,Value:big.NewInt(value)})
   if e!=nil{t.Fatal(e)}
   raw,e:=tx.MarshalBinary();if e!=nil{t.Fatal(e)}
   var decoded types.Transaction
   if e=decoded.UnmarshalBinary(raw);e!=nil{t.Fatal(e)}
   return &decoded
  }
  txA,txB:=makeTx(a,1100),makeTx(b,2200)
  first,second:=txA,txB
  recipient,value:=a,int64(1100)
  if tc.firstB{first,second=txB,txA;recipient,value=b,2200}
  var used uint64
  apply:=func(tx *types.Transaction)(*types.Receipt,error){return ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,tx,&used,vm.Config{})}
  r,e:=apply(first);if e!=nil||r==nil||r.Status!=types.ReceiptStatusSuccessful{t.Fatalf("first rejected seed=%d: %v %v",tc.seed,r,e)}
  ownerBefore,nonceBefore,gasBefore:=new(big.Int).Set(st.GetBalance(owner)),st.GetNonce(owner),used
  secondReceipt,secondErr:=apply(second)
  if secondErr==nil||secondReceipt!=nil{t.Fatalf("C_NONCE_DOUBLE_SPEND seed=%d second=%v err=%v",tc.seed,secondReceipt,secondErr)}
  if st.GetNonce(owner)!=nonceBefore||st.GetBalance(owner).Cmp(ownerBefore)!=0||used!=gasBefore{t.Fatalf("C_NONCE_REJECT_MUTATED_STATE seed=%d",tc.seed)}
  expectedOwner:=tc.funds-210000-value
  if st.GetNonce(owner)!=1||st.GetBalance(owner).Cmp(big.NewInt(expectedOwner))!=0||st.GetBalance(recipient).Cmp(big.NewInt(value))!=0||st.GetBalance(miner).Cmp(big.NewInt(42000))!=0{t.Fatalf("C_NONCE_ORACLE_FAIL seed=%d",tc.seed)}
  other:=a;if recipient==a{other=b}
  if st.GetBalance(other).Sign()!=0{t.Fatalf("C_NONCE_OTHER_RECIPIENT_CREDITED seed=%d",tc.seed)}
  t.Logf("C_NONCE_ORDER_ORACLE seed=%d firstB=%v owner=%s nonce=%d recipient=%s value=%d rejected=%v",tc.seed,tc.firstB,st.GetBalance(owner),st.GetNonce(owner),recipient,value,secondErr)
 }
}
