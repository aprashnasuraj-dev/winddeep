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

// A hostile RPC intermediary replays a valid legacy Homestead signature on a
// chain with EIP-155 enabled. This tests the execution boundary only: txpool
// default admission and canonical QBFT inclusion MUST be verified separately.
func TestWorkerCLegacyUnprotectedReplayBoundary(t *testing.T) {
 for _, tc := range []struct{ seed byte; chain int64; funds int64 }{
  {81,1337,10000000},{83,2337,15000000},{89,3337,20000000},
 } {
  keyBytes:=make([]byte,32);keyBytes[31]=tc.seed
  key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  recipient:=common.Address{0xd1}
  miner:=common.Address{0xe1}
  chainID:=big.NewInt(tc.chain)
  cfg:=&params.ChainConfig{ChainID:chainID,LondonBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),EIP155Block:big.NewInt(0),ByzantiumBlock:big.NewInt(0)}
  makeTx:=func(signer types.Signer)*types.Transaction{
   tx,e:=types.SignNewTx(key,signer,&types.LegacyTx{Nonce:0,GasPrice:big.NewInt(10),Gas:21000,To:&recipient,Value:big.NewInt(1000)})
   if e!=nil{t.Fatal(e)}
   raw,e:=tx.MarshalBinary();if e!=nil{t.Fatal(e)}
   var decoded types.Transaction
   if e=decoded.UnmarshalBinary(raw);e!=nil{t.Fatal(e)}
   return &decoded
  }
  protected:=makeTx(types.NewEIP155Signer(chainID))
  unprotected:=makeTx(types.HomesteadSigner{})
  if protected.Protected()==false||unprotected.Protected(){t.Fatal("signature domain control invalid")}
  execute:=func(tx *types.Transaction)(error,uint64,*big.Int,*big.Int){
   st,e:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil);if e!=nil{t.Fatal(e)}
   st.SetBalance(owner,big.NewInt(tc.funds))
   header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(8)}
   var used uint64
   receipt,err:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,tx,&used,vm.Config{})
   if err==nil && (receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful){t.Fatalf("unexpected receipt: %v",receipt)}
   return err,st.GetNonce(owner),new(big.Int).Set(st.GetBalance(owner)),new(big.Int).Set(st.GetBalance(recipient))
  }
  goodErr,goodNonce,goodBal,goodRecipient:=execute(protected)
  if goodErr!=nil||goodNonce!=1||goodBal.Cmp(big.NewInt(tc.funds-211000))!=0||goodRecipient.Cmp(big.NewInt(1000))!=0 {
   t.Fatalf("C_LEGACY_PROTECTED_CONTROL_FAIL chain=%d err=%v nonce=%d balance=%s recipient=%s",tc.chain,goodErr,goodNonce,goodBal,goodRecipient)
  }
  replayErr,replayNonce,replayBal,replayRecipient:=execute(unprotected)
  if replayErr==nil && replayNonce==1 && replayRecipient.Cmp(big.NewInt(1000))==0 {
   t.Logf("C_LEGACY_EXECUTION_ACCEPTED chain=%d nonce=%d balance=%s recipient=%s NOTE=not_txpool_or_canonical",tc.chain,replayNonce,replayBal,replayRecipient)
  } else if replayErr!=nil && replayNonce==0 && replayBal.Cmp(big.NewInt(tc.funds))==0 && replayRecipient.Sign()==0 {
   t.Logf("C_LEGACY_EXECUTION_REJECTED chain=%d err=%v",tc.chain,replayErr)
  } else {
   t.Fatalf("C_LEGACY_INCONSISTENT_STATE chain=%d err=%v nonce=%d balance=%s recipient=%s",tc.chain,replayErr,replayNonce,replayBal,replayRecipient)
  }
  t.Logf("C_LEGACY_DOMAIN_ORACLE chain=%d protected_nonce=%d replay_nonce=%d",tc.chain,goodNonce,replayNonce)
 }
}
