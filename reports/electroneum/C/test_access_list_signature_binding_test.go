package core

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

// Hostile wallet middleware modifies the access list after a user signs a
// dynamic-fee transfer, preserving the original signature bytes. The
// recipient/value/nonce remain unchanged. This is signer-boundary evidence,
// not txpool admission or canonical QBFT inclusion.
func TestWorkerCAccessListSignatureBinding(t *testing.T) {
 for _, tc := range []struct{seed byte; chain int64; slot byte}{
  {101,1337,1},{103,2337,2},{107,3337,3},
 } {
  keyBytes:=make([]byte,32);keyBytes[31]=tc.seed
  key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  to:=common.Address{0x91}
  chain:=big.NewInt(tc.chain)
  signer:=types.NewLondonSigner(chain)
  original,err:=types.SignNewTx(key,signer,&types.DynamicFeeTx{
   ChainID:chain,Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),
   Gas:50000,To:&to,Value:big.NewInt(1234),
  });if err!=nil{t.Fatal(err)}
  raw,err:=original.MarshalBinary();if err!=nil{t.Fatal(err)}
  var decoded types.Transaction
  if err=decoded.UnmarshalBinary(raw);err!=nil{t.Fatal(err)}
  honest,err:=types.Sender(signer,&decoded)
  if err!=nil||honest!=owner{t.Fatalf("C_ACCESS_HONEST_FAIL chain=%d err=%v signer=%s",tc.chain,err,honest)}
  v,r,s:=decoded.RawSignatureValues()
  slot:=common.Hash{};slot[31]=tc.slot
  mutated:=types.NewTx(&types.DynamicFeeTx{
   ChainID:chain,Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),
   Gas:50000,To:&to,Value:big.NewInt(1234),
   AccessList:types.AccessList{{Address:common.Address{0x72},StorageKeys:[]common.Hash{slot}}},
   V:new(big.Int).Set(v),R:new(big.Int).Set(r),S:new(big.Int).Set(s),
  })
  encoded,err:=mutated.MarshalBinary();if err!=nil{t.Fatal(err)}
  var candidate types.Transaction
  if err=candidate.UnmarshalBinary(encoded);err!=nil{t.Fatal(err)}
  recovered,recoverErr:=types.Sender(signer,&candidate)
  if recoverErr==nil && recovered==owner{
   t.Fatalf("C_ACCESS_OWNER_BYPASS chain=%d owner=%s candidate=%s",tc.chain,owner,candidate.Hash())
  }
  if candidate.Hash()==decoded.Hash(){t.Fatalf("C_ACCESS_HASH_UNCHANGED chain=%d",tc.chain)}
  t.Logf("C_ACCESS_BINDING_ORACLE chain=%d honest=%s candidate=%s recovery_error=%v honest_hash=%s candidate_hash=%s",tc.chain,owner,recovered,recoverErr,decoded.Hash(),candidate.Hash())
 }
}
