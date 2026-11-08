package core

import (
 "bytes"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/rlp"
)

// An untrusted RPC intermediary re-encodes the nonce-zero RLP integer as 0x00.
// The canonical representation is 0x80; an alternate representation must not
// reach transaction admission as an alias for a signed transaction.
func TestWorkerCNoncanonicalNonceRLP(t *testing.T) {
 for _, tc := range []struct{seed byte; chain int64}{{73,1337},{79,2337},{83,3337}} {
  kb:=make([]byte,32); kb[31]=tc.seed
  key,err:=crypto.ToECDSA(kb); if err!=nil {t.Fatal(err)}
  to:=common.Address{0x91}
  original,err:=types.SignTx(types.NewTransaction(0,to,big.NewInt(17),21000,big.NewInt(30),nil),types.NewEIP155Signer(big.NewInt(tc.chain)),key)
  if err!=nil {t.Fatal(err)}
  raw,err:=original.MarshalBinary(); if err!=nil {t.Fatal(err)}
  var honest types.Transaction
  if err=honest.UnmarshalBinary(raw);err!=nil||honest.Hash()!=original.Hash(){t.Fatalf("honest decode: %v",err)}
  var fields []rlp.RawValue
  if err=rlp.DecodeBytes(raw,&fields);err!=nil {t.Fatal(err)}
  if len(fields)!=9 || !bytes.Equal(fields[0],[]byte{0x80}) {t.Fatalf("unexpected legacy nonce encoding %x",fields)}
  fields[0]=rlp.RawValue{0x00}
  hostile,err:=rlp.EncodeToBytes(fields);if err!=nil {t.Fatal(err)}
  var decoded types.Transaction
  err=decoded.UnmarshalBinary(hostile)
  if err==nil {t.Fatalf("C_RLP_NONCANONICAL_ACCEPT seed=%d chain=%d owner=%s original=%x hostile=%x decoded=%s",tc.seed,tc.chain,crypto.PubkeyToAddress(key.PublicKey),raw,hostile,decoded.Hash())}
  if bytes.Equal(raw,hostile){t.Fatal("mutation did not change bytes")}
  var control types.Transaction
  if e:=control.UnmarshalBinary(raw);e!=nil||control.Hash()!=original.Hash(){t.Fatalf("canonical control rejected: %v",e)}
  t.Logf("C_RLP_NONCANONICAL_REJECT seed=%d chain=%d honest=%s hostile_len=%d err=%v",tc.seed,tc.chain,original.Hash(),len(hostile),err)
 }
}
