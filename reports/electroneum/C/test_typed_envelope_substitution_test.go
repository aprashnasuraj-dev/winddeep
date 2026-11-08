package types

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/crypto"
)

// C_TYPE_ENVELOPE: an untrusted RPC intermediary may rewrite the typed
// transaction envelope without possessing the owner's signing key.
// This test does not assume a forged signature must be rejected: a valid
// signature for another recovered address is not owner authorization.
func TestWorkerCTypedEnvelopeSubstitution(t *testing.T) {
 for _,seed:=range []byte{43,47,53} {
  keyBytes:=make([]byte,32);keyBytes[31]=seed
  key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  chainID:=big.NewInt(1337)
  recipient:=common.Address{0x91}
  london:=NewLondonSigner(chainID)
  honest,err:=SignNewTx(key,london,&DynamicFeeTx{
   ChainID:chainID,Nonce:0,GasTipCap:big.NewInt(2),
   GasFeeCap:big.NewInt(10),Gas:25000,To:&recipient,
   Value:big.NewInt(1234),
   AccessList:AccessList{{Address:common.Address{0xa1},StorageKeys:[]common.Hash{{0x01}}}},
  })
  if err!=nil{t.Fatal(err)}
  honestBytes,err:=honest.MarshalBinary();if err!=nil{t.Fatal(err)}
  var decoded Transaction
  if err:=decoded.UnmarshalBinary(honestBytes);err!=nil{t.Fatal(err)}
  if decoded.Type()!=DynamicFeeTxType {t.Fatalf("unexpected honest type %d",decoded.Type())}
  got,err:=Sender(london,&decoded)
  if err!=nil||got!=owner {t.Fatalf("C_TYPE_HONEST_FAIL seed=%d got=%s err=%v",seed,got,err)}
  t.Logf("C_TYPE_HONEST seed=%d owner=%s hash=%s",seed,owner,decoded.Hash())
  v,r,s:=honest.RawSignatureValues()
  // A third-party relay replaces the signed EIP-1559 envelope with an
  // EIP-2930 envelope, reusing exactly the owner's (v,r,s).
  replacement:=NewTx(&AccessListTx{
   ChainID:new(big.Int).Set(chainID),Nonce:0,GasPrice:big.NewInt(10),
   Gas:25000,To:&recipient,Value:big.NewInt(1234),
   AccessList:AccessList{{Address:common.Address{0xa1},StorageKeys:[]common.Hash{{0x01}}}},
   V:new(big.Int).Set(v),R:new(big.Int).Set(r),S:new(big.Int).Set(s),
  })
  raw,err:=replacement.MarshalBinary();if err!=nil{t.Fatal(err)}
  var candidate Transaction
  if err:=candidate.UnmarshalBinary(raw);err!=nil{t.Fatal(err)}
  if candidate.Type()!=AccessListTxType {t.Fatalf("type not substituted seed=%d",seed)}
  berlin:=NewEIP2930Signer(chainID)
  substituted,signErr:=Sender(berlin,&candidate)
  if signErr==nil && substituted==owner {
   t.Fatalf("C_TYPE_OWNER_BYPASS seed=%d owner=%s hash=%s",seed,owner,candidate.Hash())
  }
  if candidate.Hash()==decoded.Hash() {t.Fatalf("C_TYPE_HASH_COLLISION seed=%d",seed)}
  t.Logf("C_TYPE_ENVELOPE_ISOLATED seed=%d owner=%s candidate=%s err=%v hash=%s",seed,owner,substituted,signErr,candidate.Hash())
 }
}
