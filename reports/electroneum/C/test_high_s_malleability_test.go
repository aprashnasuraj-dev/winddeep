package types

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/crypto"
)

func TestWorkerCHighSMalleabilityAdmission(t *testing.T) {
 for _, seed := range []byte{31,37,41} {
  t.Run(string(rune('A'+seed%26)),func(t *testing.T) {
   rawKey:=make([]byte,32);rawKey[31]=seed
   key,err:=crypto.ToECDSA(rawKey);if err!=nil {t.Fatal(err)}
   owner:=crypto.PubkeyToAddress(key.PublicKey)
   chainID:=big.NewInt(1337)
   to:=common.Address{0x51}
   signer:=NewLondonSigner(chainID)
   signed,err:=SignNewTx(key,signer,&DynamicFeeTx{ChainID:chainID,Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),Gas:21000,To:&to,Value:big.NewInt(100)})
   if err!=nil {t.Fatal(err)}
   original,err:=Sender(signer,signed);if err!=nil||original!=owner {t.Fatalf("C_HIGHS_BASELINE_FAIL seed=%d from=%s err=%v",seed,original,err)}
   v,r,s:=signed.RawSignatureValues()
   order:=crypto.S256().Params().N
   highS:=new(big.Int).Sub(order,s)
   if highS.Cmp(s)<=0 {t.Fatalf("unexpected high-S boundary seed=%d",seed)}
   flippedV:=new(big.Int).Xor(v,big.NewInt(1))
   candidate:=NewTx(&DynamicFeeTx{ChainID:new(big.Int).Set(chainID),Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),Gas:21000,To:&to,Value:big.NewInt(100),V:flippedV,R:new(big.Int).Set(r),S:highS})
   encoded,err:=candidate.MarshalBinary();if err!=nil {t.Fatal(err)}
   var decoded Transaction
   if err=decoded.UnmarshalBinary(encoded);err!=nil {t.Fatal(err)}
   attackerRecovered,attackerErr:=Sender(signer,&decoded)
   if attackerErr==nil {t.Fatalf("C_HIGHS_AUTH_BYPASS seed=%d recovered=%s original=%s",seed,attackerRecovered,owner)}
   t.Logf("C_HIGHS_REJECTED seed=%d recovered=%s err=%v",seed,attackerRecovered,attackerErr)
   if recovered,err:=Sender(signer,signed);err!=nil||recovered!=owner {t.Fatalf("C_HIGHS_HONEST_CHANGED seed=%d",seed)}
   t.Logf("C_HIGHS_HONEST_CONTROL seed=%d owner=%s",seed,owner)
  })
 }
}
