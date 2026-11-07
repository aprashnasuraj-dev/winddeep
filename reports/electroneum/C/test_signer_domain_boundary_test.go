package core

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

// C_DOMAIN_BOUNDARY: independent signer recovery oracle across fork/chain domains.
// This does not claim txpool admission, canonical import or externally reachable exploit.
func TestWorkerCSignerDomainBoundary(t *testing.T) {
 for _, seed := range []byte{13,29,43} {
  keyBytes:=make([]byte,32); keyBytes[31]=seed
  key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  for _,tc:=range []struct{name string;domain int64}{
   {"valid",1337},{"wrong",1338},{"zero",0},{"boundary",1336},
  } {
   t.Run(tc.name+string(rune('A'+seed%26)),func(t *testing.T){
    to:=owner
    tx,err:=types.SignNewTx(key,types.NewLondonSigner(big.NewInt(tc.domain)),
      &types.DynamicFeeTx{ChainID:big.NewInt(tc.domain),Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(10),Gas:21000,To:&to,Value:big.NewInt(1)})
    if err!=nil{t.Fatal(err)}
    raw,err:=tx.MarshalBinary();if err!=nil{t.Fatal(err)}
    var decoded types.Transaction
    if err:=decoded.UnmarshalBinary(raw);err!=nil{t.Fatal(err)}
    targetSigner:=types.NewLondonSigner(big.NewInt(1337))
    got,err:=types.Sender(targetSigner,&decoded)
    if tc.domain==1337 {
     if err!=nil||got!=owner{t.Fatalf("C_DOMAIN_OWNER_BREACH domain=%d got=%s err=%v",tc.domain,got,err)}
     t.Logf("C_DOMAIN_VALID_OWNER seed=%d owner=%s",seed,owner)
    } else {
     if err==nil&&got==owner{t.Fatalf("C_DOMAIN_CROSS_CHAIN_BREACH domain=%d recovered_owner=%s",tc.domain,got)}
     t.Logf("C_DOMAIN_REJECTED seed=%d domain=%d recovered=%s err=%v",seed,tc.domain,got,err)
    }
   })
  }
 }
}
