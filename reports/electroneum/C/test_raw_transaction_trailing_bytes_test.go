package core

import (
 "bytes"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
)

// Outside-in raw-transaction framing hypothesis: an RPC intermediary appends
// a second RLP item to a valid signed transaction. The decoder must reject
// ambiguous trailing bytes instead of silently accepting a prefix.
func TestWorkerCRawTransactionTrailingBytes(t *testing.T) {
 for _, tc := range []struct{seed byte; chain int64; typed bool}{
  {31,1337,false},{47,2337,true},{59,3337,true},
 } {
  keyBytes:=make([]byte,32);keyBytes[31]=tc.seed
  key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
  owner:=crypto.PubkeyToAddress(key.PublicKey)
  chain:=big.NewInt(tc.chain)
  to:=common.Address{0x31}
  var tx *types.Transaction
  if tc.typed {
   tx,err=types.SignNewTx(key,types.NewLondonSigner(chain),&types.DynamicFeeTx{ChainID:chain,Nonce:0,GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(30),Gas:21000,To:&to,Value:big.NewInt(7)})
  }else{
   unsigned:=types.NewTransaction(0,to,big.NewInt(7),21000,big.NewInt(30),nil)
   tx,err=types.SignTx(unsigned,types.NewEIP155Signer(chain),key)
  }
  if err!=nil{t.Fatal(err)}
  raw,err:=tx.MarshalBinary();if err!=nil{t.Fatal(err)}
  var honest types.Transaction
  if err=honest.UnmarshalBinary(raw);err!=nil{t.Fatalf("honest decode: %v",err)}
  if honest.Hash()!=tx.Hash(){t.Fatal("honest hash changed")}
  signer:=types.LatestSignerForChainID(chain)
  sender,err:=types.Sender(signer,&honest);if err!=nil||sender!=owner{t.Fatalf("honest sender: %v",err)}
  // RLP empty string is a valid second item but not part of the signed tx.
  hostile:=append(bytes.Clone(raw),0x80)
  var decoded types.Transaction
  err=decoded.UnmarshalBinary(hostile)
  if err==nil{
   t.Fatalf("C_RAW_TRAILING_ACCEPT seed=%d chain=%d typed=%t original=%x hostile=%x decoded_hash=%s",tc.seed,tc.chain,tc.typed,raw,hostile,decoded.Hash())
  }
  // Boundary: a valid signed transaction must still decode unmodified.
  var boundary types.Transaction
  if err=boundary.UnmarshalBinary(raw);err!=nil||boundary.Hash()!=tx.Hash(){t.Fatalf("boundary failed: %v",err)}
  t.Logf("C_RAW_TRAILING_REJECT seed=%d chain=%d typed=%t owner=%s raw_len=%d hostile_len=%d",tc.seed,tc.chain,tc.typed,owner,len(raw),len(hostile))
 }
}
