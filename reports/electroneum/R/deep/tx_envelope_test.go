// Worker R deep D3: three signed transaction types across binary envelope,
// RLP transport, sender-domain recovery and mutation-derived parser states.
package types

import (
 "bytes"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/rlp"
)

func rDeepTxSamples(t *testing.T) []*Transaction {
 t.Helper()
 keybytes:=make([]byte,32);keybytes[31]=1
 key,err:=crypto.ToECDSA(keybytes);if err!=nil{t.Fatal(err)}
 addr:=common.HexToAddress("0x0000000000000000000000000000000000000055")
 signer:=LatestSignerForChainID(big.NewInt(1399))
 inner:=[]TxData{
  &LegacyTx{Nonce:1,GasPrice:big.NewInt(17),Gas:21000,To:&addr,Value:big.NewInt(3),Data:[]byte{1,2,3}},
  &AccessListTx{ChainID:big.NewInt(1399),Nonce:2,GasPrice:big.NewInt(19),Gas:25000,To:&addr,Value:big.NewInt(5),Data:[]byte{4,5},AccessList:AccessList{{Address:addr,StorageKeys:[]common.Hash{common.HexToHash("0x01")}}}},
  &DynamicFeeTx{ChainID:big.NewInt(1399),Nonce:3,GasTipCap:big.NewInt(5),GasFeeCap:big.NewInt(21),Gas:26000,To:&addr,Value:big.NewInt(7),Data:[]byte{6,7},AccessList:AccessList{{Address:addr}}},
 }
 out:=make([]*Transaction,0,len(inner))
 for _,txdata:=range inner{
  tx,err:=SignTx(NewTx(txdata),signer,key)
  if err!=nil{t.Fatalf("R_DEEP_TX_VALID_SIGN: %T err=%v",txdata,err)}
  from,err:=Sender(signer,tx)
  if err!=nil||from!=crypto.PubkeyToAddress(key.PublicKey){t.Fatalf("R_DEEP_TX_SENDER_CONTROL: %T err=%v",txdata,err)}
  if _,err:=Sender(NewLondonSigner(big.NewInt(1400)),tx);err!=ErrInvalidChainId {
   t.Fatalf("R_DEEP_TX_CROSS_DOMAIN_REPLAY: type=%d got=%v",tx.Type(),err)
  }
  out=append(out,tx)
 }
 return out
}
func rDeepTxEnvelope(t *testing.T,control []byte){
 t.Helper()
 if len(control)>512{return}
 samples:=rDeepTxSamples(t)
 for _,original:=range samples{
  raw,err:=original.MarshalBinary();if err!=nil{t.Fatal(err)}
  var a Transaction
  if err:=a.UnmarshalBinary(raw);err!=nil||a.Hash()!=original.Hash(){t.Fatalf("R_DEEP_TX_BINARY_ROUNDTRIP: type=%d err=%v",original.Type(),err)}
  transport,err:=rlp.EncodeToBytes(original)
  if err!=nil{t.Fatal(err)}
  var b Transaction
  if err:=rlp.DecodeBytes(transport,&b);err!=nil||b.Hash()!=original.Hash(){
   t.Fatalf("R_DEEP_TX_RLP_TRANSPORT_MISMATCH: type=%d err=%v",original.Type(),err)
  }
  if len(control)==0{continue}
  altered:=append([]byte(nil),raw...)
  for i:=0;i<len(control)&&i<12;i++{
   idx:=int(control[i])%len(altered)
   switch control[i]%5{
   case 0:altered[idx]^=0x80
   case 1:altered[idx]=0
   case 2:altered[idx]=0xff
   case 3:altered[idx]=byte(i)
   case 4:altered[idx]^=0x01
   }
  }
  if len(control)>3&&control[0]%7==6 {
   altered=altered[:int(control[1])%len(altered)]
  }
  var mutated Transaction
  if err:=mutated.UnmarshalBinary(altered);err!=nil{continue}
  recoded,err:=mutated.MarshalBinary()
  if err!=nil{t.Fatalf("R_DEEP_TX_REENCODE_ERROR: %v",err)}
  if !bytes.Equal(recoded,altered){
   t.Fatalf("R_DEEP_TX_NONCANONICAL_BINARY_ACCEPTED: type=%d input=%x normalized=%x",mutated.Type(),altered,recoded)
  }
  var verify Transaction
  if err:=verify.UnmarshalBinary(recoded);err!=nil||verify.Hash()!=mutated.Hash(){
   t.Fatalf("R_DEEP_TX_ACCEPTED_BINARY_UNSTABLE: err=%v",err)
  }
 }
}
func TestRDeepTxEnvelopeBaseline(t *testing.T){
 for _,script:=range [][]byte{nil,{0,1,2,3,4},{1,2,3,4,5},{255,254,253,252},{6,0,1,1,2,3}}{
  rDeepTxEnvelope(t,script)
 }
 t.Log("R_DEEP_TYPED_LEGACY_RLP_BINARY_SIGNER_CONTROLS_PASS")
}
func FuzzRDeepTxEnvelope(f *testing.F){
 f.Add([]byte{0,1,2,3,4})
 f.Add([]byte{255,254,253,252})
 f.Add([]byte{6,0,1,1,2,3})
 f.Fuzz(func(t *testing.T,script []byte){
  if len(script)>256{return}
  rDeepTxEnvelope(t,script)
 })
}
