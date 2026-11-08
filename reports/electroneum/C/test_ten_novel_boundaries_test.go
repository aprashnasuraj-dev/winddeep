package types

import (
    "fmt"
    "math/big"
    "testing"
    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/rlp"
)

// Ten independent outsider-input hypotheses, three distinct signed synthetic
// transaction states. Regression PASS means guard survived, NOT a vulnerability.
// No third-party wallets, real assets, external nodes or canonical QBFT blocks.
func TestWorkerCTenNovelBoundaries(t *testing.T) {
    for _,tc:=range []struct{ seed byte; chain int64; nonce uint64; value int64 }{
      {0x29,1337,0,9},{0x49,1338,1,37},{0x63,1339,2,83},
    } {
      t.Run(fmt.Sprintf("state_%d",tc.seed),func(t *testing.T){
        secret:=make([]byte,32);secret[31]=tc.seed
        key,err:=crypto.ToECDSA(secret);if err!=nil{t.Fatal(err)}
        owner:=crypto.PubkeyToAddress(key.PublicKey)
        chain:=big.NewInt(tc.chain);signer:=NewLondonSigner(chain)
        recipient:=common.Address{0x99,tc.seed}
        original:=&DynamicFeeTx{
          ChainID:new(big.Int).Set(chain),Nonce:tc.nonce,
          GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(100),Gas:120000,
          To:&recipient,Value:big.NewInt(tc.value),
          Data:[]byte{0xa9,0x05,0x9c,0xbb,tc.seed},
        }
        signed,err:=SignNewTx(key,signer,original);if err!=nil{t.Fatal(err)}
        raw,err:=signed.MarshalBinary();if err!=nil{t.Fatal(err)}
        honest:=new(Transaction)
        if err:=honest.UnmarshalBinary(raw);err!=nil{t.Fatal(err)}
        got,err:=Sender(signer,honest)
        if err!=nil||got!=owner{t.Fatalf("C_NOVEL_HONEST_FAIL seed=%d got=%s err=%v",tc.seed,got,err)}
        t.Logf("C_NOVEL_HONEST_OK seed=%d owner=%s hash=%s",tc.seed,owner,honest.Hash())
        v,r,s:=signed.RawSignatureValues()
        changed:=func(mutate func(*DynamicFeeTx))*Transaction{
          d:=&DynamicFeeTx{
            ChainID:new(big.Int).Set(chain),Nonce:tc.nonce,
            GasTipCap:big.NewInt(2),GasFeeCap:big.NewInt(100),Gas:120000,
            To:&recipient,Value:big.NewInt(tc.value),
            Data:[]byte{0xa9,0x05,0x9c,0xbb,tc.seed},
            V:new(big.Int).Set(v),R:new(big.Int).Set(r),S:new(big.Int).Set(s),
          };mutate(d);return NewTx(d)
        }
        noOwner:=func(id string, candidate *Transaction){
          t.Helper()
          recovered,e:=Sender(signer,candidate)
          if e==nil&&recovered==owner{t.Fatalf("C_NOVEL_%s_OWNER_BYPASS seed=%d",id,tc.seed)}
          if candidate.Hash()==signed.Hash(){t.Fatalf("C_NOVEL_%s_HASH_UNCHANGED seed=%d",id,tc.seed)}
          t.Logf("C_NOVEL_%s_GUARD_OK seed=%d recovered=%s err=%v",id,tc.seed,recovered,e)
        }
        rejectRaw:=func(id string, blob []byte){
          t.Helper()
          candidate:=new(Transaction)
          e:=candidate.UnmarshalBinary(blob)
          if e==nil{t.Fatalf("C_NOVEL_%s_NONCANONICAL_ACCEPTED seed=%d hash=%s",id,tc.seed,candidate.Hash())}
          t.Logf("C_NOVEL_%s_GUARD_OK seed=%d decode_error=%v",id,tc.seed,e)
        }
        noOwner("H01_CALLDATA",changed(func(d *DynamicFeeTx){d.Data[0]^=1}))
        noOwner("H02_GASLIMIT",changed(func(d *DynamicFeeTx){d.Gas+=100000}))
        noOwner("H03_TIP",changed(func(d *DynamicFeeTx){d.GasTipCap.SetInt64(50)}))
        noOwner("H04_CREATION",changed(func(d *DynamicFeeTx){d.To=nil}))
        rejectRaw("H05_TYPED_SUFFIX",append(append([]byte{},raw...),0x00))
        unknown:=append([]byte{},raw...);unknown[0]=0x7e
        rejectRaw("H06_UNKNOWN_TYPE",unknown)
        noOwner("H07_PARITY",changed(func(d *DynamicFeeTx){d.V.SetInt64(2)}))
        noOwner("H08_ZERO_R",changed(func(d *DynamicFeeTx){d.R.SetInt64(0)}))
        var fields []rlp.RawValue
        if err:=rlp.DecodeBytes(raw[1:],&fields);err!=nil{t.Fatal(err)}
        if len(fields)!=12{t.Fatalf("unexpected 1559 RLP fields %d",len(fields))}
        fields[1]=rlp.RawValue{0x00}
        inner,err:=rlp.EncodeToBytes(fields);if err!=nil{t.Fatal(err)}
        rejectRaw("H09_RLP_ZERO",append([]byte{DynamicFeeTxType},inner...))
        legacy,err:=SignNewTx(key,NewEIP155Signer(chain),&LegacyTx{
          Nonce:tc.nonce,Gas:21000,GasPrice:big.NewInt(11),To:&recipient,Value:big.NewInt(tc.value),
        });if err!=nil{t.Fatal(err)}
        legacyRaw,err:=legacy.MarshalBinary();if err!=nil{t.Fatal(err)}
        honestLegacy:=new(Transaction)
        if err:=honestLegacy.UnmarshalBinary(legacyRaw);err!=nil{t.Fatal(err)}
        legacyOwner,err:=Sender(NewEIP155Signer(chain),honestLegacy)
        if err!=nil||legacyOwner!=owner{t.Fatalf("C_NOVEL_LEGACY_HONEST_FAIL seed=%d err=%v",tc.seed,err)}
        rejectRaw("H10_LEGACY_SUFFIX",append(append([]byte{},legacyRaw...),0x00))
        t.Logf("C_NOVEL_10x3_ORACLE seed=%d distinct_state=1 tested=10",tc.seed)
      })
    }
}
