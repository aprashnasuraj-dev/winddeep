package types

import (
 "bytes"
 "math/big"
 "runtime"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/rlp"
 "github.com/electroneum/electroneum-sc/trie"
)

func TestRRealisticRawTransactionAndReceiptDecodeBudgets(t *testing.T){
 keybytes:=make([]byte,32);keybytes[31]=1
 key,err:=crypto.ToECDSA(keybytes);if err!=nil{t.Fatal(err)}
 to:=common.HexToAddress("0x0000000000000000000000000000000000000088")
 signer:=NewLondonSigner(big.NewInt(1399))
 data:=bytes.Repeat([]byte{0x5a},2*1024*1024)
 tx,err:=SignNewTx(key,signer,&DynamicFeeTx{ChainID:big.NewInt(1399),Nonce:1,GasTipCap:big.NewInt(1),GasFeeCap:big.NewInt(10),Gas:3_000_000,To:&to,Value:big.NewInt(0),Data:data})
 if err!=nil{t.Fatal(err)}
 raw,err:=tx.MarshalBinary();if err!=nil{t.Fatal(err)}
 if len(raw)<2*1024*1024{t.Fatalf("R_TX_LARGE_FIXTURE_TOO_SMALL bytes=%d",len(raw))}
 var before,after runtime.MemStats
 runtime.GC();runtime.ReadMemStats(&before)
 start:=time.Now();var decoded Transaction;err=decoded.UnmarshalBinary(raw);elapsed:=time.Since(start)
 runtime.ReadMemStats(&after)
 if err!=nil||decoded.Hash()!=tx.Hash(){t.Fatalf("R_TX_LARGE_DECODE_FAIL err=%v",err)}
 from,err:=Sender(signer,&decoded);if err!=nil||from!=crypto.PubkeyToAddress(key.PublicKey){t.Fatalf("R_TX_LARGE_SIGNATURE_RECOVERY_FAIL err=%v",err)}
 if elapsed>6*time.Second{t.Fatalf("R_TX_LARGE_WALLTIME_BREACH elapsed=%s",elapsed)}
 delta:=uint64(0);if after.TotalAlloc>before.TotalAlloc{delta=after.TotalAlloc-before.TotalAlloc}
 if delta>uint64(len(raw))*10{t.Fatalf("R_TX_LARGE_ALLOCATION_AMPLIFICATION raw=%d alloc=%d",len(raw),delta)}
 t.Logf("R_TX_REALISTIC_RAW_DECODE_PASS raw=%d elapsed=%s alloc=%d",len(raw),elapsed,delta)

 logs:=make([]*Log,256)
 for i:=range logs{logs[i]=&Log{Address:to,Topics:[]common.Hash{common.BigToHash(big.NewInt(int64(i+1)))},Data:bytes.Repeat([]byte{byte(i)},8192)}}
 receipts:=Receipts{&Receipt{Type:DynamicFeeTxType,Status:ReceiptStatusSuccessful,CumulativeGasUsed:3_000_000,Logs:logs}}
 receiptRaw,err:=rlp.EncodeToBytes(receipts);if err!=nil{t.Fatal(err)}
 runtime.GC();runtime.ReadMemStats(&before)
 start=time.Now();var decodedReceipts Receipts;err=rlp.DecodeBytes(receiptRaw,&decodedReceipts);elapsed=time.Since(start)
 runtime.ReadMemStats(&after)
 if err!=nil||len(decodedReceipts)!=1||len(decodedReceipts[0].Logs)!=len(logs){t.Fatalf("R_RECEIPT_LARGE_DECODE_FAIL err=%v logs=%d",err,len(decodedReceipts))}
 if elapsed>6*time.Second{t.Fatalf("R_RECEIPT_LARGE_WALLTIME_BREACH elapsed=%s",elapsed)}
 reencoded,err:=rlp.EncodeToBytes(decodedReceipts);if err!=nil{t.Fatal(err)}\n if !bytes.Equal(reencoded,receiptRaw){t.Fatal("R_RECEIPT_LARGE_CANONICAL_REENCODE_CHANGED")}
 delta=0;if after.TotalAlloc>before.TotalAlloc{delta=after.TotalAlloc-before.TotalAlloc}
 if delta>uint64(len(receiptRaw))*12{t.Fatalf("R_RECEIPT_LARGE_ALLOCATION_AMPLIFICATION raw=%d alloc=%d",len(receiptRaw),delta)}
 t.Logf("R_RECEIPT_REALISTIC_LOG_DECODE_PASS raw=%d logs=%d elapsed=%s alloc=%d",len(receiptRaw),len(logs),elapsed,delta)
}
