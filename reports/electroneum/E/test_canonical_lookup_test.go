// Worker E: isolated defensive canonicality regression on certified Electroneum source.
// Installed only in a SCRATCH COPY by the Worker E CI; not committed into vendor source.
package rawdb

import (
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/params"
)

func workerETx(nonce uint64) *types.Transaction {
    to := common.HexToAddress("0x00000000000000000000000000000000000000e1")
    return types.NewTx(&types.LegacyTx{
        Nonce: nonce, To: &to, Gas: 21000,
        GasPrice: big.NewInt(2), Value: big.NewInt(11),
    })
}

func TestWorkerECanonicalReceiptReorg(t *testing.T) {
    db := NewMemoryDatabase()
    defer db.Close()
    const height uint64 = 52
    original := common.HexToHash("0x1111")
    replacement := common.HexToHash("0x2222")
    tx := workerETx(1)
    other := workerETx(2)
    config := &params.ChainConfig{ChainID: big.NewInt(52014)}

    WriteBody(db, original, height, &types.Body{Transactions: types.Transactions{tx}})
    WriteReceipts(db, original, height, types.Receipts{&types.Receipt{
        Type: types.LegacyTxType, Status: types.ReceiptStatusSuccessful,
        CumulativeGasUsed: 21000,
    }})
    WriteTxLookupEntries(db, height, []common.Hash{tx.Hash()})
    WriteCanonicalHash(db, original, height)

    assertPresent := func(expected common.Hash) {
        t.Helper()
        got, bh, bn, idx := ReadTransaction(db, tx.Hash())
        if got == nil || got.Hash() != tx.Hash() || bh != expected || bn != height || idx != 0 {
            t.Fatalf("canonical transaction mismatch: got=%v hash=%s height=%d idx=%d", got, bh, bn, idx)
        }
        receipt, rh, rn, ri := ReadReceipt(db, tx.Hash(), config)
        if receipt == nil || receipt.Status != types.ReceiptStatusSuccessful || rh != expected || rn != height || ri != 0 {
            t.Fatalf("canonical receipt mismatch: receipt=%v hash=%s height=%d idx=%d", receipt, rh, rn, ri)
        }
    }
    assertMissing := func() {
        t.Helper()
        if got, _, _, _ := ReadTransaction(db, tx.Hash()); got != nil {
            t.Fatalf("stale/orphaned transaction returned: %s", got.Hash())
        }
        if got, _, _, _ := ReadReceipt(db, tx.Hash(), config); got != nil {
            t.Fatalf("stale/orphaned receipt returned: %s", got.TxHash)
        }
    }

    assertPresent(original) // honest canonical baseline
    WriteBody(db, replacement, height, &types.Body{Transactions: types.Transactions{other}})
    WriteReceipts(db, replacement, height, types.Receipts{&types.Receipt{
        Type: types.LegacyTxType, Status: types.ReceiptStatusFailed,
        CumulativeGasUsed: 21000,
    }})
    WriteCanonicalHash(db, replacement, height) // synthetic reorg; old tx lookup stays stale
    assertMissing() // must ignore orphaned original even though lookup key still exists
    WriteCanonicalHash(db, original, height) // canonical restoration
    assertPresent(original)
    DeleteTxLookupEntry(db, tx.Hash()) // removed index
    assertMissing()
}

func TestWorkerEUnknownTransactionNeverCredits(t *testing.T) {
    db := NewMemoryDatabase()
    defer db.Close()
    unknown := common.HexToHash("0xdeadc0de")
    config := &params.ChainConfig{ChainID: big.NewInt(52014)}
    if tx, _, _, _ := ReadTransaction(db, unknown); tx != nil {
        t.Fatal("unknown transaction returned a value")
    }
    if receipt, _, _, _ := ReadReceipt(db, unknown, config); receipt != nil {
        t.Fatal("unknown receipt returned a value")
    }
}

 
// Fuzz the actual rawdb canonical lookup under synthetic reorgs and stale indexes.
func FuzzWorkerEReorgLookup(f *testing.F) {
    f.Add([]byte{0, 1, 2, 3})
    f.Add([]byte{255, 4, 5, 6})
    f.Add([]byte{1, 1, 1, 1, 1})
    f.Fuzz(func(t *testing.T, data []byte) {
        if len(data) < 4 || len(data) > 256 { return }
        db := NewMemoryDatabase()
        defer db.Close()
        height := uint64(data[0]) + 1
        original := common.HexToHash("0x1111")
        replacement := common.HexToHash("0x2222")
        tx := workerETx(uint64(data[1]))
        other := workerETx(uint64(data[1]) + 256)
        config := &params.ChainConfig{ChainID: big.NewInt(52014)}
        WriteBody(db, original, height, &types.Body{Transactions: types.Transactions{tx}})
        WriteReceipts(db, original, height, types.Receipts{&types.Receipt{
            Type: types.LegacyTxType, Status: types.ReceiptStatusSuccessful,
            CumulativeGasUsed: uint64(data[2]) + 21000,
        }})
        WriteTxLookupEntries(db, height, []common.Hash{tx.Hash()})
        WriteCanonicalHash(db, original, height)
        if got, bh, _, _ := ReadTransaction(db, tx.Hash()); got == nil || bh != original {
            t.Fatal("canonical transaction was not returned")
        }
        if got, bh, _, _ := ReadReceipt(db, tx.Hash(), config); got == nil || bh != original {
            t.Fatal("canonical receipt was not returned")
        }
        WriteBody(db, replacement, height, &types.Body{Transactions: types.Transactions{other}})
        WriteCanonicalHash(db, replacement, height)
        if got, _, _, _ := ReadTransaction(db, tx.Hash()); got != nil {
            t.Fatal("orphan transaction incorrectly returned as canonical")
        }
        if got, _, _, _ := ReadReceipt(db, tx.Hash(), config); got != nil {
            t.Fatal("orphan receipt incorrectly returned as canonical")
        }
        WriteCanonicalHash(db, original, height)
        if got, bh, _, _ := ReadReceipt(db, tx.Hash(), config); got == nil || bh != original {
            t.Fatal("restored canonical receipt lost")
        }
    })
}


// TestWorkerEOrphanHeaderRetention checks the actual certified rawdb header
// storage across canonical-hash transitions. This is a component-level
// falsification of the premise that a canonical switch itself deletes headers;
// it is NOT a consensus-valid imported-block reorganization or RPC exploit test.
func TestWorkerEOrphanHeaderRetention(t *testing.T) {
    db := NewMemoryDatabase()
    defer db.Close()
    const height uint64 = 52
    a := &types.Header{Number: new(big.Int).SetUint64(height), Extra: []byte("worker-e-A")}
    b := &types.Header{Number: new(big.Int).SetUint64(height), Extra: []byte("worker-e-B")}
    ah, bh := a.Hash(), b.Hash()
    if ah == bh { t.Fatal("independent header fixtures collided") }
    WriteHeader(db, a)
    WriteHeader(db, b)
    WriteCanonicalHash(db, ah, height)

    assertHeader := func(label string, hash common.Hash, want bool) {
        t.Helper()
        got := ReadHeader(db, hash, height)
        if (got != nil) != want {
            t.Fatalf("%s header availability mismatch hash=%s want=%v got=%v", label, hash, want, got != nil)
        }
        if want && got.Hash() != hash {
            t.Fatalf("%s returned wrong header hash=%s expected=%s", label, got.Hash(), hash)
        }
    }
    assertHeader("honest canonical A", ah, true)
    assertHeader("honest stored sibling B", bh, true)

    WriteCanonicalHash(db, bh, height)
    if got := ReadCanonicalHash(db, height); got != bh {
        t.Fatalf("canonical switch failed: got=%s expected=%s", got, bh)
    }
    assertHeader("orphan A after switch", ah, true)
    assertHeader("canonical B after switch", bh, true)

    WriteCanonicalHash(db, ah, height)
    assertHeader("restored A", ah, true)
    assertHeader("stored sibling B after restoration", bh, true)

    // Mutation sensitivity: explicit scratch-only deletion is the negative
    // control proving the read detects absent headers. This deletion is NOT
    // an attacker-reachable reorg or a claimed target vulnerability.
    DeleteHeader(db, ah, height)
    assertHeader("deliberately deleted A", ah, false)
    assertHeader("unmodified sibling B", bh, true)
    t.Log("E_HEADER_RETENTION_SWITCH_RESTORE_AND_DELETION_CONTROL_PASS")
}


// TestWorkerESameTransactionAcrossCanonicalBranches checks a counterexample
// to the simplistic rule that every transaction in an orphaned block must
// disappear: the identical transaction can also be present in the replacement.
// This uses shipped rawdb functions, not a mocked RPC backend.
func TestWorkerESameTransactionAcrossCanonicalBranches(t *testing.T) {
 db:=NewMemoryDatabase()
 defer db.Close()
 const height uint64=73
 a:=common.HexToHash("0xaabb")
 b:=common.HexToHash("0xccdd")
 tx:=workerETx(77)
 cfg:=&params.ChainConfig{ChainID:big.NewInt(52014)}
 receipt:=func(status uint64)*types.Receipt{return &types.Receipt{
  Type:types.LegacyTxType, Status:status, CumulativeGasUsed:21000,
 }}
 WriteBody(db,a,height,&types.Body{Transactions:types.Transactions{tx}})
 WriteBody(db,b,height,&types.Body{Transactions:types.Transactions{tx}})
 WriteReceipts(db,a,height,types.Receipts{receipt(types.ReceiptStatusSuccessful)})
 WriteReceipts(db,b,height,types.Receipts{receipt(types.ReceiptStatusFailed)})
 WriteTxLookupEntries(db,height,[]common.Hash{tx.Hash()})
 for _,tc:=range []struct{name string;canonical common.Hash;status uint64}{
  {"original",a,types.ReceiptStatusSuccessful},
  {"replacement_same_tx",b,types.ReceiptStatusFailed},
  {"restored",a,types.ReceiptStatusSuccessful},
 } {
  t.Run(tc.name,func(t *testing.T){
   WriteCanonicalHash(db,tc.canonical,height)
   got,hash,num,index:=ReadTransaction(db,tx.Hash())
   if got==nil||got.Hash()!=tx.Hash()||hash!=tc.canonical||num!=height||index!=0 {
    t.Fatalf("same-tx canonical lookup mismatch: hash=%s height=%d index=%d",hash,num,index)
   }
   rec,rhash,rnum,rindex:=ReadReceipt(db,tx.Hash(),cfg)
   if rec==nil||rhash!=tc.canonical||rnum!=height||rindex!=0||rec.Status!=tc.status {
    t.Fatalf("same-tx canonical receipt mismatch: receipt=%v hash=%s height=%d index=%d",rec,rhash,rnum,rindex)
   }
   t.Logf("E_SAME_TX_CANONICAL_BRANCH_PASS branch=%s status=%d",tc.canonical,tc.status)
  })
 }
 // An actually absent transaction must still be rejected when its index
 // points to a canonical body containing a different transaction.
 WriteBody(db,b,height,&types.Body{Transactions:types.Transactions{workerETx(78)}})
 WriteCanonicalHash(db,b,height)
 if got,_,_,_:=ReadTransaction(db,tx.Hash());got!=nil {t.Fatal("orphaned transaction accepted")}
 if got,_,_,_:=ReadReceipt(db,tx.Hash(),cfg);got!=nil {t.Fatal("orphaned receipt accepted")}
 t.Log("E_SAME_TX_ABSENT_REPLACEMENT_REJECTED")
}
