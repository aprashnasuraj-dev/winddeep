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
