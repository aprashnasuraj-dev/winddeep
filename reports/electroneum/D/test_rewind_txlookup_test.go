// Worker D: certified-runtime rewind/reimport transaction lookup canonicality regression.
// Copied into a disposable scratch copy of the immutable certified target.
package core

import (
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/params"
)

// TestWorkerDRewindTxLookupCanonicality exercises the real BlockChain SetHead
// path with signed transactions, then imports a valid replacement branch and
// reopens the database. A raw txlookup row may survive the rewind; the security
// invariant is that hash-based transaction/receipt reads must never resolve the
// orphaned transaction as canonical after rewind, replacement, or restart.
func TestWorkerDRewindTxLookupCanonicality(t *testing.T) {
    key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
    if err != nil {
        t.Fatalf("key: %v", err)
    }
    sender := crypto.PubkeyToAddress(key.PublicKey)
    db := rawdb.NewMemoryDatabase()
    gspec := &Genesis{
        Config: params.TestChainConfig,
        Alloc: GenesisAlloc{
            sender: {Balance: big.NewInt(100000000000000000)},
        },
        BaseFee: big.NewInt(params.InitialBaseFee),
    }
    genesis := gspec.MustCommit(db)
    signer := types.LatestSigner(gspec.Config)
    engine := ethash.NewFaker()

    chainA, _ := GenerateChain(gspec.Config, genesis, engine, db, 3, func(i int, b *BlockGen) {
        to := common.BigToAddress(big.NewInt(int64(0xA0 + i)))
        tx, err := types.SignTx(
            types.NewTransaction(b.TxNonce(sender), to, big.NewInt(int64(1000+i)), params.TxGas, b.header.BaseFee, nil),
            signer, key,
        )
        if err != nil {
            panic(err)
        }
        b.AddTx(tx)
    })

    bc, err := NewBlockChain(db, nil, gspec.Config, engine, vm.Config{}, nil, nil)
    if err != nil {
        t.Fatalf("new chain: %v", err)
    }
    if n, err := bc.InsertChain(chainA); err != nil {
        bc.Stop()
        t.Fatalf("insert chain A at %d: %v", n, err)
    }

    oldTx := chainA[1].Transactions()[0] // height 2: must become orphaned by SetHead(1)
    if idx := rawdb.ReadTxLookupEntry(db, oldTx.Hash()); idx == nil || *idx != 2 {
        bc.Stop()
        t.Fatalf("honest precondition: missing/wrong txlookup for A tx: %v", idx)
    }
    if tx, bh, bn, _ := rawdb.ReadTransaction(db, oldTx.Hash()); tx == nil || bh != chainA[1].Hash() || bn != 2 {
        bc.Stop()
        t.Fatalf("honest precondition: canonical A transaction lookup failed")
    }
    if rcpt, bh, bn, _ := rawdb.ReadReceipt(db, oldTx.Hash(), gspec.Config); rcpt == nil || bh != chainA[1].Hash() || bn != 2 {
        bc.Stop()
        t.Fatalf("honest precondition: canonical A receipt lookup failed")
    }

    if err := bc.SetHead(1); err != nil {
        bc.Stop()
        t.Fatalf("SetHead(1): %v", err)
    }
    if got := rawdb.ReadCanonicalHash(db, 2); got != (common.Hash{}) {
        bc.Stop()
        t.Fatalf("rewind left canonical hash at height 2: %s", got)
    }

    staleAfterRewind := rawdb.ReadTxLookupEntry(db, oldTx.Hash())
    if staleAfterRewind != nil {
        t.Logf("WORKER_D_RAW_TXLOOKUP_SURVIVED_REWIND tx=%s height=%d", oldTx.Hash(), *staleAfterRewind)
    } else {
        t.Logf("WORKER_D_RAW_TXLOOKUP_CLEANED_ON_REWIND tx=%s", oldTx.Hash())
    }
    if tx, _, _, _ := rawdb.ReadTransaction(db, oldTx.Hash()); tx != nil {
        bc.Stop()
        t.Fatalf("WORKER_D_STALE_CANONICAL_TRANSACTION_AFTER_REWIND tx=%s", oldTx.Hash())
    }
    if rcpt, _, _, _ := rawdb.ReadReceipt(db, oldTx.Hash(), gspec.Config); rcpt != nil {
        bc.Stop()
        t.Fatalf("WORKER_D_STALE_CANONICAL_RECEIPT_AFTER_REWIND tx=%s", oldTx.Hash())
    }

    // Build a valid sibling from the retained height-1 state with distinct txs.
    chainB, _ := GenerateChain(gspec.Config, chainA[0], engine, db, 2, func(i int, b *BlockGen) {
        to := common.BigToAddress(big.NewInt(int64(0xB0 + i)))
        tx, err := types.SignTx(
            types.NewTransaction(b.TxNonce(sender), to, big.NewInt(int64(9000+i)), params.TxGas, b.header.BaseFee, nil),
            signer, key,
        )
        if err != nil {
            panic(err)
        }
        b.AddTx(tx)
    })
    if n, err := bc.InsertChain(chainB); err != nil {
        bc.Stop()
        t.Fatalf("insert replacement chain B at %d: %v", n, err)
    }
    if got := rawdb.ReadCanonicalHash(db, 2); got != chainB[0].Hash() {
        bc.Stop()
        t.Fatalf("replacement canonical mismatch at 2: got=%s want=%s", got, chainB[0].Hash())
    }

    newTx := chainB[0].Transactions()[0]
    if tx, bh, bn, _ := rawdb.ReadTransaction(db, newTx.Hash()); tx == nil || bh != chainB[0].Hash() || bn != 2 {
        bc.Stop()
        t.Fatalf("replacement B transaction not canonical")
    }
    if rcpt, bh, bn, _ := rawdb.ReadReceipt(db, newTx.Hash(), gspec.Config); rcpt == nil || bh != chainB[0].Hash() || bn != 2 {
        bc.Stop()
        t.Fatalf("replacement B receipt not canonical")
    }
    if tx, _, _, _ := rawdb.ReadTransaction(db, oldTx.Hash()); tx != nil {
        bc.Stop()
        t.Fatalf("WORKER_D_STALE_CANONICAL_TRANSACTION_AFTER_REIMPORT tx=%s", oldTx.Hash())
    }
    if rcpt, _, _, _ := rawdb.ReadReceipt(db, oldTx.Hash(), gspec.Config); rcpt != nil {
        bc.Stop()
        t.Fatalf("WORKER_D_STALE_CANONICAL_RECEIPT_AFTER_REIMPORT tx=%s", oldTx.Hash())
    }

    bc.Stop()
    reopened, err := NewBlockChain(db, nil, gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
    if err != nil {
        t.Fatalf("reopen: %v", err)
    }
    defer reopened.Stop()

    if got := reopened.CurrentBlock().Hash(); got != chainB[len(chainB)-1].Hash() {
        t.Fatalf("restart head mismatch: got=%s want=%s", got, chainB[len(chainB)-1].Hash())
    }
    if tx, _, _, _ := rawdb.ReadTransaction(db, oldTx.Hash()); tx != nil {
        t.Fatalf("WORKER_D_STALE_CANONICAL_TRANSACTION_AFTER_RESTART tx=%s", oldTx.Hash())
    }
    if rcpt, _, _, _ := rawdb.ReadReceipt(db, oldTx.Hash(), gspec.Config); rcpt != nil {
        t.Fatalf("WORKER_D_STALE_CANONICAL_RECEIPT_AFTER_RESTART tx=%s", oldTx.Hash())
    }
    if tx, bh, bn, _ := rawdb.ReadTransaction(db, newTx.Hash()); tx == nil || bh != chainB[0].Hash() || bn != 2 {
        t.Fatalf("replacement B transaction lost after restart")
    }

    if idx := rawdb.ReadTxLookupEntry(db, oldTx.Hash()); idx != nil {
        t.Logf("WORKER_D_RAW_TXLOOKUP_STILL_PRESENT_AFTER_RESTART tx=%s height=%d", oldTx.Hash(), *idx)
    } else {
        t.Logf("WORKER_D_RAW_TXLOOKUP_ABSENT_AFTER_RESTART tx=%s", oldTx.Hash())
    }
    t.Log("WORKER_D_REWIND_TXLOOKUP_CANONICALITY_PASS")
}
