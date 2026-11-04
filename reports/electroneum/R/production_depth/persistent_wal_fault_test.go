// Worker R P2b: characterize an actual LevelDB WAL-tail fault, not just
// process exit between completed writes. Faults are explicitly local and synthetic.
// A corrupted database is not evidence of a remotely reachable security defect.
package core

import (
    "math/big"
    "github.com/electroneum/electroneum-sc/crypto"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "sort"
    "strings"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/trie"
)

func rWALCopyDirectory(t *testing.T, src, dst string) {
    t.Helper()
    if err := os.MkdirAll(dst, 0700); err != nil { t.Fatal(err) }
    entries, err := os.ReadDir(src)
    if err != nil { t.Fatal(err) }
    for _, entry := range entries {
        if entry.IsDir() { t.Fatalf("R_WAL_UNEXPECTED_SUBDIRECTORY name=%s", entry.Name()) }
        in, err := os.Open(filepath.Join(src, entry.Name()))
        if err != nil { t.Fatal(err) }
        out, err := os.OpenFile(filepath.Join(dst, entry.Name()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
        if err != nil { in.Close(); t.Fatal(err) }
        _, copyErr := io.Copy(out, in)
        closeErr := out.Close()
        inCloseErr := in.Close()
        if copyErr != nil || closeErr != nil || inCloseErr != nil {
            t.Fatalf("R_WAL_COPY_FAIL file=%s copy=%v close=%v input=%v", entry.Name(), copyErr, closeErr, inCloseErr)
        }
    }
}

func rWALInjectTail(t *testing.T, path, mode string) {
    t.Helper()
    entries, err := os.ReadDir(path)
    if err != nil { t.Fatal(err) }
    var logs []string
    for _, entry := range entries {
        if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".log") && strings.TrimSuffix(entry.Name(), ".log") != "LOG" {
            logs = append(logs, entry.Name())
        }
    }
    sort.Strings(logs)
    if len(logs) == 0 { t.Fatal("R_WAL_FAULT_NO_LEVELDB_LOG") }
    name := filepath.Join(path, logs[len(logs)-1])
    data, err := os.ReadFile(name)
    if err != nil { t.Fatal(err) }
    if len(data) < 128 { t.Fatalf("R_WAL_FAULT_LOG_TOO_SMALL bytes=%d", len(data)) }
    switch mode {
    case "truncate_1":
        data = data[:len(data)-1]
    case "truncate_64":
        data = data[:len(data)-64]
    case "flip_last":
        data[len(data)-1] ^= 0xff
    default:
        t.Fatalf("R_WAL_FAULT_UNKNOWN_MODE %s", mode)
    }
    if err := os.WriteFile(name, data, 0600); err != nil { t.Fatal(err) }
    t.Logf("R_WAL_FAULT_INJECTED mode=%s journal=%s remaining_bytes=%d", mode, logs[len(logs)-1], len(data))
}

func TestRLevelDBWALTailFaultMatrix(t *testing.T) {
    // The existing P2 child writes a complete, coherent checkpoint and exits
    // without a LevelDB Close. No WAL bytes are altered until it has exited.
    baselinePath := filepath.Join(t.TempDir(), "abrupt-source")
    child := exec.Command(os.Args[0], "-test.run=^TestRPersistentSubprocessAbruptExitChild$", "-test.v")
    child.Env = append(os.Environ(), "R_PERSIST_CHILD_STAGE=complete", "R_PERSIST_CHILD_PATH="+baselinePath)
    output, err := child.CombinedOutput()
    exit, ok := err.(*exec.ExitError)
    if !ok || exit.ExitCode() != 97 {
        t.Fatalf("R_WAL_FAULT_ABRUPT_CHILD_CONTROL_FAIL err=%v output=%s", err, output)
    }

    modes := []string{"clean", "truncate_1", "truncate_64", "flip_last"}
    for _, mode := range modes {
        t.Run(mode, func(t *testing.T) {
            path := filepath.Join(t.TempDir(), "chaindata")
            rWALCopyDirectory(t, baselinePath, path)
            if mode != "clean" { rWALInjectTail(t, path, mode) }

            db, err := rawdb.NewLevelDBDatabase(path, 16, 16, "r-wal-fault", false)
            if err != nil {
                if mode == "clean" { t.Fatalf("R_WAL_CLEAN_REOPEN_FAIL: %v", err) }
                t.Logf("R_WAL_FAULT_STRUCTURED_REOPEN_REJECTION mode=%s err=%v", mode, err)
                return
            }
            genesisHash := rawdb.ReadCanonicalHash(db, 0)
            if genesisHash == (common.Hash{}) {
                db.Close()
                t.Fatal("R_WAL_FAULT_GENESIS_LOST")
            }
            cfg := rawdb.ReadChainConfig(db, genesisHash)
            if cfg == nil { db.Close(); t.Fatal("R_WAL_FAULT_CONFIG_LOST") }

            canonical := rawdb.ReadCanonicalHash(db, 1)
            headHash := rawdb.ReadHeadBlockHash(db)
            if canonical != (common.Hash{}) {
                header := rawdb.ReadHeader(db, canonical, 1)
                if header == nil {
                    db.Close()
                    t.Fatalf("R_WAL_CANONICAL_MAPPING_WITHOUT_HEADER mode=%s", mode)
                }
                body := rawdb.ReadBody(db, canonical, 1)
                if body != nil {
                    if root := types.DeriveSha(types.Transactions(body.Transactions), trie.NewStackTrie(nil)); root != header.TxHash {
                        db.Close()
                        t.Fatalf("R_WAL_BODY_TX_ROOT_MISMATCH mode=%s", mode)
                    }
                }
                receipts := rawdb.ReadRawReceipts(db, canonical, 1)
                if receipts != nil {
                    if root := types.DeriveSha(receipts, trie.NewStackTrie(nil)); root != header.ReceiptHash {
                        db.Close()
                        t.Fatalf("R_WAL_RECEIPT_ROOT_MISMATCH mode=%s", mode)
                    }
                }
            }
            if headHash != genesisHash && headHash != (common.Hash{}) {
                if block := rawdb.ReadBlock(db, headHash, 1); block == nil {
                    db.Close()
                    t.Fatalf("R_WAL_FULL_HEAD_WITHOUT_COMPLETE_BLOCK mode=%s", mode)
                }
            }
            if mode == "clean" && (canonical == (common.Hash{}) || headHash != canonical) {
                db.Close()
                t.Fatalf("R_WAL_CLEAN_POSITIVE_CONTROL_FAIL canonical=%s full=%s", canonical, headHash)
            }

            chain, err := NewBlockChain(db, nil, cfg, ethash.NewFaker(), vm.Config{}, nil, nil)
            if err != nil {
                db.Close()
                if mode == "clean" { t.Fatalf("R_WAL_CLEAN_CHAIN_RESTART_FAIL: %v", err) }
                t.Logf("R_WAL_FAULT_CHAIN_RESTART_REJECTION mode=%s err=%v", mode, err)
                return
            }
            head := chain.CurrentBlock()
            if head == nil { chain.Stop(); db.Close(); t.Fatalf("R_WAL_RESTART_NIL_FULL_HEAD mode=%s", mode) }
            if rawdb.ReadBlock(db, head.Hash(), head.NumberU64()) == nil {
                chain.Stop(); db.Close(); t.Fatalf("R_WAL_RESTART_HEAD_BLOCK_MISSING mode=%s", mode)
            }
            t.Logf("R_WAL_FAULT_RESTART_COHERENT mode=%s full=%d canonical_one=%t", mode, head.NumberU64(), canonical != (common.Hash{}))
            chain.Stop()
            if err := db.Close(); err != nil { t.Fatal(err) }
        })
    }
    t.Log("R_WAL_FAULT_MATRIX_PASS local_synthetic_fault_only_no_remote_exploit_claim")
}


// TestRLevelDBWALResumeSync exercises the next stage omitted by P2b: actual
// BlockChain.InsertChain after local WAL-tail loss, then persistence across
// another clean restart. This is NOT a remote fault-injection model.
func TestRLevelDBWALResumeSync(t *testing.T) {
    baselinePath := filepath.Join(t.TempDir(), "abrupt-source")
    child := exec.Command(os.Args[0], "-test.run=^TestRPersistentSubprocessAbruptExitChild$", "-test.v")
    child.Env = append(os.Environ(), "R_PERSIST_CHILD_STAGE=complete", "R_PERSIST_CHILD_PATH="+baselinePath)
    output, err := child.CombinedOutput()
    exit, ok := err.(*exec.ExitError)
    if !ok || exit.ExitCode() != 97 {
        t.Fatalf("R_WAL_RESUME_CHILD_CONTROL_FAIL err=%v output=%s", err, output)
    }

    for _, mode := range []string{"clean", "truncate_1", "truncate_64", "flip_last"} {
        t.Run(mode, func(t *testing.T) {
            path := filepath.Join(t.TempDir(), "chaindata")
            rWALCopyDirectory(t, baselinePath, path)
            if mode != "clean" { rWALInjectTail(t, path, mode) }

            db := rOpenPersist(t, path)
            genesisHash := rawdb.ReadCanonicalHash(db, 0)
            genesis := rawdb.ReadBlock(db, genesisHash, 0)
            cfg := rawdb.ReadChainConfig(db, genesisHash)
            if genesis == nil || cfg == nil {
                db.Close()
                t.Fatalf("R_WAL_RESUME_GENESIS_OR_CONFIG_LOST mode=%s", mode)
            }
            oldCanonical := rawdb.ReadCanonicalHash(db, 1)
            if oldCanonical == (common.Hash{}) {
                db.Close()
                t.Fatalf("R_WAL_RESUME_OLD_CANONICAL_MAPPING_MISSING mode=%s", mode)
            }
            var oldTxHash common.Hash
            oldBody := rawdb.ReadBody(db, oldCanonical, 1)
            if oldBody != nil && len(oldBody.Transactions) > 0 {
                oldTxHash = oldBody.Transactions[0].Hash()
            }
            chain, err := NewBlockChain(db, nil, cfg, ethash.NewFaker(), vm.Config{}, nil, nil)
            if err != nil {
                db.Close()
                t.Fatalf("R_WAL_RESUME_CHAIN_BOOT_FAIL mode=%s err=%v", mode, err)
            }
            preFull := chain.CurrentBlock()
            if preFull == nil {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_PREHEAD_MISSING mode=%s", mode)
            }
            if mode == "truncate_64" && preFull.NumberU64() != 0 {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_FALLBACK_PRECONDITION_FAIL mode=%s got=%d", mode, preFull.NumberU64())
            }

            key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
            if err != nil { chain.Stop(); db.Close(); t.Fatal(err) }
            sender := crypto.PubkeyToAddress(key.PublicKey)
            destination := common.HexToAddress("0x0000000000000000000000000000000000000099")
            signer := types.LatestSigner(cfg)
            var tx *types.Transaction
            fork, _ := GenerateChain(cfg, genesis, ethash.NewFaker(), db, 2, func(i int, b *BlockGen) {
                b.SetExtra([]byte{0x52, 0x57, 0x41, 0x4c, byte(i)})
                if i == 0 {
                    var signErr error
                    tx, signErr = types.SignTx(types.NewTransaction(
                        b.TxNonce(sender), destination, big.NewInt(23), 100000, b.BaseFee(), []byte{0xf1, 0x0e},
                    ), signer, key)
                    if signErr != nil { t.Fatal(signErr) }
                    b.AddTx(tx)
                }
            })
            if len(fork) != 2 || tx == nil || fork[0].Hash() == oldCanonical {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_FORK_FIXTURE_INVALID mode=%s", mode)
            }
            if oldTxHash != (common.Hash{}) && oldTxHash == tx.Hash() {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_TX_HASH_COLLISION mode=%s", mode)
            }

            // Counterexample: a structurally linked but invalid transaction
            // root must be rejected before any fork changes the canonical view.
            invalidHeader := fork[0].Header()
            invalidHeader.TxHash = common.HexToHash("0xdeadbeef")
            invalid := types.NewBlockWithHeader(invalidHeader).WithBody(fork[0].Transactions(), fork[0].Uncles())
            if _, badErr := chain.InsertChain(types.Blocks{invalid}); badErr == nil ||
                !strings.Contains(badErr.Error(), "transaction root") {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_INVALID_ROOT_NOT_REJECTED mode=%s err=%v", mode, badErr)
            }
            if chain.CurrentBlock().Hash() != preFull.Hash() || chain.GetCanonicalHash(1) != oldCanonical {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_INVALID_FORK_MUTATED_CANONICAL mode=%s", mode)
            }
            t.Logf("R_WAL_RESUME_INVALID_FORK_REJECTED_PASS mode=%s", mode)

            // Import a longer, distinct valid chain through production insertion.
            if index, insertErr := chain.InsertChain(fork); insertErr != nil {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_VALID_FORK_IMPORT_FAIL mode=%s index=%d err=%v", mode, index, insertErr)
            }
            if chain.CurrentBlock().Hash() != fork[1].Hash() ||
                chain.GetCanonicalHash(1) != fork[0].Hash() ||
                chain.GetCanonicalHash(2) != fork[1].Hash() {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_CANONICAL_ADVANCE_FAIL mode=%s full=%s height1=%s height2=%s",
                    mode, chain.CurrentBlock().Hash(), chain.GetCanonicalHash(1), chain.GetCanonicalHash(2))
            }
            headerHead := chain.CurrentHeader()
            fastHead := chain.CurrentFastBlock()
            if headerHead == nil || headerHead.Hash() != fork[1].Hash() ||
                fastHead == nil || fastHead.Hash() != fork[1].Hash() {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_HEADER_FAST_HEAD_DIVERGENCE mode=%s", mode)
            }
            found, indexedHash, indexedNumber, indexedAt := rawdb.ReadTransaction(db, tx.Hash())
            if found == nil || found.Hash() != tx.Hash() ||
                indexedHash != fork[0].Hash() || indexedNumber != 1 || indexedAt != 0 {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_NEW_TX_LOOKUP_FAIL mode=%s tx=%v block=%s number=%d index=%d",
                    mode, found, indexedHash, indexedNumber, indexedAt)
            }
            receipt, receiptHash, receiptNumber, receiptIndex := rawdb.ReadReceipt(db, tx.Hash(), cfg)
            if receipt == nil || receipt.TxHash != tx.Hash() || receipt.Status != types.ReceiptStatusSuccessful ||
                receiptHash != fork[0].Hash() || receiptNumber != 1 || receiptIndex != 0 {
                chain.Stop(); db.Close()
                t.Fatalf("R_WAL_RESUME_NEW_RECEIPT_LOOKUP_FAIL mode=%s receipt=%v block=%s number=%d index=%d",
                    mode, receipt, receiptHash, receiptNumber, receiptIndex)
            }
            if oldTxHash != (common.Hash{}) {
                if orphan, _, _, _ := rawdb.ReadTransaction(db, oldTxHash); orphan != nil {
                    chain.Stop(); db.Close()
                    t.Fatalf("R_WAL_RESUME_STALE_ORPHAN_TX_LOOKUP mode=%s hash=%s", mode, oldTxHash)
                }
            }
            t.Logf("R_WAL_RESUME_SYNC_ADVANCED_PASS mode=%s previous_full=%d resumed_full=%d",
                mode, preFull.NumberU64(), chain.CurrentBlock().NumberU64())
            chain.Stop()
            if err := db.Close(); err != nil { t.Fatal(err) }

            reopened := rOpenPersist(t, path)
            cfg2 := rawdb.ReadChainConfig(reopened, rawdb.ReadCanonicalHash(reopened, 0))
            restarted, err := NewBlockChain(reopened, nil, cfg2, ethash.NewFaker(), vm.Config{}, nil, nil)
            if err != nil {
                reopened.Close()
                t.Fatalf("R_WAL_RESUME_SECOND_RESTART_FAIL mode=%s err=%v", mode, err)
            }
            if restarted.CurrentBlock().Hash() != fork[1].Hash() ||
                restarted.CurrentHeader().Hash() != fork[1].Hash() ||
                restarted.CurrentFastBlock().Hash() != fork[1].Hash() ||
                restarted.GetCanonicalHash(1) != fork[0].Hash() ||
                restarted.GetCanonicalHash(2) != fork[1].Hash() {
                restarted.Stop(); reopened.Close()
                t.Fatalf("R_WAL_RESUME_DURABLE_HEAD_MISMATCH mode=%s", mode)
            }
            persistedTx, _, _, _ := rawdb.ReadTransaction(reopened, tx.Hash())
            persistedReceipt, _, _, _ := rawdb.ReadReceipt(reopened, tx.Hash(), cfg2)
            if persistedTx == nil || persistedTx.Hash() != tx.Hash() ||
                persistedReceipt == nil || persistedReceipt.TxHash != tx.Hash() {
                restarted.Stop(); reopened.Close()
                t.Fatalf("R_WAL_RESUME_DURABLE_TX_RECEIPT_MISSING mode=%s", mode)
            }
            t.Logf("R_WAL_RESUME_SECOND_RESTART_PASS mode=%s head=%d", mode, restarted.CurrentBlock().NumberU64())
            restarted.Stop()
            if err := reopened.Close(); err != nil { t.Fatal(err) }
        })
    }
    t.Log("R_WAL_RESUME_SYNC_MATRIX_PASS local_post_exit_WAL_fault_no_remote_exploit_claim")
}
