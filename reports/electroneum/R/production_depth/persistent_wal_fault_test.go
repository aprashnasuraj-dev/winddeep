// Worker R P2b: characterize an actual LevelDB WAL-tail fault, not just
// process exit between completed writes. Faults are explicitly local and synthetic.
// A corrupted database is not evidence of a remotely reachable security defect.
package core

import (
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
