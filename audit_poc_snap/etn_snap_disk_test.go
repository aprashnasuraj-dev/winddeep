package snap

import (
    "fmt"
    "math/big"
    "path/filepath"
    "runtime"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/params"
    "github.com/electroneum/electroneum-sc/rlp"
)

// TestETNSnapPersistentDiskStorageFanout repeats the first PoC with real
// LevelDB iterators instead of the in-memory database. Isolated temporary DB.
func TestETNSnapPersistentDiskStorageFanout(t *testing.T) {
    storage, err := rawdb.NewLevelDBDatabase(filepath.Join(t.TempDir(), "leveldb"), 64, 64, "etn-snap-fanout", false)
    if err != nil { t.Fatal(err) }
    defer storage.Close()
    db := &snapFanoutCountingDB{Database: storage}
    genesis := (&core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee)}).MustCommit(db)
    chain, err := core.NewBlockChain(db, nil, params.AllEthashProtocolChanges, ethash.NewFaker(), vm.Config{}, nil, nil)
    if err != nil { t.Fatal(err) }
    defer chain.Stop()
    if chain.Snapshots() == nil || chain.Snapshots().Snapshot(genesis.Root()) == nil {
        t.Fatal("persistent genesis snapshot not initialized")
    }
    hash := common.HexToHash("0x11223344")
    for _, n := range []int{1, 1024, 8192, 65536, 250000} {
        accounts := make([]common.Hash, n)
        for i := range accounts { accounts[i] = hash }
        req := &GetStorageRangesPacket{ID: 19, Root: genesis.Root(), Accounts: accounts, Bytes: 1}
        wire, err := rlp.EncodeToBytes(req)
        if err != nil { t.Fatal(err) }
        if len(wire) > maxMessageSize { t.Fatalf("test wire exceeds SNAP max: %d", len(wire)) }
        db.storageIterators.Store(0)
        runtime.GC()
        var before, after runtime.MemStats
        runtime.ReadMemStats(&before)
        start := time.Now()
        slots, proof := ServiceGetStorageRangesQuery(chain, req)
        elapsed := time.Since(start)
        runtime.ReadMemStats(&after)
        iterators := db.storageIterators.Load()
        allocated := after.TotalAlloc - before.TotalAlloc
        fmt.Printf("ETN_SNAP_LEVELDB_FANOUT accounts=%d wire=%d iterators=%d time=%s alloc_bytes=%d response_ranges=%d proofs=%d\n",
            n, len(wire), iterators, elapsed, allocated, len(slots), len(proof))
        if iterators != int64(n) { t.Fatalf("expected %d disk storage iterators, got %d", n, iterators) }
        if len(slots) != 0 || len(proof) != 0 { t.Fatalf("expected empty response for empty storage") }
    }
    fmt.Println("ETN_SNAP_LEVELDB_CONTROL_PASS")
}