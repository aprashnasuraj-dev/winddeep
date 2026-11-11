package snap

import (
    "bytes"
    "fmt"
    "math/big"
    "sync/atomic"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/params"
    "github.com/electroneum/electroneum-sc/rlp"
)

type snapFanoutCountingDB struct {
    ethdb.Database
    storageIterators atomic.Int64
}

func (db *snapFanoutCountingDB) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
    if bytes.HasPrefix(prefix, rawdb.SnapshotStoragePrefix) {
        db.storageIterators.Add(1)
    }
    return db.Database.NewIterator(prefix, start)
}

// TestETNSnapRepeatedEmptyStorageFanout exercises the real published
// ServiceGetStorageRangesQuery on a disposable, freshly initialized blockchain.
// It performs NO live-network traffic and never reads a user's wallet.
func TestETNSnapRepeatedEmptyStorageFanout(t *testing.T) {
    db := &snapFanoutCountingDB{Database: rawdb.NewMemoryDatabase()}
    genesis := (&core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee)}).MustCommit(db)
    chain, err := core.NewBlockChain(db, nil, params.AllEthashProtocolChanges, ethash.NewFaker(), vm.Config{}, nil, nil)
    if err != nil { t.Fatal(err) }
    defer chain.Stop()

    if chain.Snapshots() == nil || chain.Snapshots().Snapshot(genesis.Root()) == nil {
        t.Fatal("snapshot for isolated genesis not available")
    }
    // No storage exists in the test genesis. A repeated arbitrary account hash
    // therefore triggers a storage-iterator creation but contributes no response bytes.
    hash := common.HexToHash("0x11223344")
    for _, n := range []int{1, 64, 1024, 8192, 32768, 131072} {
        accounts := make([]common.Hash, n)
        for i := range accounts { accounts[i] = hash }
        wire, err := rlp.EncodeToBytes(&GetStorageRangesPacket{
            ID: 9, Root: genesis.Root(), Accounts: accounts, Bytes: 1,
        })
        if err != nil { t.Fatal(err) }
        if len(wire) >= maxMessageSize { t.Fatalf("oversize input: %d", len(wire)) }
        var decoded GetStorageRangesPacket
        if err := rlp.DecodeBytes(wire, &decoded); err != nil { t.Fatal(err) }
        if len(decoded.Accounts) != n { t.Fatalf("round-trip count: %d != %d", len(decoded.Accounts), n) }
        db.storageIterators.Store(0)
        start := time.Now()
        slots, proof := ServiceGetStorageRangesQuery(chain, &decoded)
        elapsed := time.Since(start)
        got := db.storageIterators.Load()
        fmt.Printf("ETN_SNAP_FANOUT accounts=%d wire=%d iterators=%d elapsed=%s response_ranges=%d proofs=%d\n",
            n, len(wire), got, elapsed, len(slots), len(proof))
        if got != int64(n) { t.Fatalf("storage-iterator fanout: got %d want %d", got, n) }
        if len(slots) != 0 || len(proof) != 0 { t.Fatalf("expected empty response, got slots=%d proof=%d", len(slots), len(proof)) }
    }
    // Strong negative control: zero-byte budget must suppress all iterator creation.
    db.storageIterators.Store(0)
    slots, proof := ServiceGetStorageRangesQuery(chain, &GetStorageRangesPacket{
        ID: 10, Root: genesis.Root(), Accounts: []common.Hash{hash, hash, hash}, Bytes: 0,
    })
    if got := db.storageIterators.Load(); got != 0 { t.Fatalf("zero budget performed %d lookups", got) }
    if len(slots) != 0 || len(proof) != 0 { t.Fatal("zero budget returned results") }
    fmt.Println("ETN_SNAP_NEGATIVE_CONTROL_PASS")
}