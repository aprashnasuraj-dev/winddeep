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
)

// The layered snapshots are synthetically created with Tree.Update; their root
// hashes are NOT real canonical EVM roots. This isolates complexity of the
// unchanged storage range service; it is not proof of network reachability.
func TestETNSnapLayeredSnapshotStorageFanout(t *testing.T) {
    kv, err := rawdb.NewLevelDBDatabase(filepath.Join(t.TempDir(), "leveldb"), 64, 64, "snap-layer-work", false)
    if err != nil { t.Fatal(err) }
    defer kv.Close()
    db := &snapFanoutCountingDB{Database: kv}
    genesis := (&core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee)}).MustCommit(db)
    chain, err := core.NewBlockChain(db, nil, params.AllEthashProtocolChanges, ethash.NewFaker(), vm.Config{}, nil, nil)
    if err != nil { t.Fatal(err) }
    defer chain.Stop()
    snaps := chain.Snapshots()
    if snaps == nil || snaps.Snapshot(genesis.Root()) == nil { t.Fatal("snapshots unavailable") }

    const n = 16384
    accounts := make([]common.Hash, n)
    for i:=range accounts { accounts[i]=common.HexToHash("0x11223344") }
    root := genesis.Root()
    depth := 0
    for _, targetDepth := range []int{0,8,32,128} {
        for depth<targetDepth {
            next := common.BigToHash(big.NewInt(int64(depth+100000)))
            if err := snaps.Update(next, root, map[common.Hash]struct{}{}, map[common.Hash][]byte{}, map[common.Hash]map[common.Hash][]byte{}); err!=nil {t.Fatal(err)}
            root = next
            depth++
        }
        runtime.GC()
        var before, after runtime.MemStats
        runtime.ReadMemStats(&before)
        db.storageIterators.Store(0)
        start :=time.Now()
        slots,proof:=ServiceGetStorageRangesQuery(chain,&GetStorageRangesPacket{
            ID: 23, Root:root, Accounts:accounts, Bytes:1,
        })
        elapsed:=time.Since(start)
        runtime.ReadMemStats(&after)
        fmt.Printf("ETN_SNAP_LAYER_DEPTH synthetic_diff_layers=%d accounts=%d real_leveldb_iterators=%d elapsed=%s cumulative_alloc_bytes=%d ranges=%d proofs=%d\n",depth,n,db.storageIterators.Load(),elapsed,after.TotalAlloc-before.TotalAlloc,len(slots),len(proof))
        if db.storageIterators.Load()!=n || len(slots)!=0 || len(proof)!=0 {
            t.Fatalf("unexpected fanout outcome at depth %d",depth)
        }
    }
    fmt.Println("ETN_SNAP_LAYERED_SERVICE_PASS")
}