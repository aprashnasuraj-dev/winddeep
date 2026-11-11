package snap

import (
    "fmt"
    "math/big"
    "path/filepath"
    "runtime"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/params"
)

func TestETNSnapConcurrentServiceFanout(t *testing.T) {
    storage, err := rawdb.NewLevelDBDatabase(filepath.Join(t.TempDir(), "leveldb"), 64, 64, "etn-snap-parallel", false)
    if err != nil { t.Fatal(err) }
    defer storage.Close()
    db := &snapFanoutCountingDB{Database: storage}
    genesis := (&core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee)}).MustCommit(db)
    chain, err := core.NewBlockChain(db, nil, params.AllEthashProtocolChanges, ethash.NewFaker(), vm.Config{}, nil, nil)
    if err != nil { t.Fatal(err) }
    defer chain.Stop()
    if chain.Snapshots() == nil || chain.Snapshots().Snapshot(genesis.Root()) == nil {
        t.Fatal("persistent genesis snapshot missing")
    }

    const peers = 8
    const hashesPerRequest = 250000
    accounts := make([]common.Hash, hashesPerRequest)
    for i := range accounts { accounts[i] = common.HexToHash("0x11223344") }

    runtime.GC()
    var initial runtime.MemStats
    runtime.ReadMemStats(&initial)
    var peakHeap atomic.Uint64
    peakHeap.Store(initial.HeapAlloc)
    stop := make(chan struct{})
    sampled := make(chan struct{})
    go func() {
        defer close(sampled)
        ticker := time.NewTicker(2*time.Millisecond)
        defer ticker.Stop()
        for {
            select {
            case <-stop:
                return
            case <-ticker.C:
                var m runtime.MemStats
                runtime.ReadMemStats(&m)
                for {
                    prev := peakHeap.Load()
                    if m.HeapAlloc <= prev || peakHeap.CompareAndSwap(prev,m.HeapAlloc) { break }
                }
            }
        }
    }()
    db.storageIterators.Store(0)
    startGate := make(chan struct{})
    var wg sync.WaitGroup
    errs := make(chan string, peers)
    start := time.Now()
    for i:=0; i<peers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            <-startGate
            req := &GetStorageRangesPacket{ID: 27, Root: genesis.Root(), Accounts: accounts, Bytes: 1}
            slots, proof := ServiceGetStorageRangesQuery(chain,req)
            if len(slots)>0 || len(proof)>0 { errs <- "unexpected non-empty response" }
        }()
    }
    close(startGate)
    wg.Wait()
    elapsed := time.Since(start)
    close(stop)
    <-sampled
    close(errs)
    for err := range errs { t.Error(err) }
    var ending runtime.MemStats
    runtime.ReadMemStats(&ending)
    got := db.storageIterators.Load()
    allocations := ending.TotalAlloc - initial.TotalAlloc
    fmt.Printf("ETN_SNAP_CONCURRENT_SERVICE peer_models=%d accounts_each=%d total_iterators=%d elapsed=%s cumulative_alloc_bytes=%d peak_sampled_heap_bytes=%d initial_heap_bytes=%d gc_cycles=%d\n",
       peers, hashesPerRequest, got, elapsed, allocations, peakHeap.Load(), initial.HeapAlloc, ending.NumGC-initial.NumGC)
    if got != peers*hashesPerRequest {
        t.Fatalf("wrong total storage iterations %d, expected %d",got,peers*hashesPerRequest)
    }
    fmt.Println("ETN_SNAP_CONCURRENT_ACCOUNTING_PASS")
}