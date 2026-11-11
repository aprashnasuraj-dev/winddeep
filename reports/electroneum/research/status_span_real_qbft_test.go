// Research-only: single-process, local QBFT chain; no network requests.
// Measures the number of header lookups performed by the public Istanbul Status API.
// A successful test demonstrates linear API cost, not an unauthenticated P2 exploit.
package backend

import (
  "sync/atomic"
  "testing"

  "github.com/electroneum/electroneum-sc/consensus"
  "github.com/electroneum/electroneum-sc/core/types"
  "github.com/electroneum/electroneum-sc/rpc"
)

type auditStatusSpyChain struct {
  consensus.ChainHeaderReader
  reads uint64
}

func (s *auditStatusSpyChain) GetHeaderByNumber(number uint64) *types.Header {
  atomic.AddUint64(&s.reads, 1)
  return s.ChainHeaderReader.GetHeaderByNumber(number)
}

// This test uses the actual Backend.API.Status method and genuine canonical,
// signed blocks. No mock replacement for Status or getSigners is used.
func TestAuditStatusRangeLinearRealQBFT(t *testing.T) {
  chain, engine := newBlockChain(1)
  defer engine.Stop()
  for i := 0; i < 4; i++ {
    block := makeBlock(chain, engine, chain.CurrentBlock())
    if block == nil {
      t.Fatal("signed block generation returned nil")
    }
    n, err := chain.InsertChain([]*types.Block{block})
    if err != nil || n != 1 {
      t.Fatalf("canonical insert %d: count=%d err=%v", i, n, err)
    }
  }
  for _, endNumber := range []int64{2, 3, 4} {
    spy := &auditStatusSpyChain{ChainHeaderReader: chain}
    api := &API{chain: spy, backend: engine}
    first, last := rpc.BlockNumber(1), rpc.BlockNumber(endNumber)
    got, err := api.Status(&first, &last)
    if err != nil {
      t.Fatalf("istanbul_status range 1..%d failed: %v", endNumber, err)
    }
    want := uint64(endNumber-1)
    reads := atomic.LoadUint64(&spy.reads)
    if reads != want {
      t.Fatalf("header reads in range 1..%d = %d, want %d", endNumber, reads, want)
    }
    if got == nil || got.NumBlocks != want {
      t.Fatalf("status result range 1..%d = %+v, expected %d blocks", endNumber, got, want)
    }
    t.Logf("ETN_STATUS_REAL_QBFT end=%d scanned=%d requested=%d", endNumber, reads, want)
  }
}
