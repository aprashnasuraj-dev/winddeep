package backend

import (
    "testing"
    "github.com/electroneum/electroneum-sc/core/types"
)

// TestWorkerAQBFTGasUsedSealIntegrity checks whether an unprivileged peer can
// alter the gas accounting commitment of a signed QBFT block after sealing.
// This is an admission/security guard test, NOT proof of financial exploitation.
func TestWorkerAQBFTGasUsedSealIntegrity(t *testing.T) {
    for _, n := range []int{1, 2, 3} {
        t.Run(string(rune('0'+n)), func(t *testing.T) {
            chain, engine := newBlockChain(1)
            defer engine.Stop()
            parent := chain.Genesis()
            for i := 0; i < n; i++ {
                honest := makeBlock(chain, engine, parent)
                if honest == nil { t.Fatal("nil signed QBFT block") }
                if index, err := chain.InsertChain(types.Blocks{honest}); err != nil {
                    t.Fatalf("honest QBFT import height=%d index=%d: %v", i+1, index, err)
                }
                parent = honest
            }
            before := chain.CurrentBlock()
            stateBefore, err := chain.State()
            if err != nil { t.Fatal(err) }
            _ = stateBefore
            candidate := makeBlock(chain, engine, parent)
            if candidate == nil { t.Fatal("nil candidate") }
            tamperedHeader := types.CopyHeader(candidate.Header())
            tamperedHeader.GasUsed++
            tampered := candidate.WithSeal(tamperedHeader)
            index, err := chain.InsertChain(types.Blocks{tampered})
            if err == nil {
                t.Fatalf("A_QBFT_GASUSED_BREACH blocks=%d index=%d changed_gas_used_admitted=true", n, index)
            }
            after := chain.CurrentBlock()
            if after.Hash() != before.Hash() || after.Root() != before.Root() {
                t.Fatalf("A_QBFT_GASUSED_BREACH blocks=%d rejected_block_changed_canonical_state=true", n)
            }
            t.Logf("A_QBFT_GASUSED_DEFENSE blocks=%d rejected=true canonical_unchanged=true error=%v", n, err)
        })
    }
}
