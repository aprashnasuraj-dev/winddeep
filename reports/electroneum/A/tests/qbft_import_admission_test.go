package backend

import (
    "testing"

    "github.com/electroneum/electroneum-sc/core/types"
)

// TestWorkerAQBFTImportAdmission tests actual InsertChain admission, including
// a negative proposer-identity control. This is NOT a value exploit test.
func TestWorkerAQBFTImportAdmission(t *testing.T) {
    for _, n := range []int{1, 2, 3} {
        t.Run(string(rune('0'+n)), func(t *testing.T) {
            chain, engine := newBlockChain(1)
            defer engine.Stop()
            parent := chain.Genesis()
            for i := 0; i < n; i++ {
                block := makeBlock(chain, engine, parent)
                if block == nil { t.Fatal("nil QBFT block") }
                if index, err := chain.InsertChain(types.Blocks{block}); err != nil {
                    t.Fatalf("QBFT import height=%d index=%d: %v", i+1, index, err)
                }
                if chain.CurrentBlock().Hash() != block.Hash() {
                    t.Fatalf("canonical head mismatch at %d", i+1)
                }
                parent = block
            }
            st, err := chain.State()
            if err != nil || st == nil { t.Fatalf("canonical state unavailable: %v", err) }
            t.Logf("A_QBFT_IMPORT_BASELINE blocks=%d head=%s state_root=%s", n, parent.Hash(), parent.Root())

            // Adversarial control: change the claimed proposer after sealing.
            // An unprivileged actor must not be able to insert this as canonical.
            candidate := makeBlock(chain, engine, parent)
            if candidate == nil { t.Fatal("nil candidate") }
            forgedHeader := types.CopyHeader(candidate.Header())
            forgedHeader.Coinbase = getInvalidAddress()
            forged := candidate.WithSeal(forgedHeader)
            before := chain.CurrentBlock()
            index, importErr := chain.InsertChain(types.Blocks{forged})
            if importErr == nil {
                t.Fatalf("A_QBFT_IMPORT_BREACH forged proposer admitted at index=%d height=%d", index, n+1)
            }
            after := chain.CurrentBlock()
            if after.Hash() != before.Hash() || after.Root() != before.Root() {
                t.Fatalf("A_QBFT_IMPORT_BREACH failed import changed canonical state height=%d", n)
            }
            t.Logf("A_QBFT_IMPORT_DEFENSE blocks=%d rejected_forged_coinbase=true canonical_unchanged=true err=%v", n, importErr)
        })
    }
}
