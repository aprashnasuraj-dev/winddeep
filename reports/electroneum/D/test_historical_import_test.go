// Worker D: real certified-source full-import admission / canonical-state regression.
// Copied into a scratch copy of the immutable certified target; never mutate vendor.
package core

import (
    "strings"
    "testing"

    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/params"
)

// These cases test the actual InsertChain -> ValidateBody/ValidateState -> canonical
// persistence path. FakePow intentionally isolates commitment checks; this is NOT
// a QBFT finality or a production snapshot-download admission proof.
func TestWorkerDHistoricalImportAdmission(t *testing.T) {
    cases := []struct {
        name string
        mutate func(*types.Header)
        expected string
    }{
        {name: "honest_control"},
        {name: "bad_transaction_root", expected: "transaction root hash mismatch",
            mutate: func(h *types.Header) { h.TxHash[0] ^= 0x01 }},
        {name: "bad_receipt_root", expected: "invalid receipt root hash",
            mutate: func(h *types.Header) { h.ReceiptHash[0] ^= 0x01 }},
        {name: "bad_state_root", expected: "invalid merkle root",
            mutate: func(h *types.Header) { h.Root[0] ^= 0x01 }},
        {name: "bad_receipt_bloom", expected: "invalid bloom",
            mutate: func(h *types.Header) { h.Bloom[0] ^= 0x01 }},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            engine := ethash.NewFaker()
            db, bc, err := newCanonical(engine, 0, true)
            if err != nil { t.Fatalf("fixture genesis: %v", err) }
            blocks := makeBlockChain(bc.CurrentBlock(), 3, engine, db, canonicalSeed)
            if _, err = bc.InsertChain(blocks[:2]); err != nil {
                bc.Stop()
                t.Fatalf("honest ancestor import: %v", err)
            }
            previous := blocks[1].Hash()
            if bc.CurrentBlock().Hash() != previous || bc.GetCanonicalHash(2) != previous {
                bc.Stop()
                t.Fatal("honest ancestor control not canonical")
            }
            header := blocks[2].Header()
            if tc.mutate != nil { tc.mutate(header) }
            candidate := types.NewBlockWithHeader(header).WithBody(blocks[2].Transactions(), blocks[2].Uncles())
            index, admissionErr := bc.InsertChain(types.Blocks{candidate})
            expected := previous
            if tc.mutate == nil {
                if admissionErr != nil {
                    bc.Stop()
                    t.Fatalf("honest block rejected at index=%d: %v", index, admissionErr)
                }
                expected = candidate.Hash()
                if bc.GetCanonicalHash(3) != expected {
                    bc.Stop()
                    t.Fatal("honest block accepted without canonical commitment")
                }
                t.Logf("WORKER_D_FULL_IMPORT_HONEST_ACCEPTED height=3 hash=%s", expected)
            } else {
                if admissionErr == nil {
                    bc.Stop()
                    t.Fatalf("WORKER_D_MUTATION_ACCEPTED: %s corrupt commitment admitted at index=%d", tc.name, index)
                }
                if !strings.Contains(admissionErr.Error(), tc.expected) {
                    bc.Stop()
                    t.Fatalf("wrong rejection boundary for %s: %v (expected %q)", tc.name, admissionErr, tc.expected)
                }
                if bc.GetCanonicalHash(3) == candidate.Hash() {
                    bc.Stop()
                    t.Fatalf("invalid block made canonical: %s", tc.name)
                }
                t.Logf("WORKER_D_FULL_IMPORT_REJECTED mutation=%s index=%d error=%v", tc.name, index, admissionErr)
            }
            if got := bc.CurrentBlock().Hash(); got != expected {
                bc.Stop()
                t.Fatalf("incorrect live canonical head: got=%s expected=%s", got, expected)
            }
            bc.Stop()
            reopened, reopenErr := NewBlockChain(db, nil, params.AllEthashProtocolChanges,
                ethash.NewFaker(), vm.Config{}, nil, nil)
            if reopenErr != nil { t.Fatalf("restart failed: %v", reopenErr) }
            defer reopened.Stop()
            if got := reopened.CurrentBlock().Hash(); got != expected {
                t.Fatalf("WORKER_D_RESTART_CANONICALITY_BREACH mutation=%s got=%s want=%s", tc.name, got, expected)
            }
            if tc.mutate != nil && reopened.GetCanonicalHash(3) == candidate.Hash() {
                t.Fatalf("WORKER_D_RESTART_BAD_HISTORY_CANONICAL mutation=%s", tc.name)
            }
            if tc.mutate == nil && reopened.GetCanonicalHash(3) != candidate.Hash() {
                t.Fatal("honest canonical block disappeared on restart")
            }
            t.Logf("WORKER_D_RESTART_CANONICALITY_OK case=%s", tc.name)
        })
    }
}

// Semantic fuzzing: all generated inputs have a valid canonical parent and a
// single intentionally corrupted commitment. Unlike prior sensitivity fuzzing,
// each iteration must reach the real InsertChain validator and not change HEAD.
func FuzzWorkerDImportAdmission(f *testing.F) {
    for field := uint8(0); field < 4; field++ {
        f.Add(field, uint8(1))
        f.Add(field, uint8(0xff))
    }
    f.Fuzz(func(t *testing.T, field, delta uint8) {
        engine := ethash.NewFaker()
        db, bc, err := newCanonical(engine, 0, true)
        if err != nil { t.Fatalf("genesis fixture: %v", err) }
        defer bc.Stop()
        blocks := makeBlockChain(bc.CurrentBlock(), 2, engine, db, canonicalSeed)
        if _, err := bc.InsertChain(types.Blocks{blocks[0]}); err != nil {
            t.Fatalf("honest parent import: %v", err)
        }
        baseline := blocks[0].Hash()
        header := blocks[1].Header()
        mask := delta | 1
        var expected string
        switch field % 4 {
        case 0:
            header.TxHash[0] ^= mask
            expected = "transaction root hash mismatch"
        case 1:
            header.ReceiptHash[0] ^= mask
            expected = "invalid receipt root hash"
        case 2:
            header.Root[0] ^= mask
            expected = "invalid merkle root"
        default:
            header.Bloom[0] ^= mask
            expected = "invalid bloom"
        }
        candidate := types.NewBlockWithHeader(header).WithBody(blocks[1].Transactions(), blocks[1].Uncles())
        _, err = bc.InsertChain(types.Blocks{candidate})
        if err == nil || !strings.Contains(err.Error(), expected) {
            t.Fatalf("commitment admission failure: field=%d delta=%d err=%v expected=%s", field%4, delta, err, expected)
        }
        if bc.CurrentBlock().Hash() != baseline || bc.GetCanonicalHash(2) == candidate.Hash() ||
            rawdb.ReadCanonicalHash(db, 2) == candidate.Hash() {
            t.Fatalf("bad block changed canonical history: field=%d delta=%d", field%4, delta)
        }
    })
}
