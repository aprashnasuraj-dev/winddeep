package eth

import (
	"context"
	"sync"
	"testing"

	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/internal/ethapi"
	"github.com/electroneum/electroneum-sc/rpc"
)

type rGuardResidualBackend struct {
	ethapi.Backend
	f    *rFullFixture
	once sync.Once
}

func (b *rGuardResidualBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	block, err := b.Backend.BlockByNumber(ctx, number)
	if err != nil {
		return block, err
	}
	// Reorg only after the candidate guard has captured the old canonical block,
	// but before that guard compares and returns to GetTransactionReceipt.
	b.once.Do(func() {
		if i, insertErr := b.f.chain.InsertChain(b.f.fork); insertErr != nil {
			panic(&rGuardInsertPanic{index: i, err: insertErr})
		}
	})
	return block, nil
}

type rGuardInsertPanic struct {
	index int
	err   error
}
func (p *rGuardInsertPanic) Error() string { return p.err.Error() }

func TestRCanonicalGuardResidualRace(t *testing.T) {
	f := rNewFullFixture(t, 4)
	defer f.Close()

	wrapped := &rGuardResidualBackend{Backend: f.backend, f: f}
	api := ethapi.NewPublicTransactionPoolAPI(wrapped, new(ethapi.AddrLocker))

	var receipt map[string]interface{}
	func() {
		defer func() {
			if p := recover(); p != nil {
				if gp, ok := p.(*rGuardInsertPanic); ok {
					t.Fatalf("R_GUARD_RESIDUAL_REORG_IMPORT_FAIL index=%d err=%v", gp.index, gp.err)
				}
				panic(p)
			}
		}()
		var err error
		receipt, err = api.GetTransactionReceipt(context.Background(), f.oldTx.Hash())
		if err != nil {
			t.Fatalf("R_GUARD_RESIDUAL_RPC_ERROR: %v", err)
		}
	}()

	canonical := f.chain.GetCanonicalHash(f.oldBlock.NumberU64())
	if canonical == f.oldBlock.Hash() {
		t.Fatal("R_GUARD_RESIDUAL_REORG_NOT_APPLIED")
	}
	if receipt == nil {
		t.Fatal("R_GUARD_RESIDUAL_UNEXPECTED_NIL")
	}
	got, ok := receipt["blockHash"]
	if !ok || got != f.oldBlock.Hash() {
		t.Fatalf("R_GUARD_RESIDUAL_EXPECTED_STALE_OLD_RECEIPT got=%v", got)
	}
	t.Logf("R_CANONICAL_GUARD_RESIDUAL_TOCTOU_OBSERVED old=%s canonical=%s", f.oldBlock.Hash(), canonical)
	t.Log("R_CANONICAL_GUARD_NOT_COMPLETE_FIX_PASS")
}
