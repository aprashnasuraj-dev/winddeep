package backend

import (
	"crypto/ecdsa"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
	qbftengine "github.com/electroneum/electroneum-sc/consensus/istanbul/engine"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
	"github.com/electroneum/electroneum-sc/core"
	"github.com/electroneum/electroneum-sc/core/misc"
	"github.com/electroneum/electroneum-sc/core/rawdb"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/core/vm"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/ethdb"
)

type rQBFTFixture struct {
	chain   *core.BlockChain
	backend *Backend
	db      ethdb.Database
	keys    []*ecdsa.PrivateKey
	block   *types.Block
}

func (f *rQBFTFixture) close() {
	if f.backend != nil {
		_ = f.backend.Stop()
	}
	if f.chain != nil {
		f.chain.Stop()
	}
	if f.db != nil {
		_ = f.db.Close()
	}
}

func rQBFTFixtureNew(t *testing.T, n int) *rQBFTFixture {
	t.Helper()
	genesis, keys := testutils.GenesisAndKeys(n)
	cfg := *istanbul.DefaultConfig
	db := rawdb.NewMemoryDatabase()
	be := New(cfg, keys[0], db)
	genesis.MustCommit(db)
	chain, err := core.NewBlockChain(db, nil, genesis.Config, be, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("R_QBFT_CHAIN_CREATE_FAIL n=%d err=%v", n, err)
	}
	if err := be.Start(chain, chain.CurrentBlock, rawdb.HasBadBlock); err != nil {
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_BACKEND_START_FAIL n=%d err=%v", n, err)
	}
	snap, err := be.snapshot(chain, 0, common.Hash{}, nil)
	if err != nil || snap == nil {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_SNAPSHOT_FAIL n=%d err=%v", n, err)
	}
	proposer := snap.ValSet.GetProposer().Address()
	found := false
	for _, key := range keys {
		if crypto.PubkeyToAddress(key.PublicKey) == proposer {
			be.privateKey = key
			be.address = proposer
			found = true
			break
		}
	}
	if !found {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_PROPOSER_KEY_NOT_FOUND n=%d proposer=%s", n, proposer)
	}
	parent := chain.Genesis()
	number := new(big.Int).Add(parent.Number(), common.Big1)
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     number,
		GasLimit:   core.CalcGasLimit(parent.GasLimit(), parent.GasLimit()),
		GasUsed:    0,
		Time:       parent.Time() + be.config.GetConfig(number).BlockPeriod,
		Difficulty: istanbulcommon.DefaultDifficulty,
	}
	if chain.Config().IsLondon(number) {
		header.BaseFee = misc.CalcBaseFee(chain.Config(), parent.Header())
	}
	if err := be.Prepare(chain, header); err != nil {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_PREPARE_FAIL n=%d err=%v", n, err)
	}
	state, err := chain.StateAt(parent.Root())
	if err != nil {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_STATE_FAIL n=%d err=%v", n, err)
	}
	block, err := be.FinalizeAndAssemble(chain, header, state, nil, nil, nil)
	if err != nil {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_ASSEMBLE_FAIL n=%d err=%v", n, err)
	}
	snap, err = be.snapshot(chain, 0, common.Hash{}, nil)
	if err != nil {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_SEAL_SNAPSHOT_FAIL n=%d err=%v", n, err)
	}
	block, err = be.EngineForBlockNumber(block.Number()).Seal(chain, block, snap.ValSet)
	if err != nil {
		be.Stop()
		chain.Stop()
		_ = db.Close()
		t.Fatalf("R_QBFT_PROPOSER_SEAL_FAIL n=%d err=%v", n, err)
	}
	return &rQBFTFixture{chain: chain, backend: be, db: db, keys: keys, block: block}
}

func rQBFTSeals(t *testing.T, header *types.Header, keys []*ecdsa.PrivateKey, indexes []int) [][]byte {
	t.Helper()
	msg := qbftengine.PrepareCommittedSeal(header, 0)
	seals := make([][]byte, 0, len(indexes))
	for _, idx := range indexes {
		if idx < 0 || idx >= len(keys) {
			t.Fatalf("R_QBFT_BAD_KEY_INDEX idx=%d keys=%d", idx, len(keys))
		}
		sig, err := crypto.Sign(msg, keys[idx])
		if err != nil {
			t.Fatalf("R_QBFT_SIGN_FAIL idx=%d err=%v", idx, err)
		}
		seals = append(seals, sig)
	}
	return seals
}

func rQBFTApplySeals(t *testing.T, f *rQBFTFixture, seals [][]byte) *types.Block {
	t.Helper()
	h := f.block.Header()
	if err := f.backend.EngineForBlockNumber(h.Number).CommitHeader(h, seals, big.NewInt(0)); err != nil {
		t.Fatalf("R_QBFT_COMMIT_HEADER_FAIL seals=%d err=%v", len(seals), err)
	}
	return f.block.WithSeal(h)
}

func rIndexes(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func TestRQBFTQuorumGate(t *testing.T) {
	for _, n := range []int{1, 4, 7} {
		n := n
		t.Run(fmt.Sprintf("exact_quorum_n%d", n), func(t *testing.T) {
			f := rQBFTFixtureNew(t, n)
			defer f.close()
			required := int(math.Ceil(float64(2*n) / 3))
			final := rQBFTApplySeals(t, f, rQBFTSeals(t, f.block.Header(), f.keys, rIndexes(required)))
			if err := f.backend.VerifyHeader(f.chain, final.Header(), false); err != nil {
				t.Fatalf("R_QBFT_EXACT_QUORUM_VERIFY_FAIL n=%d required=%d err=%v", n, required, err)
			}
			if i, err := f.chain.InsertChain(types.Blocks{final}); err != nil {
				t.Fatalf("R_QBFT_EXACT_QUORUM_IMPORT_FAIL n=%d required=%d index=%d err=%v", n, required, i, err)
			}
			if f.chain.CurrentBlock().Hash() != final.Hash() {
				t.Fatalf("R_QBFT_EXACT_QUORUM_HEAD_MISMATCH n=%d", n)
			}
			t.Logf("R_QBFT_QUORUM_IMPORT_PASS validators=%d required=%d", n, required)
		})
	}

	for _, n := range []int{4, 7} {
		n := n
		t.Run(fmt.Sprintf("subquorum_n%d", n), func(t *testing.T) {
			f := rQBFTFixtureNew(t, n)
			defer f.close()
			required := int(math.Ceil(float64(2*n) / 3))
			final := rQBFTApplySeals(t, f, rQBFTSeals(t, f.block.Header(), f.keys, rIndexes(required-1)))
			if err := f.backend.VerifyHeader(f.chain, final.Header(), false); err == nil {
				t.Fatalf("R_QBFT_SUBQUORUM_UNEXPECTED_ACCEPT n=%d seals=%d required=%d", n, required-1, required)
			}
			if i, err := f.chain.InsertChain(types.Blocks{final}); err == nil {
				t.Fatalf("R_QBFT_SUBQUORUM_IMPORT_UNEXPECTED_ACCEPT n=%d index=%d", n, i)
			}
			t.Logf("R_QBFT_SUBQUORUM_REJECTED validators=%d seals=%d required=%d", n, required-1, required)
		})
	}

	t.Run("duplicate_quorum_shape_rejected", func(t *testing.T) {
		const n = 4
		f := rQBFTFixtureNew(t, n)
		defer f.close()
		required := int(math.Ceil(float64(2*n) / 3))
		indexes := make([]int, required)
		for i := range indexes {
			indexes[i] = 0
		}
		final := rQBFTApplySeals(t, f, rQBFTSeals(t, f.block.Header(), f.keys, indexes))
		if err := f.backend.VerifyHeader(f.chain, final.Header(), false); err == nil {
			t.Fatal("R_QBFT_DUPLICATE_SEALS_UNEXPECTED_ACCEPT")
		}
		t.Logf("R_QBFT_DUPLICATE_SEALS_REJECTED validators=%d supplied=%d", n, required)
	})

	t.Run("outsider_plus_subquorum_rejected", func(t *testing.T) {
		const n = 4
		f := rQBFTFixtureNew(t, n)
		defer f.close()
		required := int(math.Ceil(float64(2*n) / 3))
		outsider, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys := append(append([]*ecdsa.PrivateKey{}, f.keys...), outsider)
		indexes := []int{0, 1, len(keys) - 1}
		if len(indexes) != required {
			t.Fatalf("R_QBFT_TEST_SETUP_QUORUM_MISMATCH have=%d required=%d", len(indexes), required)
		}
		final := rQBFTApplySeals(t, f, rQBFTSeals(t, f.block.Header(), keys, indexes))
		if err := f.backend.VerifyHeader(f.chain, final.Header(), false); err == nil {
			t.Fatal("R_QBFT_OUTSIDER_UNEXPECTED_ACCEPT")
		}
		t.Logf("R_QBFT_OUTSIDER_REJECTED validators=%d supplied=%d valid_members=%d", n, required, required-1)
	})

	t.Log("R_QBFT_QUORUM_MATRIX_PASS")
}
