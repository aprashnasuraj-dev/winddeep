// Worker D: typed receipt persistence/reopen consistency oracle.
// Copied into core/rawdb on the certified scratch tree by Class D CI.
// Uses a temporary LevelDB only; no public chain or network activity.
package rawdb

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/params"
	"github.com/electroneum/electroneum-sc/rlp"
	"github.com/electroneum/electroneum-sc/trie"
)

func workerDPersistManualReceiptRoot(t *testing.T, receipts types.Receipts) common.Hash {
	t.Helper()
	st := trie.NewStackTrie(nil)
	update := func(i int) {
		key := rlp.AppendUint64(nil, uint64(i))
		value, err := receipts[i].MarshalBinary()
		if err != nil {
			t.Fatalf("marshal receipt %d: %v", i, err)
		}
		st.Update(key, value)
	}
	for i := 1; i < len(receipts) && i <= 0x7f; i++ {
		update(i)
	}
	if len(receipts) > 0 {
		update(0)
	}
	for i := 0x80; i < len(receipts); i++ {
		update(i)
	}
	return st.Hash()
}

func workerDPersistFixture(t *testing.T) (types.Transactions, types.Receipts) {
	t.Helper()
	to := common.Address{0x77, 0x44}
	txs := make(types.Transactions, 130)
	receipts := make(types.Receipts, 130)
	for i := 0; i < 130; i++ {
		chainID := big.NewInt(1)
		switch i % 3 {
		case 0:
			txs[i] = types.NewTx(&types.LegacyTx{
				Nonce: uint64(i), GasPrice: big.NewInt(1), Gas: 50000,
				To: &to, Value: big.NewInt(0), Data: []byte{byte(i)},
			})
		case 1:
			txs[i] = types.NewTx(&types.AccessListTx{
				ChainID: chainID, Nonce: uint64(i), GasPrice: big.NewInt(1), Gas: 50000,
				To: &to, Value: big.NewInt(0), Data: []byte{byte(i)},
			})
		case 2:
			txs[i] = types.NewTx(&types.DynamicFeeTx{
				ChainID: chainID, Nonce: uint64(i), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 50000,
				To: &to, Value: big.NewInt(0), Data: []byte{byte(i)},
			})
		}
		r := &types.Receipt{
			Type:              txs[i].Type(),
			Status:            uint64(i % 2),
			CumulativeGasUsed: uint64(21000 * (i + 1)),
		}
		if i%13 == 0 {
			r.Logs = []*types.Log{{
				Address: common.Address{byte(i), 0x91},
				Topics:  []common.Hash{{0x55, byte(i)}},
				Data:    []byte{byte(i), 0xde, 0xad},
			}}
		}
		r.Bloom = types.CreateBloom(types.Receipts{r})
		receipts[i] = r
	}
	return txs, receipts
}

func workerDAssertReceiptConsensusEqual(t *testing.T, want, got types.Receipts) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("receipt count got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		wb, err := want[i].MarshalBinary()
		if err != nil {
			t.Fatalf("want marshal %d: %v", i, err)
		}
		gb, err := got[i].MarshalBinary()
		if err != nil {
			t.Fatalf("got marshal %d: %v", i, err)
		}
		if !bytes.Equal(wb, gb) {
			t.Fatalf("receipt consensus encoding changed at %d: want=%x got=%x", i, wb, gb)
		}
	}
}

func TestWorkerDTypedReceiptPersistenceRestart(t *testing.T) {
	txs, receipts := workerDPersistFixture(t)
	oracle := workerDPersistManualReceiptRoot(t, receipts)
	derived := types.DeriveSha(receipts, trie.NewStackTrie(nil))
	if oracle != derived {
		t.Fatalf("pre-persistence independent root mismatch: oracle=%x derive=%x", oracle, derived)
	}

	// Oracle sensitivity at the DeriveSha index-order transition.
	reordered := append(types.Receipts(nil), receipts...)
	reordered[127], reordered[128] = reordered[128], reordered[127]
	if got := workerDPersistManualReceiptRoot(t, reordered); got == oracle {
		t.Fatalf("127/128 reorder did not change independent root: %x", got)
	}
	mutated := make(types.Receipts, len(receipts))
	for i, r := range receipts {
		c := *r
		mutated[i] = &c
	}
	m := *mutated[128]
	m.Status ^= 1
	mutated[128] = &m
	if got := workerDPersistManualReceiptRoot(t, mutated); got == oracle {
		t.Fatalf("status mutation did not change independent root: %x", got)
	}

	dir := t.TempDir()
	db, err := NewLevelDBDatabase(dir, 16, 16, "", false)
	if err != nil {
		t.Fatalf("open persistent database: %v", err)
	}
	hash := common.HexToHash("0xd00d00000000000000000000000000000000000000000000000000000000beef")
	number := uint64(256)
	WriteBody(db, hash, number, &types.Body{Transactions: txs})
	WriteReceipts(db, hash, number, receipts)

	beforeBlob := append([]byte(nil), ReadReceiptsRLP(db, hash, number)...)
	before := ReadReceipts(db, hash, number, params.TestChainConfig)
	if before == nil {
		t.Fatal("ReadReceipts before restart returned nil")
	}
	workerDAssertReceiptConsensusEqual(t, receipts, before)
	if got := workerDPersistManualReceiptRoot(t, before); got != oracle {
		t.Fatalf("before-restart root=%x want=%x", got, oracle)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close persistent database: %v", err)
	}

	reopened, err := NewLevelDBDatabase(dir, 16, 16, "", false)
	if err != nil {
		t.Fatalf("reopen persistent database: %v", err)
	}
	defer reopened.Close()
	afterBlob := ReadReceiptsRLP(reopened, hash, number)
	if !bytes.Equal(beforeBlob, afterBlob) {
		t.Fatalf("stored receipt RLP changed across reopen")
	}
	after := ReadReceipts(reopened, hash, number, params.TestChainConfig)
	if after == nil {
		t.Fatal("ReadReceipts after restart returned nil")
	}
	workerDAssertReceiptConsensusEqual(t, receipts, after)
	afterOracle := workerDPersistManualReceiptRoot(t, after)
	afterDerived := types.DeriveSha(after, trie.NewStackTrie(nil))
	if afterOracle != oracle || afterDerived != oracle {
		t.Fatalf("post-restart commitment mismatch: oracle=%x derived=%x want=%x", afterOracle, afterDerived, oracle)
	}
	t.Logf("WORKER_D_TYPED_PERSISTENCE_RESTART_PASS root=%x receipts=%d storage_bytes=%d", oracle, len(after), len(afterBlob))
}
