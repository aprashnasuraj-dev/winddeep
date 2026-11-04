package eth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	electroneum "github.com/electroneum/electroneum-sc"
	"github.com/electroneum/electroneum-sc/accounts/abi/bind"
	"github.com/electroneum/electroneum-sc/ethclient"
	"github.com/electroneum/electroneum-sc/internal/ethapi"
	"github.com/electroneum/electroneum-sc/rpc"
)

func TestRWaitMinedStaleReceiptImpact(t *testing.T) {
	f := rNewFullFixture(t, 4)
	defer f.Close()

	var once sync.Once
	wrapped := &rDelayedFullBackend{
		Backend: f.backend,
		beforeReceipts: func() {
			once.Do(func() {
				if i, err := f.chain.InsertChain(f.fork); err != nil {
					t.Fatalf("R_WAITMINED_REORG_IMPORT_FAIL index=%d err=%v", i, err)
				}
			})
		},
	}
	txAPI := ethapi.NewPublicTransactionPoolAPI(wrapped, new(ethapi.AddrLocker))
	chainAPI := ethapi.NewPublicBlockChainAPI(wrapped)

	server := rpc.NewServer()
	if err := server.RegisterName("eth", txAPI); err != nil {
		t.Fatalf("R_WAITMINED_REGISTER_TX_API_FAIL: %v", err)
	}
	if err := server.RegisterName("eth", chainAPI); err != nil {
		t.Fatalf("R_WAITMINED_REGISTER_CHAIN_API_FAIL: %v", err)
	}
	defer server.Stop()

	rpcClient := rpc.DialInProc(server)
	client := ethclient.NewClient(rpcClient)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	receipt, err := bind.WaitMined(ctx, client, f.oldTx)
	if err != nil {
		t.Fatalf("R_WAITMINED_CALL_FAIL: %v", err)
	}
	if receipt == nil {
		t.Fatal("R_WAITMINED_NIL_RECEIPT")
	}
	if receipt.TxHash != f.oldTx.Hash() {
		t.Fatalf("R_WAITMINED_TXHASH_MISMATCH got=%s want=%s", receipt.TxHash, f.oldTx.Hash())
	}
	if receipt.BlockHash != f.oldBlock.Hash() {
		t.Fatalf("R_WAITMINED_EXPECTED_OLD_BLOCK_RECEIPT got=%s want=%s", receipt.BlockHash, f.oldBlock.Hash())
	}
	if f.chain.GetCanonicalHash(f.oldBlock.NumberU64()) == f.oldBlock.Hash() {
		t.Fatal("R_WAITMINED_REORG_NOT_APPLIED")
	}
	t.Logf("R_WAITMINED_STALE_MINED_SIGNAL old_block=%s canonical_now=%s block_number=%d",
		receipt.BlockHash,
		f.chain.GetCanonicalHash(f.oldBlock.NumberU64()),
		receipt.BlockNumber.Uint64(),
	)

	// Shipped-client counterexample: the same ethclient can immediately ask for
	// the canonical header at the returned receipt height. The hashes disagree,
	// so a consumer that performs this check rejects the WaitMined result.
	header, err := client.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil {
		t.Fatalf("R_WAITMINED_CANONICAL_HEADER_QUERY_FAIL: %v", err)
	}
	if header == nil {
		t.Fatal("R_WAITMINED_CANONICAL_HEADER_NIL")
	}
	if header.Hash() == receipt.BlockHash {
		t.Fatal("R_WAITMINED_CANONICAL_RECHECK_FALSE_NEGATIVE")
	}
	t.Logf("R_WAITMINED_CANONICAL_RECHECK_REJECTS_PASS receipt_block=%s canonical_block=%s",
		receipt.BlockHash, header.Hash())

	// Once the reorg is fully visible, the shipped receipt client correctly
	// reports NotFound. The integrity issue is the stale success returned across
	// the lookup/read TOCTOU window, not a permanently orphaned receipt.
	after, err := client.TransactionReceipt(ctx, f.oldTx.Hash())
	if !errors.Is(err, electroneum.NotFound) || after != nil {
		t.Fatalf("R_WAITMINED_POST_REORG_NOTFOUND_CONTROL_FAIL receipt=%v err=%v", after, err)
	}
	t.Log("R_WAITMINED_POST_REORG_NOTFOUND_CONTROL_PASS")
	t.Log("R_WAITMINED_G7_CLIENT_INTEGRITY_IMPACT_PASS")
}
