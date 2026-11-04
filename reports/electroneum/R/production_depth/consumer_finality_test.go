package eth

import (
	"context"
	"errors"
	"testing"
	"time"

	electroneum "github.com/electroneum/electroneum-sc"
	"github.com/electroneum/electroneum-sc/accounts/abi/bind"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/ethclient"
	"github.com/electroneum/electroneum-sc/internal/ethapi"
	"github.com/electroneum/electroneum-sc/rpc"
)

func TestRP1IConsumerDecisionMatrix(t *testing.T) {
	const requiredConfirmations uint64 = 4

	f := rNewFullFixture(t, 4)
	defer f.Close()

	var injected bool
	wrapped := &rDelayedFullBackend{
		Backend: f.backend,
		beforeReceipts: func() {
			if injected {
				return
			}
			injected = true
			if i, err := f.chain.InsertChain(f.fork); err != nil {
				t.Fatalf("R_P1I_REORG_IMPORT_FAIL index=%d err=%v", i, err)
			}
		},
	}
	txAPI := ethapi.NewPublicTransactionPoolAPI(wrapped, new(ethapi.AddrLocker))
	chainAPI := ethapi.NewPublicBlockChainAPI(wrapped)

	server := rpc.NewServer()
	if err := server.RegisterName("eth", txAPI); err != nil {
		t.Fatalf("R_P1I_REGISTER_TX_API_FAIL: %v", err)
	}
	if err := server.RegisterName("eth", chainAPI); err != nil {
		t.Fatalf("R_P1I_REGISTER_CHAIN_API_FAIL: %v", err)
	}
	defer server.Stop()

	client := ethclient.NewClient(rpc.DialInProc(server))
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	receipt, err := bind.WaitMined(ctx, client, f.oldTx)
	if err != nil {
		t.Fatalf("R_P1I_WAITMINED_FAIL: %v", err)
	}
	if receipt == nil || receipt.BlockNumber == nil {
		t.Fatal("R_P1I_WAITMINED_RECEIPT_MISSING")
	}
	if receipt.TxHash != f.oldTx.Hash() || receipt.BlockHash != f.oldBlock.Hash() {
		t.Fatalf("R_P1I_WAITMINED_RECEIPT_IDENTITY_FAIL tx=%s block=%s", receipt.TxHash, receipt.BlockHash)
	}
	if receipt.Status != 1 {
		t.Fatalf("R_P1I_WAITMINED_STATUS_NOT_SUCCESS status=%d", receipt.Status)
	}
	if got := f.chain.GetCanonicalHash(receipt.BlockNumber.Uint64()); got == receipt.BlockHash {
		t.Fatalf("R_P1I_REORG_NOT_VISIBLE receipt_block=%s canonical=%s", receipt.BlockHash, got)
	}

	latest, err := client.HeaderByNumber(ctx, nil)
	if err != nil || latest == nil {
		t.Fatalf("R_P1I_LATEST_HEADER_FAIL header=%v err=%v", latest, err)
	}
	if latest.Number.Uint64() < receipt.BlockNumber.Uint64() {
		t.Fatalf("R_P1I_NEGATIVE_CONFIRMATION_WINDOW latest=%d receipt=%d", latest.Number.Uint64(), receipt.BlockNumber.Uint64())
	}
	confirmations := latest.Number.Uint64() - receipt.BlockNumber.Uint64() + 1

	minedCredit := receipt.Status == 1
	if !minedCredit {
		t.Fatal("R_P1I_MINED_POLICY_DID_NOT_CREDIT")
	}
	t.Logf("R_P1I_MINED_POLICY_FALSE_CREDIT_REPRODUCED receipt_block=%s canonical_now=%s",
		receipt.BlockHash, f.chain.GetCanonicalHash(receipt.BlockNumber.Uint64()))

	naiveNConfirmCredit := minedCredit && confirmations >= requiredConfirmations
	if !naiveNConfirmCredit {
		t.Fatalf("R_P1I_NAIVE_NCONF_PRECONDITION_FAIL confirmations=%d required=%d", confirmations, requiredConfirmations)
	}
	t.Logf("R_P1I_NAIVE_NCONF_FALSE_CREDIT_REPRODUCED n=%d confirmations=%d receipt_block=%s",
		requiredConfirmations, confirmations, receipt.BlockHash)

	canonicalHeader, err := client.HeaderByNumber(ctx, receipt.BlockNumber)
	if err != nil || canonicalHeader == nil {
		t.Fatalf("R_P1I_CANONICAL_HEADER_FAIL header=%v err=%v", canonicalHeader, err)
	}
	canonicalAwareCredit := naiveNConfirmCredit && canonicalHeader.Hash() == receipt.BlockHash
	if canonicalAwareCredit {
		t.Fatalf("R_P1I_CANONICAL_NCONF_FALSE_ACCEPT receipt=%s canonical=%s", receipt.BlockHash, canonicalHeader.Hash())
	}
	t.Logf("R_P1I_CANONICAL_NCONF_REJECTS_STALE_PASS receipt=%s canonical=%s confirmations=%d",
		receipt.BlockHash, canonicalHeader.Hash(), confirmations)

	after, err := client.TransactionReceipt(ctx, f.oldTx.Hash())
	if !errors.Is(err, electroneum.NotFound) || after != nil {
		t.Fatalf("R_P1I_POST_REORG_NOTFOUND_CONTROL_FAIL receipt=%v err=%v", after, err)
	}
	t.Log("R_P1I_POST_REORG_NOTFOUND_CONTROL_PASS")
	t.Log("R_P1I_SYNTHETIC_CONSUMER_ONLY_NO_REAL_EXCHANGE_CLAIM")
}

func TestRP1IQBFTFinalizedTagVisibility(t *testing.T) {
	f, senderKey := rP1HBaseFixture(t)
	defer f.close()

	tx := rP1HSignedTx(t, f.localChain, senderKey, 0x93)
	block := rQBFTBuildAndImport(t, f.localChain, f.localQBFT, f.localDB, f.validatorKeys, f.validators, tx)
	if f.localChain.CurrentBlock().Hash() != block.Hash() {
		t.Fatalf("R_P1I_QBFT_COMMITTED_HEAD_FAIL got=%s want=%s", f.localChain.CurrentBlock().Hash(), block.Hash())
	}
	extra, err := types.ExtractQBFTExtra(block.Header())
	if err != nil {
		t.Fatalf("R_P1I_QBFT_EXTRA_FAIL: %v", err)
	}
	if len(extra.CommittedSeal) != 3 {
		t.Fatalf("R_P1I_QBFT_COMMITTED_SEAL_COUNT_FAIL got=%d want=3", len(extra.CommittedSeal))
	}
	t.Logf("R_P1I_QBFT_COMMITTED_BLOCK_CONTROL_PASS validators=4 seals=3 number=%d hash=%s", block.NumberU64(), block.Hash())

	if finalized := f.localChain.CurrentFinalizedBlock(); finalized != nil {
		t.Fatalf("R_P1I_QBFT_UNEXPECTED_GENERIC_FINALIZED_BLOCK number=%d hash=%s", finalized.NumberU64(), finalized.Hash())
	}

	svc := &Ethereum{blockchain: f.localChain, chainDb: f.localDB}
	backend := &EthAPIBackend{eth: svc}
	finalizedBlock, err := backend.BlockByNumber(context.Background(), rpc.FinalizedBlockNumber)
	if err != nil {
		t.Fatalf("R_P1I_FINALIZED_BLOCK_QUERY_ERROR: %v", err)
	}
	if finalizedBlock != nil {
		t.Fatalf("R_P1I_FINALIZED_BLOCK_QUERY_UNEXPECTED_VALUE number=%d hash=%s", finalizedBlock.NumberU64(), finalizedBlock.Hash())
	}

	chainAPI := ethapi.NewPublicBlockChainAPI(backend)
	rpcBlock, err := chainAPI.GetBlockByNumber(context.Background(), rpc.FinalizedBlockNumber, false)
	if err != nil {
		t.Fatalf("R_P1I_FINALIZED_RPC_QUERY_ERROR: %v", err)
	}
	if rpcBlock != nil {
		t.Fatalf("R_P1I_FINALIZED_RPC_UNEXPECTED_VALUE block=%v", rpcBlock)
	}

	t.Logf("R_P1I_QBFT_FINALIZED_TAG_UNPUBLISHED_PASS committed_number=%d committed_hash=%s", block.NumberU64(), block.Hash())
	t.Log("R_P1I_FINALIZED_POLICY_FAILS_CLOSED_WITHOUT_MARKER_PASS")
}
