// Worker D synthetic commitment regression copied to scratch certified source.
// Exercises real Electroneum trie derivation, not network import or finality.
package core

import (
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/trie"
)

func TestWorkerDHistoricalCommitments(t *testing.T) {
    recipient := common.HexToAddress("0x00000000000000000000000000000000000000d1")
    base := types.NewTransaction(2,recipient,big.NewInt(10),21000,big.NewInt(1),nil)
    amountChanged := types.NewTransaction(2,recipient,big.NewInt(11),21000,big.NewInt(1),nil)
    nonceChanged := types.NewTransaction(3,recipient,big.NewInt(10),21000,big.NewInt(1),nil)
    goodTxRoot := types.DeriveSha(types.Transactions{base},trie.NewStackTrie(nil))
    for _, tc := range []struct{name string; tx *types.Transaction}{
        {"amount", amountChanged}, {"nonce",nonceChanged},
    }{
        t.Run(tc.name,func(t *testing.T){
            newRoot := types.DeriveSha(types.Transactions{tc.tx},trie.NewStackTrie(nil))
            if newRoot == goodTxRoot{
                t.Fatalf("changed %s did not alter transaction trie commitment",tc.name)
            }
            t.Log("WORKER_D_MUTATED_TX_COMMITMENT_DIFFERENT")
        })
    }
    makeReceipt:=func(status uint64, gas uint64) types.Receipts {
        return types.Receipts{&types.Receipt{Type:types.LegacyTxType,Status:status,CumulativeGasUsed:gas}}
    }
    goodReceipts:=makeReceipt(types.ReceiptStatusSuccessful,21000)
    goodReceiptRoot:=types.DeriveSha(goodReceipts,trie.NewStackTrie(nil))
    for _, tc:=range []struct{name string; receipts types.Receipts}{
        {"failed_status",makeReceipt(types.ReceiptStatusFailed,21000)},
        {"different_gas",makeReceipt(types.ReceiptStatusSuccessful,20000)},
    }{
        t.Run(tc.name,func(t *testing.T){
            newRoot:=types.DeriveSha(tc.receipts,trie.NewStackTrie(nil))
            if newRoot==goodReceiptRoot{
                t.Fatalf("changed %s did not alter receipt trie commitment",tc.name)
            }
            t.Log("WORKER_D_MUTATED_RECEIPT_COMMITMENT_DIFFERENT")
        })
    }
    if types.DeriveSha(types.Transactions{base},trie.NewStackTrie(nil))!=goodTxRoot{
        t.Fatal("unchanged transaction root unstable")
    }
    if types.DeriveSha(goodReceipts,trie.NewStackTrie(nil))!=goodReceiptRoot{
        t.Fatal("unchanged receipt root unstable")
    }
    t.Log("WORKER_D_HONEST_CONTROLS_PASS")
}
