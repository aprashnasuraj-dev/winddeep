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
    payloadChanged := types.NewTransaction(2,recipient,big.NewInt(10),21000,big.NewInt(1),[]byte{0x01})
    goodTxRoot := types.DeriveSha(types.Transactions{base},trie.NewStackTrie(nil))
    for _, tc := range []struct{name string; tx *types.Transaction}{
        {"amount", amountChanged}, {"nonce",nonceChanged}, {"payload",payloadChanged},
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

 
// Coverage-guided tests of real transaction/receipt commitment separation.
// This is NOT a full block-import/finality oracle.
func FuzzWorkerDCommitmentSensitivity(f *testing.F) {
    f.Add([]byte{1, 2, 3, 4})
    f.Add([]byte{255, 0, 128, 0, 1, 4})
    f.Add([]byte{0, 0, 0, 0})
    f.Fuzz(func(t *testing.T, data []byte) {
        if len(data) < 3 || len(data) > 512 { return }
        to := common.HexToAddress("0x00000000000000000000000000000000000000d1")
        value := new(big.Int).SetBytes(data[1:])
        original := types.NewTransaction(uint64(data[0]), to, value, 21000, big.NewInt(1), data[2:])
        changedPayload := append(append([]byte{}, data[2:]...), byte(0x7b))
        changed := types.NewTransaction(uint64(data[0]), to, value, 21000, big.NewInt(1), changedPayload)
        baseRoot := types.DeriveSha(types.Transactions{original}, trie.NewStackTrie(nil))
        mutationRoot := types.DeriveSha(types.Transactions{changed}, trie.NewStackTrie(nil))
        if baseRoot == mutationRoot { t.Fatal("modified transaction payload retained root") }
        if baseRoot != types.DeriveSha(types.Transactions{original}, trie.NewStackTrie(nil)) {
            t.Fatal("honest transaction root nondeterministic")
        }
        good := types.Receipts{&types.Receipt{Type: types.LegacyTxType, Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: uint64(data[1])+21000}}
        bad := types.Receipts{&types.Receipt{Type: types.LegacyTxType, Status: types.ReceiptStatusFailed, CumulativeGasUsed: uint64(data[1])+21000}}
        if types.DeriveSha(good, trie.NewStackTrie(nil)) == types.DeriveSha(bad, trie.NewStackTrie(nil)) {
            t.Fatal("receipt status mutation retained root")
        }
    })
}
