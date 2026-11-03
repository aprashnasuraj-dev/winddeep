// Reverse worker R: last-to-first, counterexample-first audit of E-RPC-010.
// The test is copied only into certified Electroneum scratch under internal/ethapi.
// No real chain, key, wallet, or endpoint is used.
package ethapi

import (
    "context"
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/params"
)

type reverseEBackend struct {
    Backend
    tx *types.Transaction
    receipt *types.Receipt
    blockHash common.Hash
    header *types.Header
    config *params.ChainConfig
    noReceipts bool
    headerCalls int
}
func (b *reverseEBackend) GetTransaction(context.Context, common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
    return b.tx,b.blockHash,1,0,nil
}
func (b *reverseEBackend) GetReceipts(context.Context, common.Hash) (types.Receipts,error) {
    if b.noReceipts {return nil,nil}
    return types.Receipts{b.receipt},nil
}
func (b *reverseEBackend) HeaderByHash(context.Context,common.Hash)(*types.Header,error){
    b.headerCalls++
    return b.header,nil
}
func (b *reverseEBackend) ChainConfig()*params.ChainConfig{return b.config}

func reverseEFixture(london bool)(*PublicTransactionPoolAPI,*reverseEBackend,common.Hash){
    to:=common.HexToAddress("0x0000000000000000000000000000000000000001")
    tx:=types.NewTransaction(0,to,big.NewInt(1),21000,big.NewInt(10),nil)
    b:=&reverseEBackend{
        tx:tx,
        receipt:&types.Receipt{TxHash:tx.Hash(),GasUsed:21000,CumulativeGasUsed:21000,Status:types.ReceiptStatusSuccessful},
        blockHash:common.HexToHash("0x1111"),
        header:&types.Header{Number:big.NewInt(1),BaseFee:big.NewInt(1)},
        config:&params.ChainConfig{ChainID:big.NewInt(1337)},
    }
    if london {b.config.LondonBlock=big.NewInt(0)}
    return NewPublicTransactionPoolAPI(b,new(AddrLocker)),b,tx.Hash()
}

// This matrix runs the production eth_getTransactionReceipt adapter with the
// strongest defeating controls before checking the failure-only branch.
func TestReverseEReceiptDefenseMatrix(t *testing.T){
    t.Run("honest_london_receipt",func(t *testing.T){
        api,b,hash:=reverseEFixture(true)
        got,err:=api.GetTransactionReceipt(context.Background(),hash)
        if err!=nil||got==nil {t.Fatalf("honest receipt rejected err=%v data=%v",err,got)}
        if got["transactionHash"]!=hash || b.headerCalls!=1 {t.Fatalf("identity or header lookup mismatch: %v count=%d",got["transactionHash"],b.headerCalls)}
        t.Log("REVERSE_E_VALID_LONDON_CONTROL_PASS")
    })
    t.Run("no_receipt_short_circuits_before_header",func(t *testing.T){
        api,b,hash:=reverseEFixture(true)
        b.noReceipts=true
        b.header=nil
        got,err:=api.GetTransactionReceipt(context.Background(),hash)
        if err!=nil||got!=nil||b.headerCalls!=0 {t.Fatalf("no-receipt branch breached err=%v result=%v calls=%d",err,got,b.headerCalls)}
        t.Log("REVERSE_E_NO_RECEIPT_DEFENSE_PASS")
    })
    t.Run("legacy_fork_does_not_need_header",func(t *testing.T){
        api,b,hash:=reverseEFixture(false)
        b.header=nil
        got,err:=api.GetTransactionReceipt(context.Background(),hash)
        if err!=nil||got==nil||b.headerCalls!=0 {t.Fatalf("legacy counterexample breached err=%v result=%v calls=%d",err,got,b.headerCalls)}
        t.Log("REVERSE_E_PRE_LONDON_COUNTEREXAMPLE_PASS")
    })
    t.Run("nil_header_london_source_characterization",func(t *testing.T){
        api,b,hash:=reverseEFixture(true)
        b.header=nil
        var caught interface{}
        var got map[string]interface{}
        var err error
        func(){
            defer func(){caught=recover()}()
            got,err=api.GetTransactionReceipt(context.Background(),hash)
        }()
        if caught!=nil {
            t.Logf("REVERSE_E_RUNTIME_NIL_HEADER_PANIC_OBSERVED type=%T value=%v",caught,caught)
            return
        }
        if err!=nil && got==nil {
            t.Logf("REVERSE_E_RUNTIME_NIL_HEADER_ERROR_OBSERVED err=%v",err)
            return
        }
        t.Fatalf("missing header neither panicked nor returned error; result=%v err=%v",got,err)
    })
    t.Run("inconsistent_receipt_not_a_production_reorg_proof",func(t *testing.T){
        api,b,hash:=reverseEFixture(true)
        b.receipt.TxHash=common.HexToHash("0xabcdef")
        if b.receipt.TxHash==hash {t.Fatal("invalid test control")}
        got,err:=api.GetTransactionReceipt(context.Background(),hash)
        if err!=nil||got==nil {t.Fatalf("synthetic mismatch unexpectedly rejected err=%v",err)}
        if got["transactionHash"]==hash {
            t.Log("REVERSE_E_SYNTHETIC_RECEIPT_MISMATCH: public adapter emits requested hash; real backend consistency unproven")
        }
    })
}

// Independent fail-closed oracle: a missing header must return an error, never
// a Go panic. This is EXPECTED TO FAIL in the unmodified certified source and
// EXPECTED TO PASS after a *scratch-only* defensive nil guard is injected.
// The workflow checks the exact failure marker and restores all target files.
func TestReverseEFailClosedOracle(t *testing.T){
    api,b,hash:=reverseEFixture(true)
    b.header=nil
    var caught interface{}
    var data map[string]interface{}
    var err error
    func(){
        defer func(){caught=recover()}()
        data,err=api.GetTransactionReceipt(context.Background(),hash)
    }()
    if caught!=nil {
        t.Errorf("REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH: header=nil yielded panic type=%T",caught)
        return
    }
    if err==nil || data!=nil {
        t.Errorf("REVERSE_E_FAIL_CLOSED_ORACLE_MISMATCH: missing header yielded data=%v err=%v",data,err)
        return
    }
    t.Logf("REVERSE_E_FAIL_CLOSED_ORACLE_PASS err=%v",err)
}
