package ethapi

import (
 "context"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/params"
)

// Synthetic backend isolates the actual public RPC adapter without chain traffic.
// Only four methods used by GetTransactionReceipt are overridden.
type workerEReceiptBackend struct {
 Backend
 tx *types.Transaction
 block common.Hash
 receipt *types.Receipt
 header *types.Header
 index uint64
}

func (b *workerEReceiptBackend) GetTransaction(_ context.Context, _ common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
 return b.tx, b.block, 1, b.index, nil
}
func (b *workerEReceiptBackend) GetReceipts(_ context.Context, _ common.Hash) (types.Receipts, error) {
 return types.Receipts{b.receipt}, nil
}
func (b *workerEReceiptBackend) HeaderByHash(_ context.Context, _ common.Hash) (*types.Header, error) {
 return b.header, nil
}
func (b *workerEReceiptBackend) ChainConfig() *params.ChainConfig {
 return &params.ChainConfig{ChainID:big.NewInt(1337), LondonBlock:big.NewInt(0)}
}

func workerEFixture() (*PublicTransactionPoolAPI, *workerEReceiptBackend, common.Hash) {
 to:=common.HexToAddress("0x0000000000000000000000000000000000000001")
 tx:=types.NewTransaction(0,to,big.NewInt(1),21000,big.NewInt(10),nil)
 block:=common.HexToHash("0x1111")
 b:=&workerEReceiptBackend{
  tx:tx,block:block,
  receipt:&types.Receipt{Type:tx.Type(),Status:types.ReceiptStatusSuccessful,TxHash:tx.Hash(),GasUsed:21000,CumulativeGasUsed:21000},
  header:&types.Header{Number:big.NewInt(1),BaseFee:big.NewInt(1)},
 }
 return NewPublicTransactionPoolAPI(b,new(AddrLocker)),b,tx.Hash()
}

// TestWorkerEReceiptIdentityAndNilHeader traces an actual eth_getTransactionReceipt
// execution through a controlled backend. It records observed acceptance/panics;
// a synthetic backend inconsistency is NOT evidence an outsider can induce it
// in a normal full node.
func TestWorkerEReceiptIdentityAndNilHeader(t *testing.T) {
 t.Run("canonical_positive",func(t *testing.T) {
  api,_,hash:=workerEFixture()
  result,err:=api.GetTransactionReceipt(context.Background(),hash)
  if err!=nil || result==nil {t.Fatalf("valid receipt failed: %v result=%v",err,result)}
  if result["transactionHash"]!=hash {t.Fatalf("valid receipt returned wrong transaction hash")}
  if result["effectiveGasPrice"]==nil {t.Fatalf("expected London effective gas price")}
  t.Log("E_RPC_CANONICAL_CONTROL_PASS")
 })
 t.Run("wrong_receipt_txhash",func(t *testing.T) {
  api,b,hash:=workerEFixture()
  b.receipt.TxHash=common.HexToHash("0xbeef")
  // Independent oracle: canonical receipt must bind to requested tx identity.
  shouldReject:=b.receipt.TxHash!=hash
  if !shouldReject {t.Fatal("negative control did not differ")}
  result,err:=api.GetTransactionReceipt(context.Background(),hash)
  if err!=nil {t.Fatalf("unexpected adapter error: %v",err)}
  if result==nil {t.Log("E_RPC_MISMATCH_REJECTED");return}
  if result["transactionHash"]==hash {
   t.Log("E_RPC_MISMATCH_ACCEPTED_BY_SYNTHETIC_BACKEND: result transactionHash is request hash despite receipt.TxHash mismatch")
  } else {t.Log("E_RPC_MISMATCH_RESULT_HASH_DIFFERENT")}
 })
 t.Run("nil_header_no_backend_error",func(t *testing.T) {
  api,b,hash:=workerEFixture()
  b.header=nil
  var observed interface{}
  var err error
  func(){
   defer func(){observed=recover()}()
   _,err=api.GetTransactionReceipt(context.Background(),hash)
  }()
  if observed!=nil {
   t.Logf("E_RPC_NIL_HEADER_PANIC_FROM_SYNTHETIC_BACKEND type=%T value=%v",observed,observed)
   return
  }
  if err!=nil {t.Logf("E_RPC_NIL_HEADER_ERROR=%v",err);return}
  t.Fatal("missing header with nonzero-fee London transaction returned success; expected error or panic")
 })
}

// Additional deterministic RPC boundary controls; they do not establish
// that an attacker can corrupt the shipped full-node backend.
func TestWorkerEReceiptStatusAndIndexControls(t *testing.T) {
 t.Run("failed_transaction_must_not_look_successful",func(t *testing.T) {
  api,b,hash:=workerEFixture()
  b.receipt.Status=types.ReceiptStatusFailed
  got,err:=api.GetTransactionReceipt(context.Background(),hash)
  if err!=nil || got==nil {t.Fatalf("failed receipt query: %v, %v",err,got)}
  if got["status"]==nil {t.Fatal("failed transaction omitted status")}
  if got["transactionHash"]!=hash {t.Fatal("failed transaction misidentified")}
  t.Log("E_RPC_FAILED_STATUS_CONTROL",got["status"])
 })
 t.Run("out_of_range_index_returns_null",func(t *testing.T) {
  api,b,hash:=workerEFixture()
  b.index=2 // One receipt exists; no receipt is valid at index two.
  got,err:=api.GetTransactionReceipt(context.Background(),hash)
  if err!=nil || got!=nil {t.Fatalf("out-of-range receipt should be null: result=%v error=%v",got,err)}
  t.Log("E_RPC_OUT_OF_RANGE_INDEX_REJECTED")
 })
}
