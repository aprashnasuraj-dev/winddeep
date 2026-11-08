package ethapi

import (
 "context"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/common/hexutil"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/params"
 "github.com/electroneum/electroneum-sc/rpc"
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
  // Strict characterization: the adapter currently masks an inconsistent
  // synthetic backend. This is NOT proof that the production backend can
  // return such a pair. Fail if the oracle or observation silently changes.
  if result["transactionHash"]!=hash {
   t.Fatalf("expected adapter to echo requested hash; got %v",result["transactionHash"])
  }
  if b.receipt.TxHash==result["transactionHash"] {
   t.Fatal("identity oracle failed to detect the deliberately mismatched receipt")
  }
  t.Log("E_RPC_SYNTHETIC_IDENTITY_MISMATCH_DETECTED_BY_INDEPENDENT_ORACLE")
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
  if got["status"]!=hexutil.Uint(types.ReceiptStatusFailed) {t.Fatalf("failed receipt status mismatch: %v",got["status"])}
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

// TestWorkerEReceiptOracleMutationSensitivity proves that the independent
// identity oracle detects two distinct synthetic backend inconsistencies.
// It does not claim either is reachable through an honest chain backend.
func TestWorkerEReceiptOracleMutationSensitivity(t *testing.T) {
 cases:=[]struct{name string; mutate func(*workerEReceiptBackend)}{
  {"wrong_receipt_hash",func(b *workerEReceiptBackend){b.receipt.TxHash=common.HexToHash("0xbeef")}},
  {"wrong_lookup_transaction",func(b *workerEReceiptBackend){to:=common.HexToAddress("0x0000000000000000000000000000000000000002");b.tx=types.NewTransaction(0,to,big.NewInt(2),21000,big.NewInt(10),nil)}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   api,b,requested:=workerEFixture()
   tc.mutate(b)
   // Independent expected identity comes from fixture construction, not
   // from RPC fields, and both backend identities must bind to request.
   oracleOK:=b.tx.Hash()==requested && b.receipt.TxHash==requested
   if oracleOK {t.Fatal("adversarial mutation escaped independent identity oracle")}
   got,err:=api.GetTransactionReceipt(context.Background(),requested)
   if err!=nil || got==nil {t.Fatalf("unexpected synthetic adapter response: %v %v",err,got)}
   rpcOK:=got["transactionHash"]==requested
   if !rpcOK {t.Fatalf("expected request-hash echo; got %v",got["transactionHash"])}
   if rpcOK==oracleOK {t.Fatal("oracle sensitivity lost: mismatch not distinguished")}
   t.Log("E_RPC_ORACLE_KILLED_SYNTHETIC_IDENTITY_MUTATION")
  })
 }
}


// TestWorkerEReceiptFeeWidthBoundary characterizes the shipped RPC fee encoding
// with actual certified ethapi code. The backend remains synthetic: this does
// not prove that a funded >64-bit gas-price transaction can enter a real block.
// The expected fee is independently computed from the fixture input, not RPC.
func TestWorkerEReceiptFeeWidthBoundary(t *testing.T) {
 boundary:=new(big.Int).Lsh(big.NewInt(1),64)
 cases:=[]struct{name string;price *big.Int; expectLoss bool}{
  {"below_uint64_max",new(big.Int).Sub(new(big.Int).Set(boundary),big.NewInt(1)),false},
  {"at_2pow64",new(big.Int).Set(boundary),true},
  {"above_2pow64",new(big.Int).Add(new(big.Int).Set(boundary),big.NewInt(1)),true},
  {"above_2pow65",new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1),65),big.NewInt(17)),true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   api,b,_:=workerEFixture()
   to:=common.HexToAddress("0x0000000000000000000000000000000000000001")
   b.tx=types.NewTransaction(0,to,big.NewInt(1),21000,new(big.Int).Set(tc.price),nil)
   b.receipt.TxHash=b.tx.Hash()
   got,err:=api.GetTransactionReceipt(context.Background(),b.tx.Hash())
   if err!=nil||got==nil {t.Fatalf("receipt error=%v result=%v",err,got)}
   field,ok:=got["effectiveGasPrice"].(hexutil.Uint64)
   if !ok {t.Fatalf("unexpected fee field type %T",got["effectiveGasPrice"])}
   observed:=new(big.Int).SetUint64(uint64(field))
   // Independent big-int fee oracle for a legacy transaction with baseFee=1.
   expected:=new(big.Int).Set(tc.price)
   discrepancy:=new(big.Int).Sub(expected,observed)
   loss:=discrepancy.Sign()!=0
   if loss!=tc.expectLoss {t.Fatalf("width boundary: expectedLoss=%v actualLoss=%v",tc.expectLoss,loss)}
   if observed.Uint64()!=tc.price.Uint64() {t.Fatalf("unexpected serialization %s",observed)}
   sibling:=newRPCTransaction(b.tx,b.block,1,0,b.header.BaseFee,b.ChainConfig())
   if sibling.GasPrice==nil||(*big.Int)(sibling.GasPrice).Cmp(expected)!=0 {
    t.Fatalf("sibling full-width price mismatch: got=%v expected=%v",sibling.GasPrice,expected)
   }
   if loss && discrepancy.Cmp(boundary)<0 {t.Fatalf("truncation delta unexpectedly small: %s",discrepancy)}
   // X-factor real RPC message boundary: encode through the shipped JSON-RPC
   // server/client, rather than merely inspecting an internal Go map. The
   // backing chain is STILL synthetic and this cannot establish outsider impact.
   server:=rpc.NewServer()
   if e:=server.RegisterName("eth",api);e!=nil {t.Fatalf("register real RPC server: %v",e)}
   client:=rpc.DialInProc(server)
   var wire struct {
    EffectiveGasPrice string `json:"effectiveGasPrice"`
    TransactionHash common.Hash `json:"transactionHash"`
   }
   wireErr:=client.CallContext(context.Background(),&wire,"eth_getTransactionReceipt",b.tx.Hash())
   client.Close()
   server.Stop()
   if wireErr!=nil {t.Fatalf("real JSON-RPC roundtrip failed: %v",wireErr)}
   wireExpected:=hexutil.EncodeUint64(tc.price.Uint64())
   if wire.TransactionHash!=b.tx.Hash() {t.Fatalf("RPC wire tx identity mismatch: got=%s",wire.TransactionHash)}
   if wire.EffectiveGasPrice!=wireExpected {t.Fatalf("RPC wire fee width changed: got=%q expected narrowed=%q",wire.EffectiveGasPrice,wireExpected)}
   t.Logf("E_RPC_WIRE_EFFECTIVE_PRICE name=%s wire=%s bigint_expected=%s confirmed_truncation=%t",tc.name,wire.EffectiveGasPrice,expected,loss)

   // Corrected full-width encoding would remove the discrepancy; the
   // independent oracle explicitly detects the current narrowing mutation.
   t.Logf("E_FEE_WIDTH_CASE price=%s receipt=%s sibling=%s loss=%v delta=%s",expected,observed,(*big.Int)(sibling.GasPrice),loss,discrepancy)
  })
 }
}
