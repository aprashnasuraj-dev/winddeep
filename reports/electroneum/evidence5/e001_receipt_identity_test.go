package ethapi
import (
"context"
"math/big"
"testing"
"github.com/electroneum/electroneum-sc/common"
"github.com/electroneum/electroneum-sc/common/hexutil"
"github.com/electroneum/electroneum-sc/core/types"
"github.com/electroneum/electroneum-sc/params"
)
type receiptIdentityBackend struct {
 Backend
 transaction *types.Transaction
 blockHash common.Hash
 receipt *types.Receipt
 header *types.Header
}
func (b *receiptIdentityBackend) GetTransaction(_ context.Context, _ common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {return b.transaction,b.blockHash,1,0,nil}
func (b *receiptIdentityBackend) GetReceipts(_ context.Context, _ common.Hash) (types.Receipts,error) {return types.Receipts{b.receipt},nil}
func (b *receiptIdentityBackend) HeaderByHash(_ context.Context, _ common.Hash) (*types.Header,error) {return b.header,nil}
func (b *receiptIdentityBackend) ChainConfig() *params.ChainConfig {return &params.ChainConfig{ChainID:big.NewInt(1337),LondonBlock:big.NewInt(0)}}
func makeReceiptIdentityFixture() (*PublicTransactionPoolAPI,*receiptIdentityBackend,common.Hash) {
 to:=common.HexToAddress("0x0000000000000000000000000000000000000001")
 tx:=types.NewTransaction(0,to,big.NewInt(1),21000,big.NewInt(10),nil)
 b:=&receiptIdentityBackend{transaction:tx,blockHash:common.HexToHash("0x1111"),receipt:&types.Receipt{Type:tx.Type(),Status:types.ReceiptStatusSuccessful,TxHash:tx.Hash(),GasUsed:21000,CumulativeGasUsed:21000},header:&types.Header{Number:big.NewInt(1),BaseFee:big.NewInt(1)}}
 return NewPublicTransactionPoolAPI(b,new(AddrLocker)),b,tx.Hash()
}
func TestReceiptIdentityCrossRecord(t *testing.T){
 api,b,txhash:=makeReceiptIdentityFixture()
 baseline,err:=api.GetTransactionReceipt(context.Background(),txhash)
 if err!=nil||baseline==nil||baseline["transactionHash"]!=txhash||baseline["status"]!=hexutil.Uint(1){t.Fatalf("valid baseline failed receipt=%v err=%v",baseline,err)}
 t.Log("RECEIPT_IDENTITY_VALID_BASELINE_PASS")
 foreignHash:=common.HexToHash("0xbeef")
 b.receipt.TxHash=foreignHash
 b.receipt.Status=types.ReceiptStatusFailed
 response,err:=api.GetTransactionReceipt(context.Background(),txhash)
 if err!=nil||response==nil{t.Fatalf("cross record absent result=%v err=%v",response,err)}
 if response["transactionHash"]!=txhash{t.Fatalf("requested identity not reported: %v",response["transactionHash"])}
 if response["status"]!=hexutil.Uint(types.ReceiptStatusFailed){t.Fatalf("foreign status not propagated: %v",response["status"])}
 if b.receipt.TxHash==txhash{t.Fatal("fixture accidentally equal")}
 t.Logf("RECEIPT_IDENTITY_MISMATCH_CONFIRMED request=%s receipt_internal=%s response=%s status=%v",txhash,foreignHash,response["transactionHash"],response["status"])
 b.receipt.TxHash=txhash
 restored,err:=api.GetTransactionReceipt(context.Background(),txhash)
 if err!=nil||restored==nil||restored["transactionHash"]!=txhash{t.Fatalf("restored baseline failed %v / %v",restored,err)}
 t.Log("RECEIPT_IDENTITY_RESTORED_CONTROL_PASS")
}
