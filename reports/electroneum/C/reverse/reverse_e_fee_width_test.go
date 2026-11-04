// Reverse Worker R: actual ethapi receipt effectiveGasPrice serialization.
// This file is copied into immutable-certified Electroneum SCRATCH only.
// Synthetic signed transactions, no public chain or real funds.
package ethapi

import (
 "context"
 "math"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/common/hexutil"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
 "github.com/electroneum/electroneum-sc/rpc"
)

type reverseFeeWidthBackend struct {
 Backend
 cfg *params.ChainConfig
 header *types.Header
 tx *types.Transaction
 receipt *types.Receipt
}
func (b *reverseFeeWidthBackend) ChainConfig() *params.ChainConfig {return b.cfg}
func (b *reverseFeeWidthBackend) GetTransaction(_ context.Context,_ common.Hash)(*types.Transaction,common.Hash,uint64,uint64,error){
 return b.tx,b.header.Hash(),1,0,nil
}
func (b *reverseFeeWidthBackend) GetReceipts(_ context.Context,_ common.Hash)(types.Receipts,error){
 return types.Receipts{b.receipt},nil
}
func (b *reverseFeeWidthBackend) HeaderByHash(_ context.Context,_ common.Hash)(*types.Header,error){
 return b.header,nil
}
func (b *reverseFeeWidthBackend) BlockByNumber(_ context.Context,_ rpc.BlockNumber)(*types.Block,error){
 return types.NewBlockWithHeader(b.header),nil
}
func reverseFeeWidthFixture(t *testing.T, price *big.Int,london bool)(*PublicTransactionPoolAPI,common.Hash) {
 t.Helper()
 blockNum:=big.NewInt(1)
 cfg:=&params.ChainConfig{ChainID:big.NewInt(1337)}
 if london {cfg.LondonBlock=big.NewInt(0)} else {cfg.LondonBlock=big.NewInt(100)}
 priv,err:=crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
 if err!=nil {t.Fatal(err)}
 to:=common.HexToAddress("0x0000000000000000000000000000000000000001")
 unsigned:=types.NewTransaction(0,to,big.NewInt(1),21000,price,nil)
 tx,err:=types.SignTx(unsigned,types.MakeSigner(cfg,blockNum),priv)
 if err!=nil {t.Fatalf("cannot sign synthetic transaction: %v",err)}
 if tx.GasPrice().Cmp(price)!=0 {t.Fatal("signed transaction changed gas price")}
 hdr:=&types.Header{Number:blockNum,BaseFee:big.NewInt(1),GasLimit:30000000,Difficulty:big.NewInt(1)}
 r:=&types.Receipt{Type:tx.Type(),Status:types.ReceiptStatusSuccessful,TxHash:tx.Hash(),CumulativeGasUsed:21000,GasUsed:21000}
 b:=&reverseFeeWidthBackend{cfg:cfg,header:hdr,tx:tx,receipt:r}
 return NewPublicTransactionPoolAPI(b,new(AddrLocker)),tx.Hash()
}
func reverseReadFeeAmount(t *testing.T,result map[string]interface{}) *big.Int {
 t.Helper()
 if result==nil {t.Fatal("receipt response unexpectedly nil")}
 switch got:=result["effectiveGasPrice"].(type) {
 case hexutil.Uint64:
  return new(big.Int).SetUint64(uint64(got))
 case *hexutil.Big:
  return new(big.Int).Set((*big.Int)(got))
 default:
  t.Fatalf("unsupported effectiveGasPrice encoding %T",result["effectiveGasPrice"])
  return nil
 }
}
func reverseHighFee() *big.Int {
 return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1),64),big.NewInt(12345))
}

func TestReverseEReceiptFeeWidthCharacterization(t *testing.T){
 cases:=[]struct{name string;fee *big.Int;london bool;expectTruncate bool}{
  {"ordinary_london_fee",big.NewInt(10),true,false},
  {"max_uint64_london",new(big.Int).SetUint64(math.MaxUint64),true,false},
  {"above_uint64_london",reverseHighFee(),true,true},
  {"above_uint64_pre_london",reverseHighFee(),false,true},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   api,hash:=reverseFeeWidthFixture(t,tc.fee,tc.london)
   response,err:=api.GetTransactionReceipt(context.Background(),hash)
   if err!=nil {t.Fatalf("actual target RPC error: %v",err)}
   if response==nil||response["transactionHash"]!=hash {t.Fatal("missing/wrong signed transaction identity")}
   got:=reverseReadFeeAmount(t,response)
   if !tc.expectTruncate{
    if got.Cmp(tc.fee)!=0 {t.Fatalf("in-range fee changed: have=%s want=%s",got,tc.fee)}
    t.Logf("REVERSE_E_FEE_IN_RANGE_PASS fee=%s",got)
    return
   }
   if got.Cmp(tc.fee)!=0{
    // Characterization: record the original target defect. After a scratch
    // guard correction, this same test must accept full-width correctness.
    expectedLow:=new(big.Int).SetUint64(tc.fee.Uint64())
    if got.Cmp(expectedLow)!=0 {t.Fatalf("unexpected narrowing: have=%s low=%s",got,expectedLow)}
    t.Logf("REVERSE_E_FEE_HIGH_TRUNCATION_OBSERVED london=%t original=%s reported=%s",tc.london,tc.fee,got)
   }else{
    t.Logf("REVERSE_E_FEE_HIGH_FULLWIDTH_ACCEPTED london=%t fee=%s",tc.london,got)
   }
  })
 }
}
// Independent arbitrary-precision oracle: JSON-RPC receipt effective gas
// price must equal the actual signed transaction gas price in these fixtures.
func TestReverseEReceiptFeeWidthOracle(t *testing.T){
 high:=reverseHighFee()
 for _,london:=range []bool{false,true}{
  api,hash:=reverseFeeWidthFixture(t,high,london)
  response,err:=api.GetTransactionReceipt(context.Background(),hash)
  if err!=nil {t.Fatalf("fee fixture: %v",err)}
  got:=reverseReadFeeAmount(t,response)
  if got.Cmp(high)!=0 {
   t.Errorf("REVERSE_E_FEE_FULLWIDTH_ORACLE_MISMATCH london=%t tx_price=%s rpc_price=%s",london,high,got)
  }else{
   t.Logf("REVERSE_E_FEE_FULLWIDTH_ORACLE_PASS london=%t fee=%s",london,got)
  }
 }
}
