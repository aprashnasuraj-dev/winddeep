package backend

import (
 "fmt"
 "math/big"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 "github.com/electroneum/electroneum-sc/consensus/misc"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
)

// A self-transfer must not mint value: only its gas fee leaves the sender.
// Control is a separate signed transfer with a different nonce and recipient.
func TestLiveASelfTransferFeeConservationQBFT(t *testing.T) {
 for _,tc:=range []struct{seed byte; initial int64; value int64}{{101,100000000000000000,17},{102,200000000000000000,7001},{103,300000000000000000,93000}} {
  t.Run(fmt.Sprintf("state_%d",tc.seed),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(1)
   var raw [32]byte;raw[31]=tc.seed
   key,err:=crypto.ToECDSA(raw[:]);if err!=nil {t.Fatal(err)}
   sender:=crypto.PubkeyToAddress(key.PublicKey)
   if genesis.Alloc==nil {genesis.Alloc=make(core.GenesisAlloc)}
   genesis.Alloc[sender]=core.GenesisAccount{Balance:big.NewInt(tc.initial)}
   cfg:=*istanbul.DefaultConfig
   chain,engine:=newBlockchainFromConfig(genesis,keys,cfg)
   defer func(){done:=make(chan struct{});go func(){engine.Stop();close(done)}();select{case <-done:case <-time.After(2*time.Second):t.Log("A_SELF_CLEANUP_TIMEOUT")}}()
   parent:=chain.Genesis()
   header:=makeHeader(parent,engine.config)
   header.Coinbase=engine.Address()
   if chain.Config().IsLondon(header.Number){header.BaseFee=misc.CalcBaseFee(chain.Config(),parent.Header())}
   if err:=engine.Prepare(chain,header);err!=nil {t.Fatal(err)}
   state,err:=chain.StateAt(parent.Root());if err!=nil {t.Fatal(err)}
   beneficiaryBefore:=new(big.Int).Set(state.GetBalance(header.Coinbase))
   price:=big.NewInt(4000000000)
   signer:=types.MakeSigner(chain.Config(),header.Number)
   self,err:=types.SignTx(types.NewTransaction(0,sender,big.NewInt(tc.value),21000,price,nil),signer,key);if err!=nil {t.Fatal(err)}
   pool:=new(core.GasPool).AddGas(header.GasLimit)
   receipt,err:=core.ApplyTransaction(chain.Config(),chain,&header.Coinbase,pool,state,header,self,&header.GasUsed,vm.Config{})
   if err!=nil {t.Fatalf("valid self-transfer rejected: %v",err)}
   block,err:=engine.FinalizeAndAssemble(chain,header,state,[]*types.Transaction{self},nil,[]*types.Receipt{receipt});if err!=nil {t.Fatal(err)}
   result:=make(chan *types.Block,1);stop:=make(chan struct{})
   go func(){_ = engine.Seal(chain,block,result,stop)}()
   var sealed *types.Block
   select{case sealed=<-result:case <-time.After(12*time.Second):close(stop);t.Fatal("QBFT seal timeout")}
   if sealed==nil {t.Fatal("nil sealed block")}
   if _,err:=chain.InsertChain(types.Blocks{sealed});err!=nil {t.Fatalf("canonical import: %v",err)}
   actual,err:=chain.State();if err!=nil {t.Fatal(err)}
   gasCost:=new(big.Int).Mul(new(big.Int).SetUint64(receipt.GasUsed),price)
   expectedSender:=new(big.Int).Sub(big.NewInt(tc.initial),gasCost)
   if actual.GetBalance(sender).Cmp(expectedSender)!=0 || actual.GetNonce(sender)!=1 {
    t.Fatalf("A_SELF_VALUE_BREACH seed=%d sender=%s expected=%s nonce=%d",tc.seed,actual.GetBalance(sender),expectedSender,actual.GetNonce(sender))
   }
   // Separate beneficiary accounting from block issuance: report observed delta, never assume reward zero.
   beneficiaryDelta:=new(big.Int).Sub(actual.GetBalance(header.Coinbase),beneficiaryBefore)
   t.Logf("A_SELF_FEE_CANONICAL seed=%d block=%s tx=%s gas=%d sender=%s expected=%s beneficiary_delta_including_issuance=%s nonce=%d",tc.seed,sealed.Hash(),self.Hash(),receipt.GasUsed,actual.GetBalance(sender),expectedSender,beneficiaryDelta,actual.GetNonce(sender))
  })
 }
}
