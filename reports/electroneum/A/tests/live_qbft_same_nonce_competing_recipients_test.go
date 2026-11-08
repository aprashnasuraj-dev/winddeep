package backend

import (
 "fmt"
 "math/big"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 "github.com/electroneum/electroneum-sc/consensus/istanbul/testutils"
 "github.com/electroneum/electroneum-sc/consensus/misc"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
)

// Two different valid signed transactions with the same nonce target different recipients.
// Canonical QBFT state must not execute a losing same-nonce alternative after first inclusion.
func TestLiveASameNonceCompetingRecipientsCanonical(t *testing.T) {
 for _,tc:=range []struct{seed byte; value int64}{{91,17},{92,7001},{93,93000}} {
  t.Run(fmt.Sprintf("state_%d",tc.seed),func(t *testing.T){
   genesis,keys:=testutils.GenesisAndKeys(1)
   var raw [32]byte;raw[31]=tc.seed
   key,err:=crypto.ToECDSA(raw[:]);if err!=nil {t.Fatal(err)}
   sender:=crypto.PubkeyToAddress(key.PublicKey)
   const initial int64=100000000000000000
   if genesis.Alloc==nil {genesis.Alloc=make(core.GenesisAlloc)}
   genesis.Alloc[sender]=core.GenesisAccount{Balance:big.NewInt(initial)}
   cfg:=*istanbul.DefaultConfig
   chain,engine:=newBlockchainFromConfig(genesis,keys,cfg)
   defer func(){done:=make(chan struct{});go func(){engine.Stop();close(done)}();select{case <-done:case <-time.After(2*time.Second):t.Log("A_REPLACEMENT_CLEANUP_TIMEOUT")}}()
   parent:=chain.Genesis()
   header:=makeHeader(parent,engine.config)
   header.Coinbase=engine.Address()
   if chain.Config().IsLondon(header.Number){header.BaseFee=misc.CalcBaseFee(chain.Config(),parent.Header())}
   if err:=engine.Prepare(chain,header);err!=nil {t.Fatal(err)}
   state,err:=chain.StateAt(parent.Root());if err!=nil {t.Fatal(err)}
   price:=big.NewInt(4000000000)
   recipient:=common.Address{0xa1}
   competing:=common.Address{0xa2}
   signer:=types.MakeSigner(chain.Config(),header.Number)
   first,err:=types.SignTx(types.NewTransaction(0,recipient,big.NewInt(tc.value),21000,price,nil),signer,key);if err!=nil {t.Fatal(err)}
   pool:=new(core.GasPool).AddGas(header.GasLimit)
   receipt,err:=core.ApplyTransaction(chain.Config(),chain,&header.Coinbase,pool,state,header,first,&header.GasUsed,vm.Config{})
   if err!=nil {t.Fatalf("honest signed tx rejected: %v",err)}
   block,err:=engine.FinalizeAndAssemble(chain,header,state,[]*types.Transaction{first},nil,[]*types.Receipt{receipt});if err!=nil {t.Fatal(err)}
   result:=make(chan *types.Block,1);stop:=make(chan struct{})
   go func(){_ = engine.Seal(chain,block,result,stop)}()
   var sealed *types.Block
   select{case sealed=<-result:case <-time.After(12*time.Second):close(stop);t.Fatal("QBFT seal timeout")}
   if sealed==nil {t.Fatal("nil sealed block")}
   if _,err:=chain.InsertChain(types.Blocks{sealed});err!=nil {t.Fatalf("canonical import failed: %v",err)}
   if chain.CurrentBlock().Hash()!=sealed.Hash(){t.Fatal("not canonical")}
   actual,err:=chain.State();if err!=nil {t.Fatal(err)}
   fee:=new(big.Int).Mul(price,big.NewInt(21000))
   expected:=new(big.Int).Sub(big.NewInt(initial),new(big.Int).Add(big.NewInt(tc.value),fee))
   if actual.GetBalance(sender).Cmp(expected)!=0||actual.GetBalance(recipient).Cmp(big.NewInt(tc.value))!=0||actual.GetBalance(competing).Sign()!=0||actual.GetNonce(sender)!=1 {
    t.Fatalf("A_SAME_NONCE_BREACH seed=%d sender=%s expected=%s first=%s second=%s nonce=%d",tc.seed,actual.GetBalance(sender),expected,actual.GetBalance(recipient),actual.GetBalance(competing),actual.GetNonce(sender))
   }
   // Two distinct, valid signatures from the same sender and nonce compete.
   // A relay may propose a higher-fee alternative, but the canonical state
   // must never execute both transfers or debit a second nonce.
   replacement,err:=types.SignTx(types.NewTransaction(0,competing,big.NewInt(tc.value+1),21000,big.NewInt(5000000000),nil),signer,key)
   if err!=nil {t.Fatal(err)}
   if replacement.Hash()==first.Hash() {t.Fatal("non-distinct replacement")}
   competingHeader:=makeHeader(sealed,engine.config)
   competingHeader.Coinbase=engine.Address()
   if chain.Config().IsLondon(competingHeader.Number){competingHeader.BaseFee=misc.CalcBaseFee(chain.Config(),sealed.Header())}
   if err:=engine.Prepare(chain,competingHeader);err!=nil {t.Fatal(err)}
   competingState,err:=chain.StateAt(sealed.Root());if err!=nil {t.Fatal(err)}
   beforeSender:=new(big.Int).Set(competingState.GetBalance(sender))
   beforeFirst:=new(big.Int).Set(competingState.GetBalance(recipient))
   beforeSecond:=new(big.Int).Set(competingState.GetBalance(competing))
   beforeNonce:=competingState.GetNonce(sender)
   competingPool:=new(core.GasPool).AddGas(competingHeader.GasLimit)
   _,rejectErr:=core.ApplyTransaction(chain.Config(),chain,&competingHeader.Coinbase,competingPool,competingState,competingHeader,replacement,&competingHeader.GasUsed,vm.Config{})
   if rejectErr==nil {t.Fatalf("A_SAME_NONCE_BREACH seed=%d competing same-nonce tx executed after canonical inclusion",tc.seed)}
   if competingState.GetBalance(sender).Cmp(beforeSender)!=0 || competingState.GetBalance(recipient).Cmp(beforeFirst)!=0 || competingState.GetBalance(competing).Cmp(beforeSecond)!=0 || competingState.GetNonce(sender)!=beforeNonce {
      t.Fatalf("A_SAME_NONCE_BREACH seed=%d rejected replacement mutated state: %v",tc.seed,rejectErr)
   }
   // Honest control: a fresh nonce-1 transaction is accepted into the next block.
   honest,err:=types.SignTx(types.NewTransaction(1,competing,big.NewInt(1),21000,price,nil),types.MakeSigner(chain.Config(),competingHeader.Number),key)
   if err!=nil {t.Fatal(err)}
   honestReceipt,err:=core.ApplyTransaction(chain.Config(),chain,&competingHeader.Coinbase,competingPool,competingState,competingHeader,honest,&competingHeader.GasUsed,vm.Config{})
   if err!=nil {t.Fatalf("honest next-nonce control rejected: %v",err)}
   nextBlock,err:=engine.FinalizeAndAssemble(chain,competingHeader,competingState,[]*types.Transaction{honest},nil,[]*types.Receipt{honestReceipt})
   if err!=nil {t.Fatal(err)}
   result2:=make(chan *types.Block,1);stop2:=make(chan struct{})
   go func(){_ = engine.Seal(chain,nextBlock,result2,stop2)}()
   var secondSealed *types.Block
   select{case secondSealed=<-result2:case <-time.After(12*time.Second):close(stop2);t.Fatal("second QBFT seal timeout")}
   if secondSealed==nil {t.Fatal("nil second sealed block")}
   if _,err:=chain.InsertChain(types.Blocks{secondSealed});err!=nil {t.Fatalf("second canonical import: %v",err)}
   final,err:=chain.State();if err!=nil {t.Fatal(err)}
   expectedFinal:=new(big.Int).Sub(expected,new(big.Int).Add(big.NewInt(1),fee))
   if final.GetBalance(sender).Cmp(expectedFinal)!=0 || final.GetBalance(recipient).Cmp(big.NewInt(tc.value))!=0 || final.GetBalance(competing).Cmp(big.NewInt(1))!=0 || final.GetNonce(sender)!=2 {
      t.Fatalf("A_SAME_NONCE_BREACH seed=%d unexpected canonical accounting sender=%s recipient1=%s recipient2=%s nonce=%d",tc.seed,final.GetBalance(sender),final.GetBalance(recipient),final.GetBalance(competing),final.GetNonce(sender))
   }
   t.Logf("A_SAME_NONCE_CANONICAL seed=%d first=%s replacement=%s second=%s sender=%s expected=%s nonce=%d rejection=%v",tc.seed,first.Hash(),replacement.Hash(),secondSealed.Hash(),final.GetBalance(sender),expectedFinal,final.GetNonce(sender),rejectErr)
  })
 }
}
