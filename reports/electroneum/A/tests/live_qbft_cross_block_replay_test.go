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

// An outsider resubmits identical signed bytes after first execution, after QBFT canonical import.
// A duplicate signed transaction must not produce a second recipient credit or nonce advance.
func TestLiveACrossBlockReplayAfterQBFTCommit(t *testing.T) {
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
   defer func(){done:=make(chan struct{});go func(){engine.Stop();close(done)}();select{case <-done:case <-time.After(2*time.Second):t.Log("A_NONCE_CLEANUP_TIMEOUT")}}()
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
    t.Fatalf("A_CROSS_BLOCK_REPLAY_BREACH seed=%d sender=%s expected=%s first=%s second=%s nonce=%d",tc.seed,actual.GetBalance(sender),expected,actual.GetBalance(recipient),actual.GetBalance(competing),actual.GetNonce(sender))
   }
   // Replay through a second relay only AFTER the first block became canonical.
   nextHeader:=makeHeader(sealed,engine.config)
   nextHeader.Coinbase=engine.Address()
   if chain.Config().IsLondon(nextHeader.Number){nextHeader.BaseFee=misc.CalcBaseFee(chain.Config(),sealed.Header())}
   if err:=engine.Prepare(chain,nextHeader);err!=nil {t.Fatal(err)}
   nextState,err:=chain.StateAt(sealed.Root());if err!=nil {t.Fatal(err)}
   replayPool:=new(core.GasPool).AddGas(nextHeader.GasLimit)
   beforeSender:=new(big.Int).Set(nextState.GetBalance(sender))
   beforeRecipient:=new(big.Int).Set(nextState.GetBalance(recipient))
   beforeNonce:=nextState.GetNonce(sender)
   _,replayErr:=core.ApplyTransaction(chain.Config(),chain,&nextHeader.Coinbase,replayPool,nextState,nextHeader,first,&nextHeader.GasUsed,vm.Config{})
   if replayErr==nil {t.Fatalf("A_CROSS_BLOCK_REPLAY_BREACH seed=%d duplicate signed tx admitted in second block",tc.seed)}
   if nextState.GetBalance(sender).Cmp(beforeSender)!=0||nextState.GetBalance(recipient).Cmp(beforeRecipient)!=0||nextState.GetNonce(sender)!=beforeNonce {
    t.Fatalf("A_CROSS_BLOCK_REPLAY_BREACH seed=%d rejected replay mutated state: %v",tc.seed,replayErr)
   }
   // Honest empty second block must still seal and import.
   empty,err:=engine.FinalizeAndAssemble(chain,nextHeader,nextState,nil,nil,nil);if err!=nil {t.Fatal(err)}
   secondResult:=make(chan *types.Block,1);secondStop:=make(chan struct{})
   go func(){_ = engine.Seal(chain,empty,secondResult,secondStop)}()
   var secondSealed *types.Block
   select{case secondSealed=<-secondResult:case <-time.After(12*time.Second):close(secondStop);t.Fatal("second QBFT seal timeout")}
   if secondSealed==nil {t.Fatal("nil second sealed block")}
   if _,err:=chain.InsertChain(types.Blocks{secondSealed});err!=nil {t.Fatalf("second canonical import failed: %v",err)}
   after,err:=chain.State();if err!=nil {t.Fatal(err)}
   if chain.CurrentBlock().Hash()!=secondSealed.Hash()||after.GetBalance(sender).Cmp(expected)!=0||after.GetBalance(recipient).Cmp(big.NewInt(tc.value))!=0||after.GetNonce(sender)!=1 {
    t.Fatalf("A_CROSS_BLOCK_REPLAY_BREACH seed=%d second canonical state differs",tc.seed)
   }
   t.Logf("A_CROSS_BLOCK_REPLAY_CANONICAL seed=%d block=%s tx=%s sender=%s recipient=%s rejected_recipient=%s nonce=%d second_block=%s",tc.seed,sealed.Hash(),first.Hash(),actual.GetBalance(sender),actual.GetBalance(recipient),actual.GetBalance(competing),actual.GetNonce(sender),secondSealed.Hash())
  })
 }
}
