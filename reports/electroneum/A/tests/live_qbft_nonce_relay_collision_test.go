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

// Outsider signs two conflicting same-nonce transfers through distinct relay clients.
// Only one debit/credit may survive in a genuinely sealed canonical QBFT block.
func TestLiveASameNonceRelayCollision(t *testing.T) {
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
   second,err:=types.SignTx(types.NewTransaction(0,competing,big.NewInt(tc.value+1),21000,price,nil),signer,key);if err!=nil {t.Fatal(err)}
   pool:=new(core.GasPool).AddGas(header.GasLimit)
   receipt,err:=core.ApplyTransaction(chain.Config(),chain,&header.Coinbase,pool,state,header,first,&header.GasUsed,vm.Config{})
   if err!=nil {t.Fatalf("first signed tx rejected: %v",err)}
   beforeSecond:=new(big.Int).Set(state.GetBalance(competing))
   if _,err:=core.ApplyTransaction(chain.Config(),chain,&header.Coinbase,pool,state,header,second,&header.GasUsed,vm.Config{});err==nil {
    t.Fatalf("A_NONCE_RELAY_BREACH seed=%d second same-nonce tx accepted",tc.seed)
   }
   if state.GetBalance(competing).Cmp(beforeSecond)!=0 {t.Fatalf("A_NONCE_RELAY_BREACH seed=%d rejected tx credited recipient",tc.seed)}
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
    t.Fatalf("A_NONCE_RELAY_BREACH seed=%d sender=%s expected=%s first=%s second=%s nonce=%d",tc.seed,actual.GetBalance(sender),expected,actual.GetBalance(recipient),actual.GetBalance(competing),actual.GetNonce(sender))
   }
   t.Logf("A_NONCE_RELAY_CANONICAL seed=%d block=%s tx=%s sender=%s recipient=%s rejected_recipient=%s nonce=%d",tc.seed,sealed.Hash(),first.Hash(),actual.GetBalance(sender),actual.GetBalance(recipient),actual.GetBalance(competing),actual.GetNonce(sender))
  })
 }
}
