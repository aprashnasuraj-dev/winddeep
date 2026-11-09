package backend

import (
 "fmt"
 "math/big"
 "strings"
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

// C canonical state discriminator. No network or production credentials.
// Uses Electroneum's native QBFT test backend and actual BlockChain.InsertChain.
func TestWorkerCIntrinsicGasCanonicalBoundary(t *testing.T) {
 for _,tc:=range []struct{seed byte;value,initial int64}{
  {53,100,100000000000000000},
  {59,257,110000000000000000},
  {61,509,120000000000000000},
 } {
  t.Run(fmt.Sprintf("state_%d",tc.seed),func(t *testing.T){
   genesis,validatorKeys:=testutils.GenesisAndKeys(1)
   var keyBytes [32]byte;keyBytes[31]=tc.seed
   key,err:=crypto.ToECDSA(keyBytes[:]);if err!=nil{t.Fatal(err)}
   sender:=crypto.PubkeyToAddress(key.PublicKey)
   recipient:=common.Address{0xc3}
   if genesis.Alloc==nil{genesis.Alloc=make(core.GenesisAlloc)}
   genesis.Alloc[sender]=core.GenesisAccount{Balance:big.NewInt(tc.initial)}
   config:=*istanbul.DefaultConfig
   chain,engine:=newBlockchainFromConfig(genesis,validatorKeys,config)
   defer func(){done:=make(chan struct{});go func(){_ =engine.Stop();close(done)}();select{case <-done:case <-time.After(3*time.Second):t.Log("C_ENGINE_STOP_TIMEOUT")}}()
   parent:=chain.Genesis()
   hdr:=makeHeader(parent,engine.config)
   hdr.Coinbase=engine.Address()
   if chain.Config().IsLondon(hdr.Number){hdr.BaseFee=misc.CalcBaseFee(chain.Config(),parent.Header())}
   if err:=engine.Prepare(chain,hdr);err!=nil{t.Fatal(err)}
   signer:=types.MakeSigner(chain.Config(),hdr.Number)
   const price int64=4000000000
   bad,err:=types.SignTx(types.NewTransaction(0,recipient,big.NewInt(tc.value),20999,big.NewInt(price),nil),signer,key)
   if err!=nil{t.Fatal(err)}
   good,err:=types.SignTx(types.NewTransaction(0,recipient,big.NewInt(tc.value),21000,big.NewInt(price),nil),signer,key)
   if err!=nil{t.Fatal(err)}
   state,err:=chain.StateAt(parent.Root());if err!=nil{t.Fatal(err)}
   var used uint64
   _,directErr:=core.ApplyTransaction(chain.Config(),chain,&hdr.Coinbase,new(core.GasPool).AddGas(hdr.GasLimit),state,hdr,bad,&used,vm.Config{})
   if directErr==nil||!strings.Contains(strings.ToLower(directErr.Error()),"intrinsic"){t.Fatalf("direct guard: %v",directErr)}
   directDelta:=new(big.Int).Sub(big.NewInt(tc.initial),state.GetBalance(sender))
   t.Logf("C_INTRINSIC_COMPONENT seed=%d rejected=true disposable_debit=%s",tc.seed,directDelta)
   clean,err:=chain.StateAt(parent.Root());if err!=nil{t.Fatal(err)}
   unsealed,err:=engine.FinalizeAndAssemble(chain,hdr,clean,[]*types.Transaction{bad},nil,nil)
   if err!=nil{t.Fatal(err)}
   result:=make(chan *types.Block,1);stop:=make(chan struct{})
   go func(){_ =engine.Seal(chain,unsealed,result,stop)}()
   var sealed *types.Block
   select{case sealed=<-result:case <-time.After(15*time.Second):close(stop);t.Fatal("C_BAD_QBFT_SEAL_TIMEOUT")}
   if sealed==nil{t.Fatal("C_BAD_QBFT_NIL")}
   n,importErr:=chain.InsertChain(types.Blocks{sealed})
   if importErr==nil||!strings.Contains(strings.ToLower(importErr.Error()),"intrinsic"){
    t.Fatalf("C_BAD_BLOCK_INCORRECT_REJECTION accepted=%v count=%d",importErr,n)
   }
   canonical,err:=chain.StateAt(parent.Root());if err!=nil{t.Fatal(err)}
   if chain.CurrentBlock().Hash()!=parent.Hash()||chain.GetCanonicalHash(1)!=(common.Hash{})||
      canonical.GetBalance(sender).Cmp(big.NewInt(tc.initial))!=0||
      canonical.GetBalance(recipient).Sign()!=0||canonical.GetNonce(sender)!=0{
     t.Fatalf("C_CANONICAL_INVARIANT_BREACH seed=%d head=%s sender=%s nonce=%d",tc.seed,chain.CurrentBlock().Hash(),canonical.GetBalance(sender),canonical.GetNonce(sender))
   }
   t.Logf("C_CANONICAL_GUARD_PASS seed=%d bad=%s head=%s sender=%s nonce=0",tc.seed,bad.Hash(),chain.CurrentBlock().Hash(),canonical.GetBalance(sender))
   // Honest control: exact intrinsic limit and otherwise identical signed tx.
   honestHeader:=makeHeader(parent,engine.config)
   honestHeader.Coinbase=engine.Address()
   if chain.Config().IsLondon(honestHeader.Number){honestHeader.BaseFee=misc.CalcBaseFee(chain.Config(),parent.Header())}
   if err:=engine.Prepare(chain,honestHeader);err!=nil{t.Fatal(err)}
   honestState,err:=chain.StateAt(parent.Root());if err!=nil{t.Fatal(err)}
   pool:=new(core.GasPool).AddGas(honestHeader.GasLimit)
   receipt,err:=core.ApplyTransaction(chain.Config(),chain,&honestHeader.Coinbase,pool,honestState,honestHeader,good,&honestHeader.GasUsed,vm.Config{})
   if err!=nil||receipt==nil{t.Fatalf("C_HONEST_TX_FAIL: %v",err)}
   honest,err:=engine.FinalizeAndAssemble(chain,honestHeader,honestState,[]*types.Transaction{good},nil,[]*types.Receipt{receipt})
   if err!=nil{t.Fatal(err)}
   okCh:=make(chan *types.Block,1);okStop:=make(chan struct{})
   go func(){_ =engine.Seal(chain,honest,okCh,okStop)}()
   var accepted *types.Block
   select{case accepted=<-okCh:case <-time.After(15*time.Second):close(okStop);t.Fatal("C_HONEST_QBFT_SEAL_TIMEOUT")}
   if accepted==nil{t.Fatal("C_NIL_HONEST")}
   if _,err:=chain.InsertChain(types.Blocks{accepted});err!=nil{t.Fatalf("C_HONEST_BLOCK_IMPORT_FAIL %v",err)}
   final,err:=chain.State();if err!=nil{t.Fatal(err)}
   expected:=big.NewInt(tc.initial-tc.value-21000*price)
   if chain.CurrentBlock().Hash()!=accepted.Hash()||final.GetBalance(sender).Cmp(expected)!=0||
      final.GetBalance(recipient).Cmp(big.NewInt(tc.value))!=0||final.GetNonce(sender)!=1{
     t.Fatalf("C_HONEST_LEDGER_FAIL expected=%s observed=%s",expected,final.GetBalance(sender))
   }
   t.Logf("C_HONEST_CANONICAL_PASS seed=%d block=%s sender=%s nonce=1",tc.seed,accepted.Hash(),expected)
  })
 }
}
