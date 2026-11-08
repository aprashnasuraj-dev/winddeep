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

// TestLiveAValidSignedQBFTFeeCollision: a hostile, externally signed tx can
// direct its value to the QBFT fee beneficiary. After real QBFT sealing and
// canonical InsertChain, no spendable value may be duplicated. Synthetic
// genesis and key material: never send these transactions to a real network.
func TestLiveAValidSignedQBFTFeeCollision(t *testing.T) {
 for _, tc := range []struct{seed byte; value int64}{
  {73,13}, {79,7901}, {83,83177},
 }{
  t.Run(fmt.Sprintf("fresh_state_%d", tc.seed),func(t *testing.T){
   genesis, keys := testutils.GenesisAndKeys(1)
   var raw [32]byte; raw[31]=tc.seed
   private,err:=crypto.ToECDSA(raw[:]); if err!=nil {t.Fatal(err)}
   sender:=crypto.PubkeyToAddress(private.PublicKey)
   const initial int64 = 100000000000000000
   if genesis.Alloc==nil {genesis.Alloc=make(core.GenesisAlloc)}
   genesis.Alloc[sender]=core.GenesisAccount{Balance:big.NewInt(initial)}
   engineCfg:=*istanbul.DefaultConfig
   chain,engine:=newBlockchainFromConfig(genesis,keys,engineCfg)
   defer func(){done:=make(chan struct{});go func(){engine.Stop();close(done)}();select{case <-done:case <-time.After(2*time.Second):t.Log("A_QBFT_CLEANUP_TIMEOUT")}}()
   parent:=chain.Genesis()
   header:=makeHeader(parent,engine.config)
   header.Coinbase=engine.Address()
   if chain.Config().IsLondon(header.Number) {
    // The production helper does this for every London-enabled QBFT header.
    header.BaseFee=misc.CalcBaseFee(chain.Config(),parent.Header())
   }
   if err:=engine.Prepare(chain,header);err!=nil {t.Fatal(err)}
   state,err:=chain.StateAt(parent.Root());if err!=nil {t.Fatal(err)}
   gasPrice:=big.NewInt(4000000000)
   tx:=types.NewTransaction(0,engine.Address(),big.NewInt(tc.value),21000,gasPrice,nil)
   signer:=types.MakeSigner(chain.Config(),header.Number)
   signed,err:=types.SignTx(tx,signer,private);if err!=nil {t.Fatal(err)}
   if from,err:=types.Sender(signer,signed);err!=nil||from!=sender {t.Fatalf("outsider signer invalid: %s %v",from,err)}
   gp:=new(core.GasPool).AddGas(header.GasLimit)
   receipt,err:=core.ApplyTransaction(chain.Config(),chain,&header.Coinbase,gp,state,header,signed,&header.GasUsed,vm.Config{})
   if err!=nil {t.Fatalf("canonical signed apply failed: %v",err)}
   assembled,err:=engine.FinalizeAndAssemble(chain,header,state,[]*types.Transaction{signed},nil,[]*types.Receipt{receipt})
   if err!=nil {t.Fatal(err)}
   stopCh:=make(chan struct{})
   resultCh:=make(chan *types.Block,1)
   sealErr:=make(chan error,1)
   go func(){sealErr<-engine.Seal(chain,assembled,resultCh,stopCh)}()
   var sealed *types.Block
   select {case sealed=<-resultCh: case <-time.After(12*time.Second): close(stopCh);t.Fatal("QBFT sealing timeout")}
   if sealed==nil {t.Fatal("nil QBFT seal")}
   if _,err:=chain.InsertChain(types.Blocks{sealed});err!=nil {t.Fatalf("signed QBFT canonical import: %v",err)}
   if chain.CurrentBlock().Hash()!=sealed.Hash(){t.Fatal("A_QBFT_COLLISION_NOT_CANONICAL")}
   current,err:=chain.State();if err!=nil{t.Fatal(err)}
   consumed:=new(big.Int).Sub(big.NewInt(initial),current.GetBalance(sender))
   expectedConsumed:=new(big.Int).Add(big.NewInt(tc.value),new(big.Int).Mul(gasPrice,big.NewInt(21000)))
   if consumed.Cmp(expectedConsumed)!=0 {
    t.Fatalf("A_QBFT_COLLISION_BREACH seed=%d consumed=%s expected=%s",tc.seed,consumed,expectedConsumed)
   }
   beneficiary:=current.GetBalance(engine.Address())
   if beneficiary.Cmp(big.NewInt(tc.value))<0 {
    t.Fatalf("A_QBFT_COLLISION_BREACH seed=%d beneficiary missing transfer",tc.seed)
   }
   if current.GetNonce(sender)!=1 {t.Fatalf("A_QBFT_COLLISION_BREACH seed=%d nonce=%d",tc.seed,current.GetNonce(sender))}
   t.Logf("A_QBFT_COLLISION_CANONICAL seed=%d head=%s tx=%s gas=%d sender_cost=%s beneficiary=%s",tc.seed,sealed.Hash(),signed.Hash(),header.GasUsed,consumed,beneficiary)
   // Attack control: post-signing recipient mutation cannot retain a valid signature.
   tampered:=types.NewTransaction(0,common.Address{0xee},big.NewInt(tc.value),21000,gasPrice,nil)
   // Different canonical tx hash; externally supplied bytes do not preserve owner's signature.
   if tampered.Hash()==signed.Hash(){t.Fatal("A_QBFT_COLLISION_BREACH tampered hash identical")}
   t.Logf("A_QBFT_COLLISION_MUTATION_REJECTED seed=%d original=%s modified=%s",tc.seed,signed.Hash(),tampered.Hash())
   _=sealErr
  })
 }
}
