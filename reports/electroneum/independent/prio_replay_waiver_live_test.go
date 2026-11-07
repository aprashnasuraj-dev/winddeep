package core

import (
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/event"
)

// Independent end-to-end negative security invariant: an unauthorised sender
// must not obtain priority gas waiver by copying a second signature from a
// valid priority transaction. No public nodes or live funds are contacted.
// The victim, attacker and privilege-bearing test key are all synthetic.
func TestIndependentPriorityReplayWaiverPoolAndExecution(t *testing.T) {
  cfg := eip1559Config // test's London-at-genesis fork config
  height := big.NewInt(1)
  if cfg.IsFutureFork(height) { t.Fatal("requires production-like pre-FutureFork config") }
  signer := types.MakeSigner(cfg, height)
  authorizedPublicKey := crypto.ECDSAPubkeyToPublicKey(priorityPrivateKeys[0].PublicKey)
  const baseFee = int64(1000000000)

  for seed:=0;seed<3;seed++ {
    t.Run(string(rune('A'+seed)),func(t *testing.T){
      victim,err:=crypto.GenerateKey();if err!=nil{t.Fatal(err)}
      attacker,err:=crypto.GenerateKey();if err!=nil{t.Fatal(err)}
      attackerAddress:=crypto.PubkeyToAddress(attacker.PublicKey)
      recipient:=common.HexToAddress("0x0000000000000000000000000000000000000089")
      txData:=&types.PriorityTx{
        ChainID:new(big.Int).Set(cfg.ChainID),Nonce:0,GasTipCap:big.NewInt(0),
        GasFeeCap:big.NewInt(0),Gas:21000,To:&recipient,Value:big.NewInt(0),
      }
      legitimate,err:=types.SignNewPriorityTx(victim,priorityPrivateKeys[0],signer,txData)
      if err!=nil{t.Fatal(err)}
      pV,pR,pS:=legitimate.RawPrioritySignatureValues()
      if pV==nil||pR==nil||pS==nil{t.Fatal("missing legitimate privilege signature")}

      // Attack reconstruction uses ONLY publicly readable priority V/R/S and
      // the attacker's private sender key, not the priority private key.
      forgedBody:=&types.PriorityTx{
        ChainID:new(big.Int).Set(cfg.ChainID),Nonce:0,GasTipCap:big.NewInt(0),
        GasFeeCap:big.NewInt(0),Gas:21000,To:&recipient,Value:big.NewInt(0),
        PriorityV:new(big.Int).Set(pV),PriorityR:new(big.Int).Set(pR),PriorityS:new(big.Int).Set(pS),
      }
      forged,err:=types.SignNewTx(attacker,signer,forgedBody)
      if err!=nil{t.Fatal(err)}
      from,err:=types.Sender(signer,forged)
      if err!=nil||from!=attackerAddress{t.Fatalf("attacker sender mismatch addr=%s err=%v",from,err)}
      sponsor,err:=types.PrioritySender(signer,forged)
      if err!=nil||sponsor!=authorizedPublicKey{t.Fatalf("priority replay rejected: match=%t err=%v",sponsor==authorizedPublicKey,err)}
      if !forged.HasZeroFee(){t.Fatal("replayed priority transaction unexpectedly charges fees")}

      db:=rawdb.NewMemoryDatabase()
      st,err:=state.New(common.Hash{},state.NewDatabase(db),nil)
      if err!=nil{t.Fatal(err)}
      chain:=&testBlockChain{10000000,st,new(event.Feed),WaiverPriorityTx,common.PriorityTransactorMap{},nil}
      pool:=NewTxPool(testTxPoolConfig,cfg,chain)
      <-pool.initDoneCh
      pool.priced.urgent.baseFee=big.NewInt(baseFee)
      if st.GetBalance(attackerAddress).Sign()!=0{t.Fatal("unfunded attacker fixture invalid")}
      if err:=pool.AddRemote(forged);err!=nil{
        pool.Stop()
        t.Fatalf("remote txpool refused cloned priority signature seed=%d: %v",seed,err)
      }
      if err:=validateTxPoolInternals(pool);err!=nil{pool.Stop();t.Fatalf("pool invariants: %v",err)}
      pool.Stop()
      t.Logf("PRIORITY_REPLAY_POOL seed=%d attacker_unfunded=true external_priority_signature_reused=true fee=0",seed)

      // Reproduce actual core execution, not only signature parsing or pool
      // acceptance. The state transactor set models the authorized contract
      // output; no production credential, contract or network is accessed.
      st.SetPriorityTransactors(chain.GetPriorityTransactorsForState(nil,st))
      header:=&types.Header{Number:height,GasLimit:10000000,BaseFee:big.NewInt(baseFee),Difficulty:big.NewInt(1)}
      miner:=common.HexToAddress("0x0000000000000000000000000000000000000099")
      var used uint64
      receipt,err:=ApplyTransaction(cfg,nil,&miner,new(GasPool).AddGas(21000),st,header,forged,&used,vm.Config{})
      if err!=nil{t.Fatalf("replayed priority transaction could not execute seed=%d: %v",seed,err)}
      if receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful||receipt.GasUsed!=21000{
        t.Fatalf("wrong replay execution receipt seed=%d: %+v",seed,receipt)
      }
      if st.GetNonce(attackerAddress)!=1||st.GetBalance(attackerAddress).Sign()!=0||
         st.GetBalance(miner).Sign()!=0||used!=21000{
        t.Fatalf("fee or sender-state oracle mismatch seed=%d nonce=%d sender=%s miner=%s gas=%d",
          seed,st.GetNonce(attackerAddress),st.GetBalance(attackerAddress),st.GetBalance(miner),used)
      }
      t.Logf("PRIORITY_REPLAY_EXECUTION seed=%d signer=attacker sponsor=reused allowed_gas=21000 paid_gas_wei=0 sender_balance_wei=0 nonce=1 receipt_success=true",seed)

      // A sender-bound post-fork signature must not be reusable under a
      // changed sender signature. This does not prove fork activation.
      futureSigner:=types.NewFutureForkSigner(cfg.ChainID)
      futureLegitimate,err:=types.SignNewPriorityTx(victim,priorityPrivateKeys[0],futureSigner,txData)
      if err!=nil{t.Fatal(err)}
      fV,fR,fS:=futureLegitimate.RawPrioritySignatureValues()
      futureBody:=&types.PriorityTx{
        ChainID:new(big.Int).Set(cfg.ChainID),Nonce:0,GasTipCap:big.NewInt(0),
        GasFeeCap:big.NewInt(0),Gas:21000,To:&recipient,Value:big.NewInt(0),
        PriorityV:new(big.Int).Set(fV),PriorityR:new(big.Int).Set(fR),PriorityS:new(big.Int).Set(fS),
      }
      changedSender,err:=types.SignNewTx(attacker,futureSigner,futureBody)
      if err!=nil{t.Fatal(err)}
      recovered,err:=types.PrioritySender(futureSigner,changedSender)
      if err==nil&&recovered==authorizedPublicKey{t.Fatal("post-fork binding unexpectedly accepted cloned priority key")}
      t.Logf("PRIORITY_REPLAY_POSTFORK_DEFENSE seed=%d cloned_privilege_rejected=true",seed)
    })
  }
}
