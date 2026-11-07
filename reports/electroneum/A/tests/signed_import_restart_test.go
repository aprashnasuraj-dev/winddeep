package core

import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

// This test uses actual signed block generation and InsertChain with ethash faker.
// It is NOT a QBFT/IBFT canonical-finality or production reward proof.
func TestWorkerASignedImportRestartLedger(t *testing.T) {
 keyBytes:=make([]byte,32);keyBytes[31]=29
 key,err:=crypto.ToECDSA(keyBytes);if err!=nil {t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 recipient:=common.Address{0xa1}
 miner:=common.Address{0xa2}
 start:=big.NewInt(1000000000)
 cfg:=&params.ChainConfig{HomesteadBlock:big.NewInt(0)}
 for _,variation:=range []struct{name string; amount int64; include bool}{
  {"honest",7,true},{"boundary_zero",0,true},{"empty_control",0,false},
 } {
  t.Run(variation.name,func(t *testing.T){
   db:=rawdb.NewMemoryDatabase()
   genesisSpec:=&Genesis{Config:cfg,Alloc:GenesisAlloc{sender:{Balance:new(big.Int).Set(start)}}}
   genesis:=genesisSpec.MustCommit(db)
   engine:=ethash.NewFaker()
   blocks,_:=GenerateChain(cfg,genesis,engine,db,1,func(i int,g *BlockGen){
    g.SetCoinbase(miner)
    if variation.include {
     tx:=types.NewTransaction(0,recipient,big.NewInt(variation.amount),params.TxGas,big.NewInt(1),nil)
     signed,e:=types.SignTx(tx,types.HomesteadSigner{},key);if e!=nil{t.Fatal(e)}
     g.AddTx(signed)
    }
   })
   chain,e:=NewBlockChain(db,nil,cfg,engine,vm.Config{},nil,nil);if e!=nil{t.Fatal(e)}
   index,e:=chain.InsertChain(blocks);if e!=nil{t.Fatalf("insert %d: %v",index,e)}
   st,e:=chain.State();if e!=nil{t.Fatal(e)}
   expectedSender:=new(big.Int).Set(start)
   if variation.include {expectedSender.Sub(expectedSender,big.NewInt(variation.amount+21000))}
   if st.GetBalance(sender).Cmp(expectedSender)!=0 {t.Fatalf("sender mismatch got=%s expected=%s",st.GetBalance(sender),expectedSender)}
   if st.GetBalance(recipient).Cmp(big.NewInt(variation.amount))!=0 {t.Fatalf("recipient mismatch %s",st.GetBalance(recipient))}
   if st.GetNonce(sender)!=func()uint64{if variation.include{return 1};return 0}(){t.Fatal("nonce mismatch")}
   preSender:=new(big.Int).Set(st.GetBalance(sender))
   preRecipient:=new(big.Int).Set(st.GetBalance(recipient))
   preMiner:=new(big.Int).Set(st.GetBalance(miner))
   chain.Stop()
   reopened,e:=NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil);if e!=nil{t.Fatal(e)}
   defer reopened.Stop()
   if reopened.CurrentBlock().Hash()!=blocks[0].Hash(){t.Fatal("canonical head changed on restart")}
   after,e:=reopened.State();if e!=nil{t.Fatal(e)}
   if after.GetBalance(sender).Cmp(preSender)!=0 || after.GetBalance(recipient).Cmp(preRecipient)!=0 || after.GetBalance(miner).Cmp(preMiner)!=0 {t.Fatal("restart changed spendable ledger")}
   t.Logf("A_IMPORT_RESTART_HONEST name=%s sender=%s recipient=%s miner=%s",variation.name,preSender,preRecipient,preMiner)
  })
 }
}
