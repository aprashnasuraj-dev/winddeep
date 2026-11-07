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
 for _,variation:=range []struct{name string; amount int64; gasPrice int64; include bool; blocks int}{
  {"honest",7,1,true,1},{"boundary_zero",0,1,true,1},{"empty_control",0,1,false,1},{"two_block_replay",7,1,true,2},{"fee_boundary",7,2,true,2},{"zero_fee_boundary",7,0,true,2},
 } {
  t.Run(variation.name,func(t *testing.T){
   db:=rawdb.NewMemoryDatabase()
   genesisSpec:=&Genesis{Config:cfg,Alloc:GenesisAlloc{sender:{Balance:new(big.Int).Set(start)}}}
   genesis:=genesisSpec.MustCommit(db)
   engine:=ethash.NewFaker()
   blocks,_:=GenerateChain(cfg,genesis,engine,db,variation.blocks,func(i int,g *BlockGen){
    g.SetCoinbase(miner)
    if variation.include {
     tx:=types.NewTransaction(uint64(i),recipient,big.NewInt(variation.amount),params.TxGas,big.NewInt(variation.gasPrice),nil)
     signed,e:=types.SignTx(tx,types.HomesteadSigner{},key);if e!=nil{t.Fatal(e)}
     g.AddTx(signed)
    }
   })
   chain,e:=NewBlockChain(db,nil,cfg,engine,vm.Config{},nil,nil);if e!=nil{t.Fatal(e)}
   index,e:=chain.InsertChain(blocks);if e!=nil{t.Fatalf("insert %d: %v",index,e)}
   st,e:=chain.State();if e!=nil{t.Fatal(e)}
   expectedSender:=new(big.Int).Set(start)
   if variation.include {expectedSender.Sub(expectedSender,big.NewInt(int64(variation.blocks)*(variation.amount+21000*variation.gasPrice)))}
   if st.GetBalance(sender).Cmp(expectedSender)!=0 {t.Fatalf("sender mismatch got=%s expected=%s",st.GetBalance(sender),expectedSender)}
   if st.GetBalance(recipient).Cmp(big.NewInt(int64(variation.blocks)*variation.amount))!=0 {t.Fatalf("recipient mismatch %s",st.GetBalance(recipient))}
   // Independent conservation oracle: the sender/recipient pair must lose only
   // the transaction gas; the recipient may never gain unbacked spendable wei.
   pairTotal:=new(big.Int).Add(new(big.Int).Set(st.GetBalance(sender)),st.GetBalance(recipient))
   gasSpent:=big.NewInt(0)
   if variation.include {gasSpent.Mul(big.NewInt(int64(variation.blocks)),big.NewInt(21000*variation.gasPrice))}
   expectedPair:=new(big.Int).Sub(new(big.Int).Set(start),gasSpent)
   if pairTotal.Cmp(expectedPair)!=0 {t.Fatalf("independent pair conservation mismatch got=%s expected=%s",pairTotal,expectedPair)}
   if variation.include && st.GetBalance(miner).Cmp(gasSpent)<0 {t.Fatalf("miner below paid gas: got=%s minimum=%s",st.GetBalance(miner),gasSpent)}
   // Independent differential oracle: compare the fee recipient with a fresh
   // canonical empty-block sequence of identical length and consensus settings.
   // This cancels ordinary block rewards rather than assuming their magnitude.
   controlDB:=rawdb.NewMemoryDatabase()
   controlGenesis:=genesisSpec.MustCommit(controlDB)
   controlBlocks,_:=GenerateChain(cfg,controlGenesis,ethash.NewFaker(),controlDB,variation.blocks,func(_ int,g *BlockGen){g.SetCoinbase(miner)})
   controlChain,controlErr:=NewBlockChain(controlDB,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
   if controlErr!=nil {t.Fatal(controlErr)}
   controlIndex,controlErr:=controlChain.InsertChain(controlBlocks)
   if controlErr!=nil {controlChain.Stop();t.Fatalf("empty control insert %d: %v",controlIndex,controlErr)}
   controlState,controlErr:=controlChain.State()
   if controlErr!=nil {controlChain.Stop();t.Fatal(controlErr)}
   minerFeeDelta:=new(big.Int).Sub(new(big.Int).Set(st.GetBalance(miner)),controlState.GetBalance(miner))
   controlChain.Stop()
   if minerFeeDelta.Cmp(gasSpent)!=0 {t.Fatalf("miner fee differential mismatch got=%s expected=%s",minerFeeDelta,gasSpent)}
   t.Logf("A_IMPORT_RESTART_ORACLE name=%s miner_fee_delta=%s empty_block_control=true",variation.name,minerFeeDelta)

   // Independent total-spendable-balance oracle: transaction value moves between
   // accounts, fees move to miner, and only consensus issuance may increase supply.
   totalAfter:=new(big.Int).Add(new(big.Int).Set(pairTotal),st.GetBalance(miner))
   totalBefore:=new(big.Int).Set(start)
   minted:=new(big.Int).Sub(totalAfter,totalBefore)
   if minted.Sign()<0 {t.Fatalf("negative issuance despite conserved transaction value: %s",minted)}
   if variation.include && minerFeeDelta.Cmp(gasSpent)!=0 {t.Fatal("fee accounting disagrees with independent supply ledger")}
   t.Logf("A_IMPORT_RESTART_SUPPLY name=%s minted=%s fee=%s",variation.name,minted,gasSpent)
   t.Logf("A_IMPORT_RESTART_ORACLE name=%s pair=%s gas=%s",variation.name,pairTotal,gasSpent)
   if st.GetNonce(sender)!=func()uint64{if variation.include{return uint64(variation.blocks)};return 0}(){t.Fatal("nonce mismatch")}
   preSender:=new(big.Int).Set(st.GetBalance(sender))
   preRecipient:=new(big.Int).Set(st.GetBalance(recipient))
   preMiner:=new(big.Int).Set(st.GetBalance(miner))
   chain.Stop()
   reopened,e:=NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil);if e!=nil{t.Fatal(e)}
   defer reopened.Stop()
   if reopened.CurrentBlock().Hash()!=blocks[len(blocks)-1].Hash(){t.Fatal("canonical head changed on restart")}
   after,e:=reopened.State();if e!=nil{t.Fatal(e)}
   if after.GetNonce(sender)!=st.GetNonce(sender) {t.Fatal("restart changed sender nonce")}
   if after.GetBalance(sender).Cmp(preSender)!=0 || after.GetBalance(recipient).Cmp(preRecipient)!=0 || after.GetBalance(miner).Cmp(preMiner)!=0 {t.Fatal("restart changed spendable ledger")}
   t.Logf("A_IMPORT_RESTART_HONEST name=%s sender=%s recipient=%s miner=%s blocks=%d",variation.name,preSender,preRecipient,preMiner,variation.blocks)
  })
 }
 // Strongest signature defense: unsigned attacker bytes must not be accepted as
 // a valid Homestead-signed transaction. This is a pre-admission negative control,
 // NOT proof of QBFT block validation.
 unsigned:=types.NewTransaction(0,recipient,big.NewInt(7),params.TxGas,big.NewInt(1),nil)
 if _,err:=types.Sender(types.HomesteadSigner{},unsigned);err==nil {t.Fatal("unsigned transaction recovered a sender")}
 t.Log("A_IMPORT_RESTART_DEFENSE name=unsigned_rejected")
}
