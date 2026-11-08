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

// TestWorkerAFeeRecipientCollision probes whether a sender-selected transfer
// destination equal to the fee beneficiary causes duplicated spendable value.
// Ethash faker is a component-path probe, NEVER evidence of QBFT admission.
func TestWorkerAFeeRecipientCollision(t *testing.T) {
 keyBytes:=make([]byte,32);keyBytes[31]=83
 key,err:=crypto.ToECDSA(keyBytes);if err!=nil {t.Fatal(err)}
 sender:=crypto.PubkeyToAddress(key.PublicKey)
 beneficiary:=common.Address{0xb3}
 separate:=common.Address{0xb4}
 cfg:=&params.ChainConfig{HomesteadBlock:big.NewInt(0)}
 for _,tc:=range []struct{name string; balance,amount,price int64; collide bool}{
  {"honest_separate",1000000,13,2,false},
  {"attacker_collision",1000000,13,2,true},
  {"zero_price_collision",1000000,13,0,true},
  {"exact_balance_collision",21013,13,1,true},
 } {
  t.Run(tc.name,func(t *testing.T){
   db:=rawdb.NewMemoryDatabase()
   spec:=&Genesis{Config:cfg,Alloc:GenesisAlloc{sender:{Balance:big.NewInt(tc.balance)}}}
   genesis:=spec.MustCommit(db)
   target:=separate
   if tc.collide {target=beneficiary}
   blocks,_:=GenerateChain(cfg,genesis,ethash.NewFaker(),db,1,func(i int,g *BlockGen){
    g.SetCoinbase(beneficiary)
    tx:=types.NewTransaction(0,target,big.NewInt(tc.amount),params.TxGas,big.NewInt(tc.price),nil)
    signed,e:=types.SignTx(tx,types.HomesteadSigner{},key);if e!=nil {t.Fatal(e)}
    g.AddTx(signed)
   })
   chain,e:=NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil);if e!=nil {t.Fatal(e)}
   defer chain.Stop()
   if idx,e:=chain.InsertChain(blocks);e!=nil {t.Fatalf("A_COLLISION_IMPORT_ERROR case=%s idx=%d err=%v",tc.name,idx,e)}
   st,e:=chain.State();if e!=nil {t.Fatal(e)}
   if chain.CurrentBlock().Hash()!=blocks[0].Hash() {t.Fatal("noncanonical import")}
   fee:=big.NewInt(21000*tc.price)
   expectedSender:=new(big.Int).Sub(big.NewInt(tc.balance),new(big.Int).Add(big.NewInt(tc.amount),fee))
   if st.GetBalance(sender).Cmp(expectedSender)!=0 {t.Fatalf("A_COLLISION_BREACH case=%s sender expected=%s actual=%s",tc.name,expectedSender,st.GetBalance(sender))}
   // Independent empty-block baseline cancels consensus issuance.
   controlDB:=rawdb.NewMemoryDatabase()
   controlGenesis:=spec.MustCommit(controlDB)
   empty,_:=GenerateChain(cfg,controlGenesis,ethash.NewFaker(),controlDB,1,func(_ int,g *BlockGen){g.SetCoinbase(beneficiary)})
   control,e:=NewBlockChain(controlDB,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil);if e!=nil {t.Fatal(e)}
   defer control.Stop()
   if _,e:=control.InsertChain(empty);e!=nil {t.Fatal(e)}
   baseline,e:=control.State();if e!=nil {t.Fatal(e)}
   expectedBeneficiary:=new(big.Int).Add(new(big.Int).Set(baseline.GetBalance(beneficiary)),fee)
   if tc.collide {expectedBeneficiary.Add(expectedBeneficiary,big.NewInt(tc.amount))}
   if st.GetBalance(beneficiary).Cmp(expectedBeneficiary)!=0 {t.Fatalf("A_COLLISION_BREACH case=%s beneficiary expected=%s actual=%s",tc.name,expectedBeneficiary,st.GetBalance(beneficiary))}
   if !tc.collide && st.GetBalance(separate).Cmp(big.NewInt(tc.amount))!=0 {t.Fatalf("A_COLLISION_BREACH case=%s separate recipient",tc.name)}
   total:=new(big.Int).Add(new(big.Int).Set(st.GetBalance(sender)),st.GetBalance(beneficiary))
   total.Add(total,st.GetBalance(separate))
   baselineTotal:=new(big.Int).Add(new(big.Int).Set(baseline.GetBalance(sender)),baseline.GetBalance(beneficiary))
   if total.Cmp(baselineTotal)!=0 {t.Fatalf("A_COLLISION_BREACH case=%s total expected=%s actual=%s",tc.name,baselineTotal,total)}
   if st.GetNonce(sender)!=1 {t.Fatalf("A_COLLISION_BREACH case=%s nonce=%d",tc.name,st.GetNonce(sender))}
   t.Logf("A_COLLISION_ORACLE case=%s fee=%s value=%d sender=%s beneficiary=%s conserved=true nonce=1",tc.name,fee,tc.amount,st.GetBalance(sender),st.GetBalance(beneficiary))
  })
 }
}
