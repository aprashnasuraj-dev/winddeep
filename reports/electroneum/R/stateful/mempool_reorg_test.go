// Worker R: real TxPool admission and revalidation across state-reorg resets.
// Scratch-only tests in package core. Uses the certified production TxPool,
// StateDB and signature verification, plus the source's existing test chain.
// No production node, wallet, funds or network. Does not equate a mock
// StateDB reset with an end-to-end consensus reorganization.
package core

import (
 "errors"
 "math/big"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/event"
)

func auditRSetPoolChainState(t *testing.T,pool *TxPool,addr common.Address,nonce uint64,balance int64){
 t.Helper()
 st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil)
 if err!=nil{t.Fatalf("mock canonical state construction: %v",err)}
 st.SetNonce(addr,nonce)
 st.SetBalance(addr,big.NewInt(balance))
 bc:=&testBlockChain{
  gasLimit:10_000_000,statedb:st,chainHeadFeed:new(event.Feed),
  priorityType:NoPriorityTx,priorityTransactorMapCache:common.PriorityTransactorMap{},
 }
 // The pool reset loop consults pool.chain under pool.mu.
 pool.mu.Lock()
 pool.chain=bc
 pool.mu.Unlock()
 done:=pool.requestReset(nil,nil)
 select{case <-done:case <-time.After(3*time.Second):t.Fatal("R_POOL_REORG_RESET_DEADLOCK")}
}

func auditRPoolReorgScenario(t *testing.T,script []byte){
 t.Helper()
 if len(script)>32{return}
 pool,key:=setupTxPool()
 defer pool.Stop()
 addr:=crypto.PubkeyToAddress(key.PublicKey)
 const funded=int64(1_000_000_000_000)
 auditRSetPoolChainState(t,pool,addr,0,funded)
 txs:=make([]*types.Transaction,6)
 for i:=range txs{txs[i]=transaction(uint64(i),100000,key)}
 admitted:=pool.AddRemotesSync(txs[:4])
 if len(admitted)!=4{t.Fatalf("R_POOL_ADMISSION_COUNT: %d",len(admitted))}
 for i,err:=range admitted{if err!=nil{t.Fatalf("R_POOL_VALID_SIGNED_TX_REJECTED: nonce=%d err=%v",i,err)}}
 if got:=pool.Nonce(addr);got!=4{t.Fatalf("R_POOL_PENDING_NONCE_INITIAL=%d want=4",got)}
 // A signed transaction from a foreign replay domain is invalid regardless
 // of post-reorg account nonce, balance or mempool policy.
 foreign,err:=types.SignTx(types.NewTransaction(5,common.Address{},big.NewInt(1),100000,big.NewInt(1),nil),types.NewEIP155Signer(big.NewInt(999999)),key)
 if err!=nil{t.Fatal(err)}
 if len(script)==0{script=[]byte{0,1,2,3,4,5,6,7}}
 for step,raw:=range script{
  nonce:=uint64(raw%5)
  balance:=funded
  if raw&0x8!=0{balance=0}
  auditRSetPoolChainState(t,pool,addr,nonce,balance)
  pool.mu.RLock()
  validErr:=pool.validateTx(txs[nonce],false)
  foreignErr:=pool.validateTx(foreign,false)
  var staleErr error
  if nonce>0{staleErr=pool.validateTx(txs[nonce-1],false)}
  pool.mu.RUnlock()
  if balance==0{
   if !errors.Is(validErr,ErrInsufficientFunds){t.Fatalf("R_POOL_BALANCE_REORG_BYPASS: step=%d nonce=%d got=%v",step,nonce,validErr)}
  }else if validErr!=nil {
   t.Fatalf("R_POOL_FUNDED_CANONICAL_VALIDATION_REJECTED: step=%d nonce=%d err=%v",step,nonce,validErr)
  }
  if nonce>0&&!errors.Is(staleErr,ErrNonceTooLow){
   t.Fatalf("R_POOL_STALE_NONCE_ACCEPTED_AFTER_REORG: step=%d nonce=%d err=%v",step,nonce,staleErr)
  }
  if !errors.Is(foreignErr,ErrInvalidSender){
   t.Fatalf("R_POOL_FOREIGN_CHAIN_SIGNATURE_ACCEPTED: step=%d got=%v",step,foreignErr)
  }
  if got:=pool.Nonce(addr);got<nonce{
   t.Fatalf("R_POOL_NONCE_REGRESSION: step=%d headNonce=%d poolNonce=%d",step,nonce,got)
  }
  // An imported transaction below the new canonical nonce must not remain
  // discoverable in the pool after synchronous reset/revalidation.
  for j:=uint64(0);j<nonce&&j<4;j++{
   if pool.Has(txs[j].Hash()){
    t.Fatalf("R_POOL_STALE_TX_RETAINED: step=%d canonicalNonce=%d staleTxNonce=%d",step,nonce,j)
   }
  }
  if err:=validateTxPoolInternals(pool);err!=nil{
   t.Fatalf("R_POOL_INDEX_REORG_INVARIANT_FAIL: step=%d err=%v",step,err)
  }
 }
 t.Logf("R_POOL_STATEFUL_REVALIDATION_PASS transitions=%d",len(script))
}
func TestRPoolReorgTransitions(t *testing.T){
 for _,seq:=range [][]byte{{0,1,2,3,4,0},{0,8,9,10,1,2,3},{4,3,2,1,0},{12,9,3,8,0,4}}{
  auditRPoolReorgScenario(t,seq)
 }
}
func FuzzRPoolReorgSequences(f *testing.F){
 f.Add([]byte{0,1,2,3,4,0})
 f.Add([]byte{12,9,3,8,0,4})
 f.Add([]byte{4,3,2,1,0})
 f.Fuzz(func(t *testing.T,script []byte){
  if len(script)>64{return}
  auditRPoolReorgScenario(t,script)
 })
}
