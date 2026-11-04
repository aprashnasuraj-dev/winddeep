// Worker R production-depth P4: actual priority transaction block execution
// versus txpool admission at a registry-address + future-signature transition.
package core

import (
 "crypto/ecdsa"
 "math/big"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/accounts/abi"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/contracts/prioritytransactors"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/ethdb"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

func rPriorityRuntime(t *testing.T,pk common.PublicKey)[]byte{
 t.Helper()
 parsed,err:=abi.JSON(strings.NewReader(prioritytransactors.ETNPriorityTransactorsInterfaceMetaData.ABI));if err!=nil{t.Fatal(err)}
 metas:=[]prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{{IsGasPriceWaiver:true,PublicKey:common.Bytes2Hex(pk[:]),Name:"R-production-depth"}}
 out,err:=parsed.Methods["getTransactors"].Outputs.Pack(metas);if err!=nil{t.Fatal(err)}
 code:=[]byte{0x36,0x60,0x09,0x57,0x60,0x00,0x60,0x00,0xfd,0x5b}
 off:=len(code)+15;l:=len(out)
 code=append(code,0x61,byte(l>>8),byte(l),0x61,byte(off>>8),byte(off),0x60,0x00,0x39,0x61,byte(l>>8),byte(l),0x60,0x00,0xf3)
 return append(code,out...)
}

type rPriorityFixture struct{
 cfg *params.ChainConfig
 genesis *types.Block
 db ethdb.Database
 senderKey,oldPriorityKey,newPriorityKey *ecdsa.PrivateKey
 sender common.Address
 oldRegistry,newRegistry common.Address
 newPK common.PublicKey
 target common.Address
}

func rNewPriorityFixture(t *testing.T)*rPriorityFixture{
 t.Helper()
 senderKey,_:=crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
 oldKey,_:=crypto.HexToECDSA("3a1076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe266")
 newKey,_:=crypto.HexToECDSA("4a2076bf45ab87712ad64ccb3b10217737f7faacbf2872e88fdd9a537d8fe277")
 oldPK:=crypto.ECDSAPubkeyToPublicKey(oldKey.PublicKey);newPK:=crypto.ECDSAPubkeyToPublicKey(newKey.PublicKey)
 sender:=crypto.PubkeyToAddress(senderKey.PublicKey)
 oldRegistry:=common.HexToAddress("0x0000000000000000000000000000000000001001")
 newRegistry:=common.HexToAddress("0x0000000000000000000000000000000000002002")
 target:=common.HexToAddress("0x0000000000000000000000000000000000003003")
 cfg:=&params.ChainConfig{
  ChainID:big.NewInt(991),HomesteadBlock:big.NewInt(0),EIP150Block:big.NewInt(0),EIP155Block:big.NewInt(0),EIP158Block:big.NewInt(0),
  ByzantiumBlock:big.NewInt(0),ConstantinopleBlock:big.NewInt(0),PetersburgBlock:big.NewInt(0),IstanbulBlock:big.NewInt(0),
  BerlinBlock:big.NewInt(0),LondonBlock:big.NewInt(0),FutureForkBlock:big.NewInt(1),Ethash:new(params.EthashConfig),
  PriorityTransactorsContractAddress:oldRegistry,
  Transitions:[]params.Transition{{Block:big.NewInt(1),PriorityTransactorsContractAddress:newRegistry}},
 }
 db:=rawdb.NewMemoryDatabase()
 genesis:=(&Genesis{Config:cfg,GasLimit:8_000_000,BaseFee:big.NewInt(params.InitialBaseFee),Alloc:GenesisAlloc{
  sender:{Balance:new(big.Int).Mul(big.NewInt(1000),big.NewInt(1e18))},
  oldRegistry:{Code:rPriorityRuntime(t,oldPK)},
  newRegistry:{Code:rPriorityRuntime(t,newPK)},
 }}).MustCommit(db)
 return &rPriorityFixture{cfg:cfg,genesis:genesis,db:db,senderKey:senderKey,oldPriorityKey:oldKey,newPriorityKey:newKey,sender:sender,oldRegistry:oldRegistry,newRegistry:newRegistry,newPK:newPK,target:target}
}
func (f *rPriorityFixture)close(){if f.db!=nil{f.db.Close()}}
func rPriorityTx(t *testing.T,f *rPriorityFixture,nonce uint64,signer types.Signer,priorityKey *ecdsa.PrivateKey)*types.Transaction{
 t.Helper()
 tx,err:=types.SignNewPriorityTx(f.senderKey,priorityKey,signer,&types.PriorityTx{ChainID:f.cfg.ChainID,Nonce:nonce,GasTipCap:big.NewInt(0),GasFeeCap:big.NewInt(0),Gas:100_000,To:&f.target,Value:big.NewInt(1)})
 if err!=nil{t.Fatal(err)}
 return tx
}

func rBuildPriorityBlockOne(t *testing.T,f *rPriorityFixture)(*types.Block,*types.Transaction){
 t.Helper()
 var tx *types.Transaction
 blocks,_:=GenerateChain(f.cfg,f.genesis,ethash.NewFaker(),f.db,1,func(i int,b *BlockGen){
  transactors:=common.PriorityTransactorMap{f.newPK:{EntityName:"new-registry",IsGasPriceWaiver:true}}
  b.statedb.SetPriorityTransactors(transactors)
  tx=rPriorityTx(t,f,b.TxNonce(f.sender),types.MakeSigner(f.cfg,b.Number()),f.newPriorityKey)
  b.AddTx(tx)
 })
 return blocks[0],tx
}

func rExecutionAcceptsPriorityTransition(t *testing.T)(*rPriorityFixture,*BlockChain,*types.Block,*types.Transaction){
 t.Helper()
 f:=rNewPriorityFixture(t)
 block,tx:=rBuildPriorityBlockOne(t,f)
 chain,err:=NewBlockChain(f.db,nil,f.cfg,ethash.NewFaker(),vm.Config{},nil,nil)
 if err!=nil{f.close();t.Fatal(err)}
 if i,err:=chain.InsertChain(types.Blocks{block});err!=nil{chain.Stop();f.close();t.Fatalf("R_PRIORITY_EXECUTION_POSITIVE_CONTROL_FAIL index=%d err=%v",i,err)}
 receipts:=chain.GetReceiptsByHash(block.Hash())
 if len(receipts)!=1||receipts[0].TxHash!=tx.Hash()||receipts[0].Status!=types.ReceiptStatusSuccessful{chain.Stop();f.close();t.Fatalf("R_PRIORITY_EXECUTION_RECEIPT_CONTROL_FAIL receipts=%v",receipts)}
 state,err:=chain.StateAt(block.Root());if err!=nil{chain.Stop();f.close();t.Fatal(err)}
 if state.GetNonce(f.sender)!=1{chain.Stop();f.close();t.Fatalf("R_PRIORITY_EXECUTION_NONCE_FAIL got=%d",state.GetNonce(f.sender))}
 t.Log("R_PRIORITY_ACTUAL_BLOCK_EXECUTION_TRANSITION_PASS")
 return f,chain,block,tx
}

func TestRPriorityExecutionPoolCharacterization(t *testing.T){
 f,chain,block,tx:=rExecutionAcceptsPriorityTransition(t)
 defer chain.Stop();defer f.close()
 // Counterexample: old registry key must no longer hold privilege at block 1.
 state,err:=chain.StateAt(block.Root());if err!=nil{t.Fatal(err)}
 evm:=vm.NewEVM(NewEVMBlockContext(block.Header(),chain,nil),vm.TxContext{},state,f.cfg,vm.Config{})
 got:=GetPriorityTransactors(evm)
 if _,ok:=got[f.newPK];!ok{t.Fatal("R_PRIORITY_NEW_REGISTRY_NOT_ACTIVE")}
 oldPK:=crypto.ECDSAPubkeyToPublicKey(f.oldPriorityKey.PublicKey)
 if _,ok:=got[oldPK];ok{t.Fatal("R_PRIORITY_OLD_REGISTRY_STILL_ACTIVE")}
 // Build a separate pool at genesis, i.e. admitting exactly block 1.
 db2:=rawdb.NewMemoryDatabase();defer db2.Close()
 genesis2:=(&Genesis{Config:f.cfg,GasLimit:8_000_000,BaseFee:big.NewInt(params.InitialBaseFee),Alloc:GenesisAlloc{
  f.sender:{Balance:new(big.Int).Mul(big.NewInt(1000),big.NewInt(1e18))},
  f.oldRegistry:{Code:rPriorityRuntime(t,oldPK)},f.newRegistry:{Code:rPriorityRuntime(t,f.newPK)},
 }}).MustCommit(db2)
 chain2,err:=NewBlockChain(db2,nil,f.cfg,ethash.NewFaker(),vm.Config{},nil,nil);if err!=nil{t.Fatal(err)};defer chain2.Stop()
 _=genesis2
 pcfg:=DefaultTxPoolConfig;pcfg.Journal=""
 pool:=NewTxPool(pcfg,f.cfg,chain2);defer pool.Stop();<-pool.initDoneCh
 if !pool.futureFork{t.Fatal("R_PRIORITY_POOL_FUTURE_FORK_NOT_ACTIVE_FOR_NEXT_BLOCK")}
 if _,ok:=pool.currentPriorityTransactors[f.newPK];!ok{t.Fatal("R_PRIORITY_POOL_NEW_REGISTRY_NOT_LOADED")}
 err=pool.AddRemote(tx)
 if err!=nil{
  t.Logf("R_PRIORITY_POOL_EXECUTION_PARITY_MISMATCH err=%v",err)
 }else{
  t.Log("R_PRIORITY_POOL_EXECUTION_PARITY_PASS")
 }
}

func TestRPriorityExecutionPoolStrictParity(t *testing.T){
 f:=rNewPriorityFixture(t);defer f.close()
 _,tx:=rBuildPriorityBlockOne(t,f)
 chain,err:=NewBlockChain(f.db,nil,f.cfg,ethash.NewFaker(),vm.Config{},nil,nil);if err!=nil{t.Fatal(err)};defer chain.Stop()
 pcfg:=DefaultTxPoolConfig;pcfg.Journal=""
 pool:=NewTxPool(pcfg,f.cfg,chain);defer pool.Stop();<-pool.initDoneCh
 if err:=pool.AddRemote(tx);err!=nil{
  t.Fatalf("R_PRIORITY_POOL_EXECUTION_PARITY_MISMATCH: future-fork tx accepted by actual block execution fixture but rejected by txpool at the same next-block transition: %v",err)
 }
 t.Log("R_PRIORITY_POOL_EXECUTION_STRICT_PARITY_PASS")
}

func TestRPriorityReorgPoolState(t *testing.T){
 f,chain,oldBlock,oldTx:=rExecutionAcceptsPriorityTransition(t);defer chain.Stop();defer f.close()
 pcfg:=DefaultTxPoolConfig;pcfg.Journal=""
 pool:=NewTxPool(pcfg,f.cfg,chain);defer pool.Stop();<-pool.initDoneCh
 pending:=rPriorityTx(t,f,1,types.MakeSigner(f.cfg,big.NewInt(2)),f.newPriorityKey)
 addErr:=pool.AddRemote(pending)
 if addErr!=nil{t.Logf("R_PRIORITY_REORG_PRECONDITION_POOL_REJECT err=%v",addErr);return}
 fork,_:=GenerateChain(f.cfg,f.genesis,ethash.NewFaker(),f.db,2,func(i int,b *BlockGen){b.SetExtra([]byte{0xf0,byte(i)})})
 if i,err:=chain.InsertChain(fork);err!=nil{t.Fatalf("R_PRIORITY_REORG_IMPORT_FAIL index=%d err=%v",i,err)}
 <-pool.requestReset(oldBlock.Header(),chain.CurrentBlock().Header())
 if chain.CurrentBlock().Hash()!=fork[len(fork)-1].Hash(){t.Fatal("R_PRIORITY_REORG_FORK_NOT_CANONICAL")}
 if !pool.Has(pending.Hash()){t.Fatal("R_PRIORITY_REORG_PENDING_TX_LOST")}
 // Dropped block-1 priority tx should be eligible for reinjection only if the
 // pool's future-fork signer and transition registry agree with execution.
 if !pool.Has(oldTx.Hash()){t.Log("R_PRIORITY_REORG_DROPPED_EXECUTED_TX_NOT_REINJECTED")}
 if err:=validateTxPoolInternals(pool);err!=nil{t.Fatalf("R_PRIORITY_REORG_POOL_INVARIANT_FAIL: %v",err)}
 t.Logf("R_PRIORITY_REORG_POOL_STATE_PASS pending_nonce=%d has_dropped=%t",pool.Nonce(f.sender),pool.Has(oldTx.Hash()))
}
