package miner

import (
 "errors"
 "fmt"
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/consensus/ethash"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

func TestCUnderIntrinsicMinerGasPoolAndRemoteAdmission(t *testing.T) {
 for _, tc := range []struct{seed byte; initial,value int64}{
  {53,100000000000000000,100},
  {59,110000000000000000,200},
  {61,120000000000000000,300},
 } {
  t.Run(fmt.Sprintf("state_%d",tc.seed),func(t *testing.T){
   var keyBytes [32]byte;keyBytes[31]=tc.seed
   key,err:=crypto.ToECDSA(keyBytes[:]);if err!=nil{t.Fatal(err)}
   sender:=crypto.PubkeyToAddress(key.PublicKey)
   recipient:=common.Address{0xb2};coinbase:=common.Address{0xb3}
   cfg:=new(params.ChainConfig);*cfg=*params.AllEthashProtocolChanges;cfg.LondonBlock=big.NewInt(0)
   if cfg.ChainID==nil{t.Fatal("nil chain ID")}
   engine:=ethash.NewFaker();defer engine.Close()
   db:=rawdb.NewMemoryDatabase()
   genesis:=core.Genesis{Config:cfg,Alloc:core.GenesisAlloc{sender:{Balance:big.NewInt(tc.initial)}}}
   genesisBlock:=genesis.MustCommit(db)
   chain,err:=core.NewBlockChain(db,&core.CacheConfig{TrieDirtyDisabled:true},cfg,engine,vm.Config{},nil,nil)
   if err!=nil{t.Fatal(err)};defer chain.Stop()
   newEnv:=func()*environment{
    st,e:=chain.StateAt(genesisBlock.Root());if e!=nil{t.Fatal(e)}
    header:=&types.Header{Number:big.NewInt(1),ParentHash:genesisBlock.Hash(),GasLimit:40000,Difficulty:big.NewInt(1),BaseFee:big.NewInt(params.InitialBaseFee),Coinbase:coinbase}
    return &environment{state:st,header:header,coinbase:coinbase,gasPool:new(core.GasPool).AddGas(40000)}
   }
   signer:=types.NewLondonSigner(cfg.ChainID)
   sign:=func(gas uint64)*types.Transaction{
    tx,e:=types.SignNewTx(key,signer,&types.DynamicFeeTx{ChainID:cfg.ChainID,Nonce:0,GasTipCap:big.NewInt(params.InitialBaseFee),GasFeeCap:new(big.Int).Mul(big.NewInt(params.InitialBaseFee),big.NewInt(2)),Gas:gas,To:&recipient,Value:big.NewInt(tc.value)})
    if e!=nil{t.Fatal(e)};return tx
   }
   bad,good:=sign(20999),sign(21000)
   pool:=core.NewTxPool(core.DefaultTxPoolConfig,cfg,chain);defer pool.Stop()
   if e:=pool.AddRemote(bad);!errors.Is(e,core.ErrIntrinsicGas){t.Fatalf("C_REMOTE_UNDERINTRINSIC_UNEXPECTED error=%v",e)}
   // eth_sendRawTransaction -> EthAPIBackend.SendTx -> TxPool.AddLocal.
   // Local RPC admission must preserve the same intrinsic-gas validation.
   if e:=pool.AddLocal(bad);!errors.Is(e,core.ErrIntrinsicGas){t.Fatalf("C_RPC_LOCAL_UNDERINTRINSIC_UNEXPECTED error=%v",e)}
   if pool.Get(bad.Hash())!=nil{t.Fatal("C_INVALID_TX_PRESENT_IN_POOL")}
   if e:=pool.AddRemote(good);e!=nil{t.Fatalf("C_REMOTE_HONEST_FAIL %v",e)}
   t.Logf("C_REMOTE_GUARD_PASS seed=%d p2p_rejected=true rpc_local_rejected=true honest_accepted=true",tc.seed)
   // Deliberate internal injection bypassing the public txpool; NOT an external exploit.
   w:=&worker{chain:chain,chainConfig:cfg};env:=newEnv()
   before:=new(big.Int).Set(env.state.GetBalance(sender))
   _,e:=w.commitTransaction(env,bad)
   if !errors.Is(e,core.ErrIntrinsicGas){t.Fatalf("C_MINER_DIRECT_REJECTION_UNEXPECTED %v",e)}
   if env.state.GetBalance(sender).Cmp(before)!=0||env.state.GetNonce(sender)!=0||env.state.GetBalance(recipient).Sign()!=0{t.Fatal("C_MINER_STATE_SNAPSHOT_BREACH")}
   if env.gasPool.Gas()!=40000-20999{t.Fatalf("C_MINER_GASPOOL_EXPECTED_LEAK got=%d",env.gasPool.Gas())}
   if len(env.txs)!=0||len(env.receipts)!=0{t.Fatal("rejected tx included in proposed block")}
   _,e=w.commitTransaction(env,good)
   if !errors.Is(e,core.ErrGasLimitReached){t.Fatalf("C_FOLLOWUP_UNEXPECTED error=%v remaining=%d",e,env.gasPool.Gas())}
   baseline:=newEnv()
   if _,e=w.commitTransaction(baseline,good);e!=nil{t.Fatalf("C_FRESH_CONTROL_FAILED %v",e)}
   if baseline.state.GetNonce(sender)!=1||baseline.state.GetBalance(recipient).Cmp(big.NewInt(tc.value))!=0||len(baseline.txs)!=1{t.Fatal("C_FRESH_CONTROL_ACCOUNTING_BAD")}
   t.Logf("C_MINER_GASPOOL_LEAK seed=%d rejected_gas=20999 remaining=%d followup_rejected=true fresh_control_accepted=true state_reverted=true",tc.seed,env.gasPool.Gas())
  })
 }
}
