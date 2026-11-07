// Cross-boundary synthetic signed-transaction sequence regression.
// Actual shipped ApplyTransaction/StateDB execution; NO consensus-valid QBFT
// block, live peer, public chain or production key is involved.
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
    "github.com/electroneum/electroneum-sc/params"
)

func TestAdversarialSignedStateMachine(t *testing.T) {
    keyBytes := make([]byte, 32)
    keyBytes[31] = 17 // disposable known fixture, never a real wallet
    key, err := crypto.ToECDSA(keyBytes)
    if err != nil { t.Fatal(err) }
    sender := crypto.PubkeyToAddress(key.PublicKey)
    recipient := common.Address{0x71}
    miner := common.Address{0x72}
    const chainID int64 = 1337
    const gasLimit uint64 = 21000
    const startingWei int64 = 10000000
    cfg := &params.ChainConfig{
        ChainID: big.NewInt(chainID), LondonBlock: big.NewInt(0),
        BerlinBlock: big.NewInt(0), EIP155Block: big.NewInt(0),
        ByzantiumBlock: big.NewInt(0),
    }
    st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
    if err != nil { t.Fatal(err) }
    st.SetBalance(sender, big.NewInt(startingWei))
    header := &types.Header{
        Number: big.NewInt(1), Difficulty: big.NewInt(1),
        GasLimit: 1000000, BaseFee: big.NewInt(8),
    }
    used := uint64(0)
    signed := func(nonce uint64, domain int64, amount int64) *types.Transaction {
        t.Helper()
        signingCfg := &params.ChainConfig{
            ChainID: big.NewInt(domain), LondonBlock: big.NewInt(0),
            BerlinBlock: big.NewInt(0), EIP155Block: big.NewInt(0),
            ByzantiumBlock: big.NewInt(0),
        }
        signer := types.MakeSigner(signingCfg, big.NewInt(1))
        transaction, e := types.SignNewTx(key, signer, &types.DynamicFeeTx{
            ChainID: big.NewInt(domain), Nonce: nonce,
            GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(10),
            Gas: gasLimit, To: &recipient, Value: big.NewInt(amount),
        })
        if e != nil { t.Fatalf("sign: %v", e) }
        wire, e := transaction.MarshalBinary()
        if e != nil { t.Fatalf("marshal: %v", e) }
        var decoded types.Transaction
        if e = decoded.UnmarshalBinary(wire); e != nil { t.Fatalf("decode: %v", e) }
        return &decoded
    }
    apply := func(tx *types.Transaction) (*types.Receipt, error) {
        return ApplyTransaction(cfg, nil, &miner, new(GasPool).AddGas(gasLimit),
            st, header, tx, &used, vm.Config{})
    }
    snapshot := func() (string, string, string, uint64, uint64) {
        return st.GetBalance(sender).String(), st.GetBalance(recipient).String(),
            st.GetBalance(miner).String(), st.GetNonce(sender), used
    }
    rejectWithoutMutation := func(label string, tx *types.Transaction) {
        t.Helper()
        a,b,c,n,g := snapshot()
        receipt,e := apply(tx)
        if e == nil || receipt != nil {
            t.Fatalf("%s: invalid transaction accepted receipt=%v err=%v", label, receipt, e)
        }
        aa,bb,cc,nn,gg := snapshot()
        if a!=aa || b!=bb || c!=cc || n!=nn || g!=gg {
            t.Fatalf("%s: rejection mutated balances/nonce/gas: before=%s,%s,%s,%d,%d after=%s,%s,%s,%d,%d",
                label,a,b,c,n,g,aa,bb,cc,nn,gg)
        }
        t.Logf("%s error=%v",label,e)
    }

    valid0 := signed(0, chainID, 1000)
    signer := types.MakeSigner(cfg, big.NewInt(1))
    if recovered,e := types.Sender(signer, valid0); e!=nil || recovered!=sender {
        t.Fatalf("valid origin mismatch: %s %v",recovered,e)
    }
    receipt0,e := apply(valid0)
    if e != nil || receipt0 == nil || receipt0.Status != types.ReceiptStatusSuccessful {
        t.Fatalf("valid nonce 0 rejected: receipt=%v err=%v", receipt0,e)
    }
    if st.GetNonce(sender)!=1 || used!=gasLimit ||
        st.GetBalance(sender).Cmp(big.NewInt(startingWei-1000-210000))!=0 ||
        st.GetBalance(recipient).Cmp(big.NewInt(1000))!=0 ||
        st.GetBalance(miner).Cmp(big.NewInt(42000))!=0 {
        t.Fatalf("valid nonce 0 broke state accounting: %v",snapshotFailure(st,sender,recipient,miner))
    }

    rejectWithoutMutation("ADVERSARIAL_REPLAY_REJECTED",valid0)
    rejectWithoutMutation("ADVERSARIAL_WRONG_CHAIN_REJECTED",signed(1,chainID+1,2000))
    rejectWithoutMutation("ADVERSARIAL_INSUFFICIENT_REJECTED",signed(1,chainID,startingWei+1))

    receipt1,e := apply(signed(1,chainID,2000))
    if e != nil || receipt1 == nil || receipt1.Status!=types.ReceiptStatusSuccessful {
        t.Fatalf("valid nonce 1 rejected: receipt=%v err=%v",receipt1,e)
    }
    if st.GetNonce(sender)!=2 || used!=2*gasLimit ||
        st.GetBalance(sender).Cmp(big.NewInt(startingWei-3000-420000))!=0 ||
        st.GetBalance(recipient).Cmp(big.NewInt(3000))!=0 ||
        st.GetBalance(miner).Cmp(big.NewInt(84000))!=0 {
        t.Fatalf("valid nonce 1 ledger mismatch: %v",snapshotFailure(st,sender,recipient,miner))
    }
    finalTotal:=new(big.Int).Add(st.GetBalance(sender),st.GetBalance(recipient))
    finalTotal.Add(finalTotal,st.GetBalance(miner))
    if finalTotal.Cmp(big.NewInt(startingWei-336000))!=0 {
        t.Fatalf("gas burn / supply conservation invalid: got=%s expected=%d",finalTotal,startingWei-336000)
    }
    t.Logf("ADVERSARIAL_SEQUENCE_VALID_PASS nonce=2 spent_value=3000 gas=42000 burned_wei=336000 remaining_total_wei=%s",finalTotal)
}

func snapshotFailure(st *state.StateDB,sender,recipient,miner common.Address) string {
    return "sender="+st.GetBalance(sender).String()+
        " recipient="+st.GetBalance(recipient).String()+
        " miner="+st.GetBalance(miner).String()
}
