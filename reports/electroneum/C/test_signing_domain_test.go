// Test copied into scratch certified Electroneum core/types by Worker C CI.
// Synthetic keys and transactions only; never broadcast to any chain.
package types

import (
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/crypto"
)

func TestWorkerCChainDomainAndAuthorization(t *testing.T) {
    key, err := crypto.HexToECDSA("0c28fca386c7a22798d919f56938b5d1be56451eae0f9d6f74ddc89348e16ee1")
    if err != nil { t.Fatal(err) }
    owner := crypto.PubkeyToAddress(key.PublicKey)
    recipient := common.HexToAddress("0x00000000000000000000000000000000000000c1")
    movedRecipient := common.HexToAddress("0x00000000000000000000000000000000000000c2")
    signer := NewEIP155Signer(big.NewInt(52014))
    tx := NewTransaction(4, recipient, big.NewInt(100), 21000, big.NewInt(1), nil)
    signed, err := SignTx(tx, signer, key)
    if err != nil { t.Fatal(err) }
    got, err := Sender(signer, signed)
    if err != nil || got != owner || !signed.Protected() {
        t.Fatalf("authorized signing baseline rejected: got=%s want=%s err=%v", got, owner, err)
    }
    t.Log("WORKER_C_AUTHORIZED_BASELINE_PASS")
    if got, err = Sender(NewEIP155Signer(big.NewInt(52015)), signed); err == nil {
        t.Fatalf("wrong-chain replay accepted: recovered=%s", got)
    }
    t.Log("WORKER_C_WRONG_CHAIN_REJECTED")

    v,r,s := signed.RawSignatureValues()
    variants := []struct{name string; nonce uint64; to common.Address; amount int64}{
        {"value_changed",4,recipient,101},
        {"recipient_changed",4,movedRecipient,100},
        {"nonce_changed",5,recipient,100},
    }
    for _, tc := range variants {
        t.Run(tc.name,func(t *testing.T){
            forged := NewTx(&LegacyTx{
                Nonce:tc.nonce, To:&tc.to, Value:big.NewInt(tc.amount),
                Gas:21000, GasPrice:big.NewInt(1),
                V:new(big.Int).Set(v),R:new(big.Int).Set(r),S:new(big.Int).Set(s),
            })
            got,err:=Sender(signer,forged)
            if err==nil && got==owner{
                t.Fatalf("changed tx incorrectly authenticated as original owner: %s",got)
            }
            t.Log("WORKER_C_SIGNATURE_BINDING_REJECTED")
        })
    }
    malformed:=NewTx(&LegacyTx{
        Nonce:4,To:&recipient,Value:big.NewInt(100),Gas:21000,
        GasPrice:big.NewInt(1),V:new(big.Int).Set(v),R:big.NewInt(0),S:new(big.Int).Set(s),
    })
    if from,err:=Sender(signer,malformed);err==nil{
        t.Fatalf("zero-R signature accepted as %s",from)
    }
    t.Log("WORKER_C_MALFORMED_SIGNATURE_REJECTED")
}

 
// Coverage-guided, synthetic-only transaction signing attack surface.
// Fuzzing varies value, nonce, recipient, payload and signing-domain semantics.
func FuzzWorkerCTransactionBinding(f *testing.F) {
    f.Add([]byte{1, 2, 3, 4, 5, 6})
    f.Add([]byte{0, 0, 0, 0, 255, 128, 1, 9})
    f.Add([]byte{255, 255, 127, 5, 1, 9, 0})
    f.Fuzz(func(t *testing.T, data []byte) {
        if len(data) < 4 || len(data) > 256 { return }
        key, err := crypto.HexToECDSA("0c28fca386c7a22798d919f56938b5d1be56451eae0f9d6f74ddc89348e16ee1")
        if err != nil { t.Fatal(err) }
        signer := NewEIP155Signer(big.NewInt(52014))
        owner := crypto.PubkeyToAddress(key.PublicKey)
        to := common.BytesToAddress(data)
        nonce := uint64(data[0])<<8 | uint64(data[1])
        amount := new(big.Int).SetBytes(data[2:])
        tx := NewTransaction(nonce, to, amount, 21000+uint64(data[2]), big.NewInt(1), data[3:])
        signed, err := SignTx(tx, signer, key)
        if err != nil { t.Fatalf("sign baseline: %v", err) }
        if recovered, err := Sender(signer, signed); err != nil || recovered != owner {
            t.Fatalf("valid signer mismatch: %s %v", recovered, err)
        }
        if _, err := Sender(NewEIP155Signer(big.NewInt(52015)), signed); err == nil {
            t.Fatal("cross-chain replay accepted")
        }
        v, r, s := signed.RawSignatureValues()
        otherAmount := new(big.Int).Add(amount, big.NewInt(1))
        changed := NewTx(&LegacyTx{
            Nonce: nonce, To: &to, Value: otherAmount, Gas: 21000+uint64(data[2]),
            GasPrice: big.NewInt(1), Data: data[3:],
            V: new(big.Int).Set(v), R: new(big.Int).Set(r), S: new(big.Int).Set(s),
        })
        if recovered, err := Sender(signer, changed); err == nil && recovered == owner {
            t.Fatal("mutated value incorrectly authorized as original sender")
        }
    })
}
