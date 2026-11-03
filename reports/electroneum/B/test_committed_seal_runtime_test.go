// Class B: certified QBFT runtime oversize seal boundary.
// Copied into scratch consensus/istanbul/engine; uses fake, synthetic seals.
package qbftengine

import (
    "bytes"
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul"
    istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
    "github.com/electroneum/electroneum-sc/core/types"
)

func workerBOversizedSeals(t *testing.T, input []byte) {
    t.Helper()
    if len(input) < 2 || len(input) > 256 { return }
    n := int(input[0]%13) + 1
    addrs := make([]common.Address, n)
    for i := 0; i < n; i++ { addrs[i] = common.Address{byte(i+1)} }
    seals := make([][]byte, n+1)
    for i := range seals {
        seals[i] = bytes.Repeat([]byte{input[1]}, types.IstanbulExtraSeal)
    }
    header := &types.Header{Number: big.NewInt(1)}
    if err := ApplyHeaderQBFTExtra(header, WriteValidators(addrs), writeCommittedSeals(seals)); err != nil {
        t.Fatalf("synthetic seal encoding rejected before admission test: %v", err)
    }
    engine := NewEngine(&istanbul.Config{}, addrs[0], nil)
    vset := validator.NewSet(addrs, istanbul.NewProposerPolicy(istanbul.RoundRobin))
    if err := engine.VerifyCommittedSeals(nil, header, vset); err != istanbulcommon.ErrInvalidCommittedSeals {
        t.Fatalf("oversize seals N=%d: expected early ErrInvalidCommittedSeals, got %v", n, err)
    }
}

func TestWorkerBOversizeSealRuntime(t *testing.T) {
    for n:=byte(0); n<13; n++ { workerBOversizedSeals(t, []byte{n, n + 10}) }
}
func FuzzWorkerBOversizeSealAdmission(f *testing.F) {
    f.Add([]byte{0, 1})
    f.Add([]byte{12, 255})
    f.Add([]byte{7, 128, 9})
    f.Fuzz(func(t *testing.T, input []byte) { workerBOversizedSeals(t, input) })
}
