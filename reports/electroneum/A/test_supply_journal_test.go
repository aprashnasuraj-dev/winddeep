// Class A: source-backed balance journal and rollback consistency checks.
// Copied into scratch certified core/state; does not model full consensus supply.
package state

import (
    "math/big"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/rawdb"
)

func workerASnapshotInvariant(t *testing.T, input []byte) {
    t.Helper()
    if len(input) < 4 || len(input) > 512 { return }
    db := rawdb.NewMemoryDatabase()
    defer db.Close()
    state, err := New(common.Hash{}, NewDatabase(db), nil)
    if err != nil { t.Fatal(err) }
    source := common.Address{0xa1}
    destination := common.Address{0xb1}
    initialSource := big.NewInt(int64(input[0]) + 1000)
    initialDestination := big.NewInt(int64(input[1]) + 100)
    state.SetBalance(source, new(big.Int).Set(initialSource))
    state.SetBalance(destination, new(big.Int).Set(initialDestination))
    initialSupply := new(big.Int).Add(initialSource, initialDestination)

    snap := state.Snapshot()
    amount := big.NewInt(int64(input[2]))
    state.SubBalance(source, amount)
    state.AddBalance(destination, amount)
    actualSupply := new(big.Int).Add(new(big.Int).Set(state.GetBalance(source)), state.GetBalance(destination))
    if actualSupply.Cmp(initialSupply) != 0 {
        t.Fatalf("balance delta violation: got=%s expected=%s", actualSupply, initialSupply)
    }
    nested := state.Snapshot()
    state.AddBalance(source, big.NewInt(int64(input[3])+1))
    state.RevertToSnapshot(nested)
    afterNested := new(big.Int).Add(new(big.Int).Set(state.GetBalance(source)), state.GetBalance(destination))
    if afterNested.Cmp(initialSupply) != 0 { t.Fatal("nested rollback retained artificial credit") }
    state.RevertToSnapshot(snap)
    if state.GetBalance(source).Cmp(initialSource) != 0 || state.GetBalance(destination).Cmp(initialDestination) != 0 {
        t.Fatal("rollback did not restore exact original balances")
    }
}

func TestWorkerASupplyJournalRegression(t *testing.T) {
    workerASnapshotInvariant(t, []byte{11, 12, 13, 14})
    workerASnapshotInvariant(t, []byte{255, 0, 0, 255})
}

func FuzzWorkerASupplySnapshotJournal(f *testing.F) {
    f.Add([]byte{11, 12, 13, 14})
    f.Add([]byte{255, 0, 0, 255})
    f.Add([]byte{0, 255, 255, 0})
    f.Fuzz(func(t *testing.T, input []byte) { workerASnapshotInvariant(t, input) })
}
