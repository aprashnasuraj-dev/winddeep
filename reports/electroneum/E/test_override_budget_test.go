package ethapi

// Copy into internal/ethapi in a certified scratch checkout for execution.
// This bounded test characterizes override processing, not a DoS exploit.
import (
 "encoding/json"
 "fmt"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/state"
)

func TestWorkerEOverrideBudgetBoundaries(t *testing.T) {
 for _, count := range []int{0, 1, 64, 256} {
  t.Run(fmt.Sprintf("entries_%d", count), func(t *testing.T) {
   st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
   if err != nil { t.Fatal(err) }
   entries := make(map[common.Hash]common.Hash, count)
   for i := 0; i < count; i++ {
    var key common.Hash
    key[30], key[31] = byte(i>>8), byte(i)
    entries[key] = common.BytesToHash([]byte{byte(i+1)})
   }
   address := common.HexToAddress("0x100")
   override := StateOverride{address: OverrideAccount{StateDiff: &entries}}
   wire, err := json.Marshal(override)
   if err != nil { t.Fatal(err) }
   if len(wire) == 0 { t.Fatal("empty JSON request") }
   started := time.Now()
   if err := override.Apply(st); err != nil { t.Fatal(err) }
   duration := time.Since(started)
   for key, want := range entries {
    if got := st.GetState(address, key); got != want {
     t.Fatalf("override mismatch at %x: got %x want %x", key, got, want)
    }
   }
   t.Logf("E_OVERRIDE_BOUNDARY entries=%d wire_bytes=%d elapsed_ns=%d", count, len(wire), duration.Nanoseconds())
  })
 }
}

func TestWorkerEOverrideConflictingStateRejected(t *testing.T) {
 st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
 if err != nil { t.Fatal(err) }
 entries := map[common.Hash]common.Hash{}
 address := common.HexToAddress("0x100")
 override := StateOverride{address: OverrideAccount{State: &entries, StateDiff: &entries}}
 if err := override.Apply(st); err == nil { t.Fatal("expected conflicting state/stateDiff rejection") }
 t.Log("E_OVERRIDE_CONFLICT_REJECTED")
}

func TestWorkerEOverrideRejectedAccountNoStorageMutation(t *testing.T) {
 st, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
 if err != nil { t.Fatal(err) }
 addr := common.HexToAddress("0x200")
 key := common.HexToHash("0x01")
 original := common.HexToHash("0x02")
 st.SetState(addr, key, original)
 replacement := map[common.Hash]common.Hash{key: common.HexToHash("0x03")}
 override := StateOverride{addr: OverrideAccount{State: &replacement, StateDiff: &replacement}}
 if err := override.Apply(st); err == nil { t.Fatal("expected rejection") }
 t.Log("E_OVERRIDE_REJECTED_STATE_INTACT")
 if got := st.GetState(addr, key); got != original {
  t.Fatalf("rejected override changed storage: got %x expected %x", got, original)
 }
}
