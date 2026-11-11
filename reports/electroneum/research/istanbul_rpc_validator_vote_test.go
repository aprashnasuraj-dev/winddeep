// Research-only isolated Electroneum QBFT test. Does not connect to a real node.
// Demonstrates the trust boundary when a node operator exposes the "istanbul" RPC namespace.
package backend

import (
  "testing"
  "net/http/httptest"

  "github.com/electroneum/electroneum-sc/common"
  "github.com/electroneum/electroneum-sc/core/types"
  "github.com/electroneum/electroneum-sc/rpc"
)

func TestResearchIstanbulRPCValidatorVoteAuthorization(t *testing.T) {
  chain, engine := newBlockChain(1)
  defer engine.Stop()

  server := rpc.NewServer()
  defer server.Stop()
  for _, api := range engine.APIs(chain) {
    if err := server.RegisterName(api.Namespace, api.Service); err != nil {
      t.Fatalf("register API namespace %q: %v", api.Namespace, err)
    }
  }
  // This is an unauthenticated in-process JSON-RPC client, modelling an explicitly
  // exposed namespace (not the default HTTP module list). No private key.
  endpoint := httptest.NewServer(server)
  defer endpoint.Close()
  caller, dialErr := rpc.DialHTTP(endpoint.URL)
  if dialErr != nil { t.Fatal(dialErr) }
  defer caller.Close()

  outsider := common.HexToAddress("0x1111111111111111111111111111111111111111")
  initial, err := (&API{chain: chain, backend: engine}).GetValidators(nil)
  if err != nil { t.Fatal(err) }
  if len(initial)!=1 || initial[0]==outsider {
    t.Fatalf("unexpected initial validator set: %+v",initial)
  }

  var ignored interface{}
  if err := caller.Call(&ignored, "istanbul_propose", outsider, true); err != nil {
    t.Fatalf("RPC proposal denied: %v",err)
  }
  candidates := (&API{chain:chain,backend:engine}).Candidates()
  if !candidates[outsider] {
    t.Fatal("RPC caller's choice not installed in backend candidate registry")
  }
  t.Log("ETN_HTTP_RPC_CANDIDATE_ACCEPTED_UNAUTH_NAMESPACE")

  // Create a real signed QBFT block using the normal consensus Prepare/Seal
  // path. On a single-validator private chain, one authentic validator vote
  // passes the >N/2 add-validator threshold.
  blk := makeBlock(chain, engine, chain.CurrentBlock())
  if blk==nil {t.Fatal("single-validator QBFT failed to seal vote-bearing block")}
  if n, err := chain.InsertChain([]*types.Block{blk}); err!=nil || n!=1 {
    t.Fatalf("valid QBFT block import failed: inserted=%d err=%v", n, err)
  }
  after, err := (&API{chain:chain,backend:engine}).GetValidators(nil)
  if err!=nil {t.Fatal(err)}
  found := false
  for _, x := range after {if x==outsider {found=true}}
  if !found {
    t.Fatalf("RPC-directed candidate was not admitted, validator set=%v",after)
  }
  if len(after)!=2 {
    t.Fatalf("validator size=%d want=2 after admission",len(after))
  }
  t.Logf("ETN_RPC_VOTE_IMPORT_CONFIRMED before=%d after=%d block=%d",len(initial),len(after),chain.CurrentBlock().NumberU64())

  // A later RPC discard only clears future proposals; it cannot undo the
  // already committed validator-set vote.
  if err := caller.Call(&ignored, "istanbul_discard",outsider);err!=nil {t.Fatal(err)}
  if (&API{chain:chain,backend:engine}).Candidates()[outsider] {
    t.Fatal("discard did not clear pending candidate")
  }
  still,err:=(&API{chain:chain,backend:engine}).GetValidators(nil)
  if err!=nil||len(still)!=2 {t.Fatalf("discard incorrectly changed committed validator set: %v %v",still,err)}
  t.Log("ETN_RPC_DISCADO_DOES_NOT_ROLL_BACK_CHAIN")
}
