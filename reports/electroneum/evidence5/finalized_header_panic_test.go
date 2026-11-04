package eth
import (
 "context"
 "fmt"
 "strings"
 "testing"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/internal/ethapi"
 "github.com/electroneum/electroneum-sc/rpc"
)
func TestFinalizedHeaderAbsentAfterValidQBFTImport(t *testing.T){
 fixture,key:=rP1HBaseFixture(t)
 defer fixture.close()
 transaction:=rP1HSignedTx(t,fixture.localChain,key,0x94)
 committed:=rQBFTBuildAndImport(t,fixture.localChain,fixture.localQBFT,fixture.localDB,fixture.validatorKeys,fixture.validators,transaction)
 if fixture.localChain.CurrentBlock().Hash()!=committed.Hash(){t.Fatal("valid 3-of-4 QBFT block not imported")}
 extra,err:=types.ExtractQBFTExtra(committed.Header())
 if err!=nil {t.Fatalf("QBFT validation control failed err=%v",err)}
 if len(extra.CommittedSeal)!=3 {t.Fatalf("QBFT seal count %d",len(extra.CommittedSeal))}
 if fixture.localChain.CurrentFinalizedBlock()!=nil {t.Fatal("unexpected generic finalized marker")}
 t.Log("FINALIZED_QBFT_3_OF_4_CANONICAL_POSITIVE_PASS")
 server:=&Ethereum{blockchain:fixture.localChain,chainDb:fixture.localDB}
 backend:=&EthAPIBackend{eth:server}
 chainAPI:=ethapi.NewPublicBlockChainAPI(backend)
 block,err:=chainAPI.GetBlockByNumber(context.Background(),rpc.FinalizedBlockNumber,false)
 if err!=nil||block!=nil{t.Fatalf("expected nil generic finalized block: block=%v err=%v",block,err)}
 t.Log("FINALIZED_GETBLOCK_RETURNS_NULL_CONFIRMED")
 var recovered any
 func(){defer func(){recovered=recover()}();_,_=chainAPI.GetHeaderByNumber(context.Background(),rpc.FinalizedBlockNumber)}()
 if recovered==nil{t.Fatal("header path did not panic; code may have been corrected")}
 if !strings.Contains(strings.ToLower(fmt.Sprint(recovered)),"nil pointer"){t.Fatalf("unexpected panic: %v",recovered)}
 t.Logf("FINALIZED_GETHEADER_NIL_DEREFERENCE_CONFIRMED panic=%v",recovered)
 t.Log("FINALIZED_SCOPE_NOTE request_panic_not_proven_node_shutdown")
}