package eth
import(
"math/big"
"testing"
"github.com/electroneum/electroneum-sc/common"
"github.com/electroneum/electroneum-sc/core/types"
)
func TestQBFTRewardReorgNoOrphanCredit(t *testing.T){
 keys,validators:=rP1HValidators(t)
 funded:=common.HexToAddress("0x0000000000000000000000000000000000000099")
 genesis:=rQBFTNetworkGenesis(t,keys,funded)
 oldDB,oldChain,oldBE:=rQBFTStartChain(t,genesis,keys[0])
 defer oldBE.Stop();defer oldChain.Stop();defer oldDB.Close()
 newDB,newChain,newBE:=rQBFTStartChain(t,genesis,keys[1])
 defer newBE.Stop();defer newChain.Stop();defer newDB.Close()
 a,b:=validators[0],validators[1]
 initial,err:=oldChain.StateAt(oldChain.Genesis().Root())
 if err!=nil{t.Fatalf("genesis state missing: %v",err)}
 baseA:=new(big.Int).Set(initial.GetBalance(a))
 baseB:=new(big.Int).Set(initial.GetBalance(b))
 oldBlock:=rQBFTBuildAndImport(t,oldChain,oldBE,oldDB,keys,validators,nil)
 oldState,err:=oldChain.StateAt(oldBlock.Root());if err!=nil{t.Fatal(err)}
 oldGain:=new(big.Int).Sub(oldState.GetBalance(a),baseA)
 if oldGain.Sign()<=0{t.Fatalf("old proposer not rewarded: %s",oldGain)}
 t.Logf("REWARD_OLD_BRANCH_CREDIT_CONFIRMED beneficiary=%s reward=%s",a,oldGain)
 remoteOrder:=append([]common.Address{b,a},validators[2:]...)
 fork1:=rQBFTBuildAndImport(t,newChain,newBE,newDB,keys,remoteOrder,nil)
 fork2:=rQBFTBuildAndImport(t,newChain,newBE,newDB,keys,remoteOrder,nil)
 if fork1.Hash()==oldBlock.Hash(){t.Fatal("competing block unexpectedly identical")}
 if fork2.NumberU64()!=2{t.Fatalf("unexpected remote height: %d",fork2.NumberU64())}
 ref,err:=newChain.StateAt(fork2.Root());if err!=nil{t.Fatal(err)}
 refA:=new(big.Int).Set(ref.GetBalance(a))
 refB:=new(big.Int).Set(ref.GetBalance(b))
 if refA.Cmp(baseA)!=0||refB.Cmp(baseB)<=0{t.Fatalf("competing branch reward invalid: baseA=%s refA=%s baseB=%s refB=%s",baseA,refA,baseB,refB)}
 t.Logf("REWARD_COMPETING_QBFT_BRANCH_VALIDATED height=%d refA=%s refB=%s",fork2.NumberU64(),refA,refB)
 if index,err:=oldChain.InsertChain(types.Blocks{fork1,fork2});err!=nil{t.Fatalf("real canonical reorg rejected index=%d err=%v",index,err)}
 if oldChain.CurrentBlock().Hash()!=fork2.Hash()||oldChain.GetCanonicalHash(1)!=fork1.Hash()||oldChain.GetCanonicalHash(2)!=fork2.Hash(){t.Fatal("canonical competing branch not selected")}
 updated,err:=oldChain.StateAt(oldChain.CurrentBlock().Root());if err!=nil{t.Fatal(err)}
 gotA,gotB:=updated.GetBalance(a),updated.GetBalance(b)
 if gotA.Cmp(refA)!=0||gotB.Cmp(refB)!=0{t.Fatalf("REWARD_ORPHAN_DOUBLE_CREDIT_DETECTED a=%s expect_a=%s b=%s expect_b=%s",gotA,refA,gotB,refB)}
 if gotA.Cmp(baseA)!=0{t.Fatalf("orphan reward survived: canonicalA=%s genesisA=%s",gotA,baseA)}
 t.Logf("REWARD_ORPHAN_CREDIT_REMOVED_PASS orphan_old_reward=%s canonical_A=%s reference_A=%s",oldGain,gotA,refA)
 t.Logf("REWARD_REORG_CANONICAL_BALANCES_MATCH_INDEPENDENT_BRANCH_PASS canonical_B=%s reference_B=%s",gotB,refB)
 t.Log("REWARD_SCOPE_NOTE no_unapproved_mint observed; fixture uses legitimate 3-of-4 validator signatures")
}