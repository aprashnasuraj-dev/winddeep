package core
import (
 "math/big"
 "testing"
 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
)
func TestRoundChangeFutureSequenceRoundWindow(t *testing.T){
 validators:=newTestValidatorSet(4)
 engine:=newTestCore(validators,10,0)
 source:=validators.List()[1].Address()
 excessiveRound:=new(big.Int).Lsh(big.NewInt(1),64)
 sameSequence:=istanbul.View{Sequence:big.NewInt(10),Round:excessiveRound}
 if engine.withinBacklogFutureWindow(qbfttypes.RoundChangeCode,sameSequence){t.Fatal("same-sequence excessive round unexpectedly accepted")}
 t.Log("BACKLOG_SAME_SEQUENCE_ROUND_CAP_PASS")
 futureSequence:=istanbul.View{Sequence:big.NewInt(11),Round:excessiveRound}
 if !engine.withinBacklogFutureWindow(qbfttypes.RoundChangeCode,futureSequence){t.Fatal("future-sequence excessive round unexpectedly rejected")}
 t.Log("BACKLOG_FUTURE_SEQUENCE_BYPASSES_ROUND_CAP_CONFIRMED")
 message:=qbfttypes.NewRoundChange(big.NewInt(11),excessiveRound,nil,nil,false)
 message.SetSource(source);message.SetSignature([]byte{1})
 engine.addToBacklog(message,256)
 if engine.backlogsTotal!=1 || engine.backlogsBytesTotal!=256 {t.Fatalf("message not retained: count=%d bytes=%d",engine.backlogsTotal,engine.backlogsBytesTotal)}
 t.Logf("BACKLOG_FUTURE_ROUND_RETAINED count=%d charged_bytes=%d round=%s",engine.backlogsTotal,engine.backlogsBytesTotal,excessiveRound)
 distant:=istanbul.View{Sequence:big.NewInt(43),Round:excessiveRound}
 if engine.withinBacklogFutureWindow(qbfttypes.RoundChangeCode,distant){t.Fatal("beyond 32-sequence window was accepted")}
 t.Log("BACKLOG_FUTURE_SEQUENCE_MAX_GAP_CONTROL_PASS")
 if MaxBacklogPerValidator!=1024||MaxBacklogBytesPerValidator!=32*1024*1024{t.Fatalf("source budget assumptions changed: count=%d bytes=%d",MaxBacklogPerValidator,MaxBacklogBytesPerValidator)}
 t.Log("BACKLOG_PER_VALIDATOR_COUNT_AND_BYTES_CAP_CONFIRMED")
}