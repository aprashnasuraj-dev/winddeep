package fetcher
// Electroneum-only, deterministic, no external peers: exercise actual TxFetcher.
// This is an inherited upstream issue (go-ethereum #32210), NOT a novel bounty claim.
import(
 "encoding/binary"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/common/mclock"
 "github.com/electroneum/electroneum-sc/core/types"
)
func TestNovelRealTxFetcherAnnounceLimit(t *testing.T){
 cases:=[]struct{sent int; retained int}{
   {256,256},{4096,4096},{4097,1},{8192,4096},{16384,12288},{100000,95904},
 }
 for _,tc:=range cases{
   tx:=NewTxFetcher(func(common.Hash)bool{return false},func([]*types.Transaction)[]error{return nil},func(string,[]common.Hash)error{return nil})
   tx.clock=new(mclock.Simulated)
   tx.step=make(chan struct{})
   tx.Start()
   list:=make([]common.Hash,tc.sent)
   for i:=range list{binary.BigEndian.PutUint64(list[i][24:],uint64(i+1))}
   start:=time.Now()
   if err:=tx.Notify("poc-peer",list);err!=nil{t.Fatal(err)}
   <-tx.step // Deterministic handshake: fetcher fully processed event
   duration:=time.Since(start)
   got:=len(tx.waitslots["poc-peer"])
   if got!=tc.retained||len(tx.waitlist)!=got||len(tx.waittime)!=got{
      t.Fatalf("sent=%d expected retained=%d got slots=%d waitlist=%d waittime=%d",tc.sent,tc.retained,got,len(tx.waitlist),len(tx.waittime))
   }
   t.Logf("NATIVE_TXFETCHER_BOUNDARY sent=%d retained=%d intended_cap=%d multiplier=%.2fx processed=%s",tc.sent,got,maxTxAnnounces,float64(got)/float64(maxTxAnnounces),duration)
   if err:=tx.Drop("poc-peer");err!=nil{t.Fatal(err)}
   <-tx.step
   if len(tx.waitslots)!=0||len(tx.waitlist)!=0{t.Fatalf("peer cleanup leak after drop: slots=%d list=%d",len(tx.waitslots),len(tx.waitlist))}
   tx.Stop()
 }
}
