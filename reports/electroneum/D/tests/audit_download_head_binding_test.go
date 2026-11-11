package downloader

// Target-integrated bounded peer-response regression. The fake peer is entirely
// in process; no P2P connection, production nodes, external keys or funds.
import (
 "math/big"
 "testing"
 "sync"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/eth/protocols/eth"
)

type auditWrongHeadPeer struct {
 *downloadTesterPeer
 advertised common.Hash
}
func (p *auditWrongHeadPeer) Head() (common.Hash,*big.Int) {
 _, td:=p.downloadTesterPeer.Head()
 return p.advertised,new(big.Int).Add(td,big.NewInt(1234))
}
func (p *auditWrongHeadPeer) RequestHeadersByHash(_ common.Hash,amount int,skip int,reverse bool,sink chan *eth.Response) (*eth.Request,error) {
 legitimate,_:=p.downloadTesterPeer.Head()
 return p.downloadTesterPeer.RequestHeadersByHash(legitimate,amount,skip,reverse,sink)
}


// auditGatedHeadPeer models a peer that supplies a valid header for the WRONG
// advertised hash and then withholds all numbered ancestor headers. Its
// authenticated transport is outside the scope of this deterministic fixture.
type auditGatedHeadPeer struct {
 *auditWrongHeadPeer
 entered chan struct{}
 release chan struct{}
 once sync.Once
}
func (p *auditGatedHeadPeer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool, sink chan *eth.Response) (*eth.Request,error) {
 p.once.Do(func(){close(p.entered)})
 <-p.release
 return p.downloadTesterPeer.RequestHeadersByNumber(origin,amount,skip,reverse,sink)
}

func TestAuditDownloaderFetchHeadAdvertisedHashBinding(t *testing.T) {
 tester:=newTester(t)
 defer tester.terminate()
 chain:=testChainBase.shorten(blockCacheMaxItems - 15)
 honest:=tester.newPeer("audit-honest",eth.ETH66,chain.blocks[1:])
 advertised,_:=honest.Head()
 head,pivot,err:=tester.downloader.fetchHead(tester.downloader.peers.Peer("audit-honest"))
 if err!=nil{t.Fatalf("honest fetch failed: %v",err)}
 if head.Hash()!=advertised || pivot!=nil {t.Fatalf("honest head mismatch or unexpected pivot")}
 t.Logf("DOWNLOADER_HONEST_HEAD_MATCH advertised=%s served=%s",advertised,head.Hash())

 spoof:=&auditWrongHeadPeer{
   downloadTesterPeer:honest,
   advertised:common.HexToHash("0x999988887777666655554444333322221111aaaabbbbccccddddeeeeffffabcd"),
 }
 if err:=tester.downloader.RegisterPeer("audit-spoof",eth.ETH66,spoof);err!=nil{t.Fatal(err)}
 response,_,err:=tester.downloader.fetchHead(tester.downloader.peers.Peer("audit-spoof"))
 if err!=nil{t.Fatalf("spoofed fetch rejected (guard may be fixed): %v",err)}
 if response.Hash()==spoof.advertised {t.Fatal("negative control failed: response matches advertised")}
 if response.Hash()!=advertised {t.Fatalf("wrong serving header hash: %s",response.Hash())}
 t.Logf("DOWNLOADER_UNBOUND_HEAD_CONFIRMED advertised=%s served=%s",spoof.advertised,response.Hash())

 // A genuinely empty header response is rejected, so this is a semantic
 // request-identity check missing after syntactically valid response decode.
 honest.withholdHeaders[advertised]=struct{}{}
 _,_,err=tester.downloader.fetchHead(tester.downloader.peers.Peer("audit-honest"))
 if err==nil {t.Fatal("missing-header negative control was wrongly accepted")}
 t.Logf("DOWNLOADER_EMPTY_HEADER_REJECTED err=%v",err)

 // Cross-component regression: despite advertising a nonexistent head hash,
 // the target emits ProgressEvent before it requests/verifies ancestry.
 // The synthetic peer holds that latter request, so the event cannot be
 // explained away as a completed chain-sync cycle.
 delete(honest.withholdHeaders,advertised)
 gated:=&auditGatedHeadPeer{
  auditWrongHeadPeer:&auditWrongHeadPeer{
   downloadTesterPeer:honest,
   advertised:common.HexToHash("0x777788889999aaaabbbbccccddddeeeeffff0000111122223333444455556666"),
  },
  entered:make(chan struct{}),
  release:make(chan struct{}),
 }
 released:=false
 defer func(){if !released{close(gated.release)}}()
 if err:=tester.downloader.RegisterPeer("audit-gated",eth.ETH66,gated);err!=nil{t.Fatal(err)}
 sub:=tester.downloader.mux.Subscribe(ProgressEvent{})
 defer sub.Unsubscribe()
 syncDone:=make(chan error,1)
 go func(){
  syncDone<-tester.downloader.synchronise("audit-gated",gated.advertised,big.NewInt(100000000),nil,FullSync,false,nil)
 }()
 select {
 case ev:=<-sub.Chan():
  if ev==nil {t.Fatal("progress subscription closed")}
  t.Logf("DOWNLOADER_UNBOUND_PROGRESS_EVENT advertised=%s still_unverified=true",gated.advertised)
 case <-time.After(8*time.Second):
  t.Fatal("expected ProgressEvent from wrong advertised head")
 }
 select {
 case <-gated.entered:
  t.Logf("DOWNLOADER_ANCESTRY_REQUEST_BLOCKED progress_already_posted=true")
 case <-time.After(8*time.Second):
  t.Fatal("sync never attempted numbered ancestor fetch after progress")
 }
 select {
 case err:=<-syncDone: t.Fatalf("sync terminated before withheld ancestor delivered: %v",err)
 default:
 }
 close(gated.release)
 released=true
 tester.downloader.Cancel()
 select {
 case <-syncDone:
  t.Logf("DOWNLOADER_SYNC_CLEANUP_FINISHED")
 case <-time.After(8*time.Second):
  t.Fatal("sync cleanup timed out after releasing in-process peer")
 }
}
