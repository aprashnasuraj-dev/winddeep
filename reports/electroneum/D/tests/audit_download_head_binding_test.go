package downloader

// Target-integrated bounded peer-response regression. The fake peer is entirely
// in process; no P2P connection, production nodes, external keys or funds.
import (
 "math/big"
 "testing"

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
}
