// Isolated post-#94 integration probe: the ACTUAL miner and downloader share
// one event mux. This is not a multi-validator QBFT finality attack.
package miner

import (
    "math/big"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
)

type independentHeadOnlyDownloaderPeer struct {
    head *types.Header
    silentHead bool
    byNumberCalled chan struct{}
}
func (p *independentHeadOnlyDownloaderPeer) Head() (common.Hash,*big.Int) {
    return p.head.Hash(),big.NewInt(1000000000)
}
func (p *independentHeadOnlyDownloaderPeer) RequestHeadersByHash(h common.Hash,amount int,skip int,reverse bool,sink chan *ethproto.Response) (*ethproto.Request,error) {
    req:=&ethproto.Request{Peer:"headonly-untrusted-eth66"}
    var hdrs []*types.Header
    var hashes []common.Hash
    if !p.silentHead && h==p.head.Hash() {
        hdrs=[]*types.Header{p.head}
        hashes=[]common.Hash{p.head.Hash()}
    }
    result:=&ethproto.Response{Req:req,Res:(*ethproto.BlockHeadersPacket)(&hdrs),Meta:hashes,Time:1,Done:make(chan error,1)}
    go func(){sink<-result}()
    return req,nil
}
func (p *independentHeadOnlyDownloaderPeer) RequestHeadersByNumber(n uint64, amount int,skip int,reverse bool,sink chan *ethproto.Response) (*ethproto.Request,error) {
    select {case p.byNumberCalled<-struct{}{}:default:}
    return &ethproto.Request{Peer:"headonly-untrusted-eth66"},nil
}
func (p *independentHeadOnlyDownloaderPeer) RequestBodies(h []common.Hash,sink chan *ethproto.Response) (*ethproto.Request,error) {
    return &ethproto.Request{Peer:"headonly-untrusted-eth66"},nil
}
func (p *independentHeadOnlyDownloaderPeer) RequestReceipts(h []common.Hash,sink chan *ethproto.Response) (*ethproto.Request,error) {
    return &ethproto.Request{Peer:"headonly-untrusted-eth66"},nil
}
var _ downloader.Peer=(*independentHeadOnlyDownloaderPeer)(nil)

func TestIndependentCurrentUpstreamHeadOnlyCausesActualMinerPause(t *testing.T) {
    for _,tc:=range []struct{name string;silent bool}{
        {"head_only_no_ancestor",false},
        {"no_head_responded_control",true},
    } {
        t.Run(tc.name,func(t *testing.T) {
            m,mux,cleanup:=createMiner(t)
            defer cleanup(false)
            m.Start(common.HexToAddress("0x12345"))
            waitForMiningState(t,m,true)
            bc:=m.eth.BlockChain()
            original:=bc.CurrentBlock().Hash()
            head:=&types.Header{
                ParentHash:original,
                Number:big.NewInt(1),
                GasLimit:11500000,
                Difficulty:big.NewInt(1),
                Time:uint64(time.Now().Unix()),
                Extra:[]byte{0x45,0x54,0x4e},
            }
            peer:=&independentHeadOnlyDownloaderPeer{head:head,silentHead:tc.silent,byNumberCalled:make(chan struct{},1)}
            dl:=downloader.New(0,rawdb.NewMemoryDatabase(),mux,bc,nil,nil,nil)
            defer dl.Terminate()
            const id="headonly-untrusted-eth66"
            if err:=dl.RegisterPeer(id,ethproto.ETH66,peer);err!=nil{t.Fatal(err)}
            result:=make(chan error,1)
            go func(){result<-dl.LegacySync(id,head.Hash(),big.NewInt(1000000000),nil,downloader.FullSync)}()
            if tc.silent {
                select {case err:=<-result:
                    if err==nil{t.Fatal("headless peer unexpectedly synced")}
                case <-time.After(10*time.Second):dl.Cancel();t.Fatal("headless peer did not terminate")}
                assertMiningStays(t,m,true)
                if bc.CurrentBlock().Hash()!=original{t.Fatal("silent control altered chain")}
                t.Log("INTEGRATED_POSTFIX_NO_HEAD_GUARD_MINE_STAYS_ON")
                return
            }
            select {case <-peer.byNumberCalled:
            case err:=<-result:t.Fatalf("headonly exited before ancestor wait: %v",err)
            case <-time.After(12*time.Second):dl.Cancel();t.Fatal("no ancestor request")}
            // A real downloader ProgressEvent has now been emitted into the same
            // mux consumed by this live miner. No direct event injection.
            waitForMiningState(t,m,false)
            assertMiningStays(t,m,false)
            if bc.CurrentBlock().Hash()!=original{dl.Cancel();t.Fatal("canonical chain changed during stalled sync")}
            t.Logf("INTEGRATED_POSTFIX_UNAUTH_HEAD_MINER_STOPPED height=%d head_hash=%s verified_ancestor=false duration_ge_ms=300",bc.CurrentBlock().NumberU64(),head.Hash())
            dl.Cancel()
            select{case err:=<-result:
                if err==nil{t.Fatal("cancelled sync returned nil")}
            case <-time.After(10*time.Second):t.Fatal("cancelled downloader did not return")}
            waitForMiningState(t,m,true)
            t.Log("INTEGRATED_POSTFIX_FAILED_EVENT_MINER_RECOVERED")
        })
    }
}
