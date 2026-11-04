//go:build linux

// Worker R G6 boundary test: protocol-valid ETH/66 peer-delivered QBFT block
// while the receiving local disk is deliberately exhausted by RLIMIT_FSIZE.
// This reproduces a local availability failure at a genuine WAL write syscall.
// It does not prove that the remote peer caused or can cause disk exhaustion;
// the block already carries validator-quorum signatures, not attacker forgery.
package eth

import (
    "bytes"
    "encoding/json"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "syscall"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul"
    istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/forkid"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
    "github.com/electroneum/electroneum-sc/p2p"
)

type rG6WireSpy struct{ p2p.MsgReadWriter }
func (s *rG6WireSpy) WriteMsg(m p2p.Msg) error {
    err:=s.MsgReadWriter.WriteMsg(m)
    if err==nil && m.Code==ethproto.BlockBodiesMsg {
        fmt.Fprintln(os.Stderr,"R_G6_ETH66_BODY_RESPONSE_SENT_SUCCESS")
    }
    return err
}
type rG6DiskMeta struct { TxHash common.Hash; BlockHash common.Hash; KeyHex string }

func TestRQBFTWireDiskLimitCrashChild(t *testing.T){
    if os.Getenv("R_G6_WIRE_LIMIT_CHILD")!="1"{return}
    // Distinct, independent remote and local chains. Local persistent genesis
    // never receives block 1 before peer/downloader synchronization.
    f,senderKey:=rP1HBaseFixture(t)
    defer f.close()
    remoteTx:=rP1HSignedTx(t,f.remoteChain,senderKey,0x97)
    block:=rQBFTBuildAndImport(t,f.remoteChain,f.remoteQBFT,f.remoteDB,f.validatorKeys,f.validators,remoteTx)
    if block==nil || block.NumberU64()!=1{t.Fatal("R_G6_REMOTE_QUORUM_BLOCK_NOT_BUILT")}
    dir:=os.Getenv("R_G6_DISK_DIR")
    db:=rQBFTOpenDisk(t,dir)
    genesis:=rQBFTNetworkGenesis(t,f.validatorKeys,crypto.PubkeyToAddress(senderKey.PublicKey))
    g:=genesis.MustCommit(db)
    if g.Hash()!=block.ParentHash(){t.Fatalf("R_G6_GENESIS_MISMATCH got=%s want=%s",g.Hash(),block.ParentHash())}
    backend:=istanbulbackend.New(*istanbul.DefaultConfig,f.validatorKeys[0],db)
    chain,err:=core.NewBlockChain(db,nil,genesis.Config,backend,vm.Config{},nil,nil)
    if err!=nil{t.Fatal(err)}
    if err:=backend.Start(chain,chain.CurrentBlock,rawdb.HasBadBlock);err!=nil{t.Fatal(err)}
    if err:=backend.VerifyHeader(chain,block.Header(),true);err!=nil{
        t.Fatalf("R_G6_REMOTE_BLOCK_NOT_QBFT_VALID: %v",err)
    }
    keyHex:=hex.EncodeToString(crypto.FromECDSA(f.validatorKeys[0]))
    meta:=rG6DiskMeta{TxHash:remoteTx.Hash(),BlockHash:block.Hash(),KeyHex:keyHex}
    encoded,err:=json.Marshal(meta)
    if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(os.Getenv("R_G6_META_PATH"),encoded,0600);err!=nil{t.Fatal(err)}

    localHandler:=rDevP2PHandler(t,db,chain)
    defer localHandler.Stop()
    localServer:=rDevP2PServer(t,"r-g6-local-disk-full",localHandler,false)
    defer localServer.Stop()
    wire:=new(rP1HWireState)
    remoteTD:=f.remoteChain.GetTd(block.Hash(),1)
    if remoteTD==nil{t.Fatal("R_G6_REMOTE_CHAIN_TD_MISSING")}
    protocol:=rP1HRemoteProtocol(t,chain.Genesis(),block,remoteTD,
        forkid.NewID(chain.Config(),chain.Genesis().Hash(),block.NumberU64()),wire)
    original:=protocol.Run
    protocol.Run=func(peer *p2p.Peer,rw p2p.MsgReadWriter) error {
        return original(peer,&rG6WireSpy{MsgReadWriter:rw})
    }
    remoteServer:=rP1HRemoteServer(t,"r-g6-remote-valid-quorum",protocol)
    defer remoteServer.Stop()
    localServer.AddPeer(remoteServer.Self())
    peer:=rP1HWaitRegisteredPeer(t,localHandler,remoteServer)
    peerHash,peerTD:=peer.Head()
    if wire.handshakes.Load()==0 || peerHash!=block.Hash() {
        t.Fatalf("R_G6_VALID_PEER_HANDSHAKE_MISSING handshakes=%d advertised=%s want=%s",
            wire.handshakes.Load(),peerHash,block.Hash())
    }
    fmt.Fprintf(os.Stderr,"R_G6_ETH66_VALID_PEER_CONNECTED handshakes=%d quorum_seals=3\n",wire.handshakes.Load())
    wal,n:=rQBFTActiveWAL(t,dir)
    limit:=uint64(n+64)
    signal.Ignore(syscall.SIGXFSZ)
    if err:=syscall.Setrlimit(syscall.RLIMIT_FSIZE,&syscall.Rlimit{Cur:limit,Max:limit});err!=nil{
        t.Fatalf("R_G6_OS_LIMIT_CANNOT_ARM: %v",err)
    }
    err=os.WriteFile(filepath.Join(t.TempDir(),"size-limit-probe"),make([]byte,int(limit)+4096),0600)
    if !errors.Is(err,syscall.EFBIG){t.Fatalf("R_G6_OS_EFBIG_PROBE_FAIL: %v",err)}
    fmt.Fprintf(os.Stderr,"R_G6_REAL_OS_EFBIG_ARMED wal=%s initial=%d limit=%d\n",filepath.Base(wal),n,limit)
    fmt.Fprintln(os.Stderr,"R_G6_ETH66_DOWNLOADER_SYNC_START")
    _,_ = peerHash,peerTD
    err=localHandler.downloader.LegacySync(peer.ID(),peerHash,peerTD,
        chain.Config().TerminalTotalDifficulty,downloader.FullSync)
    t.Fatalf("R_G6_UNEXPECTED_DOWNLOADER_RETURN err=%v bodies=%d",
        err,wire.bodyResponses.Load())
}

func TestRQBFTWireDiskLimitPeerDelivery(t *testing.T){
    temp:=t.TempDir()
    path:=filepath.Join(temp,"chaindata")
    if err:=os.MkdirAll(path,0700);err!=nil{t.Fatal(err)}
    metaFile:=filepath.Join(temp,"metadata.json")
    child:=exec.Command(os.Args[0],"-test.run=^TestRQBFTWireDiskLimitCrashChild$","-test.v")
    child.Env=append(os.Environ(),
        "R_G6_WIRE_LIMIT_CHILD=1","R_G6_DISK_DIR="+path,"R_G6_META_PATH="+metaFile)
    output,err:=child.CombinedOutput()
    exit,ok:=err.(*exec.ExitError)
    checks:=[]string{
        "R_G6_ETH66_VALID_PEER_CONNECTED",
        "R_G6_REAL_OS_EFBIG_ARMED",
        "R_G6_ETH66_DOWNLOADER_SYNC_START",
        "R_G6_ETH66_BODY_RESPONSE_SENT_SUCCESS",
    }
    for _,marker:=range checks {
        if !bytes.Contains(output,[]byte(marker)) {
            t.Fatalf("R_G6_WIRE_END_TO_END_MARKER_MISSING marker=%s exit=%v output=%s",
                marker,err,output)
        }
    }
    if !ok||exit.ExitCode()!=1 || bytes.Contains(output,[]byte("R_G6_UNEXPECTED_DOWNLOADER_RETURN")){
        t.Fatalf("R_G6_DID_NOT_FATAL_AT_DISK_WRITE exit=%v output=%s",err,output)
    }
    metaBytes,err:=os.ReadFile(metaFile)
    if err!=nil{t.Fatal(err)}
    var meta rG6DiskMeta
    if err:=json.Unmarshal(metaBytes,&meta);err!=nil{t.Fatal(err)}
    keyBytes,err:=hex.DecodeString(meta.KeyHex)
    if err!=nil{t.Fatal(err)}
    key,err:=crypto.ToECDSA(keyBytes)
    if err!=nil{t.Fatal(err)}
    db:=rQBFTOpenDisk(t,path)
    chain,backend:=rQBFTEngine(t,db,key)
    full:=chain.CurrentBlock()
    cfg:=chain.Config()
    canon:=rawdb.ReadCanonicalHash(db,1)
    tx,_,_,_:=rawdb.ReadTransaction(db,meta.TxHash)
    receipt,_,_,_:=rawdb.ReadReceipt(db,meta.TxHash,cfg)
    if full==nil||full.NumberU64()!=0 || canon!=(common.Hash{}) ||
        tx!=nil || receipt!=nil {
        _=backend.Stop();chain.Stop();db.Close()
        t.Fatalf("R_G6_PEER_VALID_BLOCK_DISK_LIMIT_UNEXPECTED_STATE full=%v canon=%s tx=%v receipt=%v",
            full,canon,tx,receipt)
    }
    t.Logf("R_G6_PEER_TRIGGERED_LOCAL_AVAILABILITY_FAIL_VALID_QUORUM disk_limit=64B_wal_growth exit=1 latest=0 receipts_visible=0")
    if err:=backend.Stop();err!=nil{t.Fatal(err)}
    chain.Stop()
    if err:=db.Close();err!=nil{t.Fatal(err)}
    t.Log("R_G6_ETH66_REAL_WAL_EFBIG_RESTART_PASS valid_qbft_peer_and_local_disk_full_only_no_attacker_induced_capacity_exhaustion")
}
