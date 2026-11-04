//go:build linux

// Worker R P2n: real loopback TCP/RLPx etn-snap/1 protocol, parser,
// producer-selected request IDs, production SnapSyncer.Sync, and real LevelDB.
// The root comes from a verified 3-of-4-committed QBFT fixture block.
// This test uses a stand-alone Snap backend glue, not the full ETH+Snap
// handler.runSnapExtension lifecycle. It does not contact public validators.
package eth

import (
    "bytes"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "sort"
    "sync"
    "sync/atomic"
    "syscall"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/state/snapshot"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/crypto"
    snap "github.com/electroneum/electroneum-sc/eth/protocols/snap"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/light"
    "github.com/electroneum/electroneum-sc/p2p"
    "github.com/electroneum/electroneum-sc/p2p/enode"
    "github.com/electroneum/electroneum-sc/rlp"
    "github.com/electroneum/electroneum-sc/trie"
)

type rP2NStats struct {
    connected atomic.Int64
    accountReq atomic.Int64
    storageReq atomic.Int64
    codeReq atomic.Int64
    trieReq atomic.Int64
    received atomic.Int64
    rejected atomic.Int64
    duplicateProofBytes atomic.Int64
    fakeIDs atomic.Int64
    badPacketDelivered atomic.Int64
    replyBytes atomic.Int64
    disconnect atomic.Int64
}
type rP2NBackend struct {
    chain *core.BlockChain
    syncer *snap.Syncer
    stat *rP2NStats
    cancel func()
}
func (b *rP2NBackend) Chain() *core.BlockChain {return b.chain}
func (b *rP2NBackend) PeerInfo(enode.ID) interface{} {return nil}
func (b *rP2NBackend) RunPeer(peer *snap.Peer, handler snap.Handler) error {return handler(peer)}
func (b *rP2NBackend) Handle(peer *snap.Peer, pkt snap.Packet) error {
    b.stat.received.Add(1)
    var err error
    switch p:=pkt.(type) {
    case *snap.AccountRangePacket:
        var hashes []common.Hash
        var accounts [][]byte
        hashes,accounts,err=p.Unpack()
        if err==nil {err=b.syncer.OnAccounts(peer,p.ID,hashes,accounts,p.Proof)}
    case *snap.StorageRangesPacket:
        hashes,slots:=p.Unpack()
        err=b.syncer.OnStorage(peer,p.ID,hashes,slots,p.Proof)
    case *snap.ByteCodesPacket:
        err=b.syncer.OnByteCodes(peer,p.ID,p.Codes)
    case *snap.TrieNodesPacket:
        err=b.syncer.OnTrieNodes(peer,p.ID,p.Nodes)
    default:
        err=fmt.Errorf("R_P2N_UNHANDLED_SNAP_PACKET %T",pkt)
    }
    if err!=nil {
        b.stat.rejected.Add(1)
        b.cancel()
    }
    return err
}
func rP2NPhysical(t *testing.T,dir string)int64 {
    t.Helper()
    var bytes int64
    err:=filepath.Walk(dir,func(_ string,f os.FileInfo,e error)error{
        if e!=nil{return e}
        if !f.Mode().IsRegular(){return nil}
        st,ok:=f.Sys().(*syscall.Stat_t);if !ok{return fmt.Errorf("unsupported stat")}
        bytes+=st.Blocks*512
        return nil
    })
    if err!=nil{t.Fatal(err)}
    return bytes
}
func rP2NAvailable(t *testing.T,dir string)uint64 {
    t.Helper()
    var s syscall.Statfs_t
    if err:=syscall.Statfs(dir,&s);err!=nil{t.Fatal(err)}
    return uint64(s.Bavail)*uint64(s.Bsize)
}
func rP2NOpen(t *testing.T,path string)ethdb.Database {
    t.Helper()
    if err:=os.MkdirAll(path,0700);err!=nil{t.Fatal(err)}
    db,err:=rawdb.NewLevelDBDatabase(path,16,16,"r-p2n-rlpx-snap",false)
    if err!=nil{t.Fatal(err)}
    return db
}
type rP2NStateSource struct {
    db ethdb.Database
    root common.Hash
    account *trie.Trie
    accounts []*snap.AccountData
    accountRLP map[common.Hash][]byte
    storage map[common.Hash]*trie.Trie
}
func rP2NSource(t *testing.T,db ethdb.Database,root common.Hash)*rP2NStateSource {
    t.Helper()
    tr,err:=trie.New(root,trie.NewDatabase(db))
    if err!=nil{t.Fatal(err)}
    s:=&rP2NStateSource{db:db,root:root,account:tr,accountRLP:make(map[common.Hash][]byte),
        storage:make(map[common.Hash]*trie.Trie)}
    it:=trie.NewIterator(tr.NodeIterator(nil))
    for it.Next(){
        h:=common.BytesToHash(it.Key)
        var a types.StateAccount
        if err:=rlp.DecodeBytes(it.Value,&a);err!=nil{t.Fatal(err)}
        slim:=snapshot.SlimAccountRLP(a.Nonce,a.Balance,a.Root,a.CodeHash)
        s.accounts=append(s.accounts,&snap.AccountData{Hash:h,Body:slim})
        s.accountRLP[h]=append([]byte(nil),it.Value...)
        if a.Root!=types.EmptyRootHash {
            storageTrie,err:=trie.New(a.Root,trie.NewDatabase(db))
            if err!=nil{t.Fatalf("R_P2N_STORAGE_TRIE_ROOT_LOOKUP_FAIL root=%s err=%v",a.Root,err)}
            s.storage[h]=storageTrie
        }
    }
    if it.Err!=nil{t.Fatal(it.Err)}
    sort.Slice(s.accounts,func(i,j int)bool{
        return bytes.Compare(s.accounts[i].Hash[:],s.accounts[j].Hash[:])<0
    })
    return s
}
func (s *rP2NStateSource) accountRange(req snap.GetAccountRangePacket,mode string)([]*snap.AccountData,[][]byte,int64,error){
    accounts:=make([]*snap.AccountData,0,len(s.accounts))
    limit:=req.Limit
    if limit==(common.Hash{}){for i:=range limit{limit[i]=0xff}}
    var total int
    for _,a:=range s.accounts{
        if bytes.Compare(a.Hash[:],req.Origin[:])<0 {continue}
        if bytes.Compare(a.Hash[:],limit[:])>0 {break}
        accounts=append(accounts,&snap.AccountData{Hash:a.Hash,Body:append([]byte(nil),a.Body...)})
        total+=32+len(a.Body)
        if uint64(total)>req.Bytes {break}
    }
    proof:=light.NewNodeSet()
    if err:=s.account.Prove(req.Origin[:],0,proof);err!=nil{return nil,nil,0,err}
    if len(accounts)>0{
        if err:=s.account.Prove(accounts[len(accounts)-1].Hash[:],0,proof);err!=nil{return nil,nil,0,err}
    }
    nodes:=make([][]byte,0)
    for _,n:=range proof.NodeList(){nodes=append(nodes,append([]byte(nil),n...))}
    if mode=="corrupt-account"&&len(accounts)>0 {
        h:=accounts[0].Hash
        var v types.StateAccount
        if err:=rlp.DecodeBytes(s.accountRLP[h],&v);err!=nil{return nil,nil,0,err}
        v.Nonce++
        accounts[0].Body=snapshot.SlimAccountRLP(v.Nonce,v.Balance,v.Root,v.CodeHash)
    }
    var dup int64
    if mode=="duplicate-proofs"&&len(nodes)>0 {
        for i:=0;i<24;i++{
            cloned:=append([]byte(nil),nodes[0]...)
            nodes=append(nodes,cloned)
            dup+=int64(len(cloned))
        }
    }
    return accounts,nodes,dup,nil
}
func(s *rP2NStateSource) storageRanges(req snap.GetStorageRangesPacket)([][]*snap.StorageData,[][]byte,error){
    sets:=make([][]*snap.StorageData,0)
    for _,h:=range req.Accounts{
        tr:=s.storage[h]
        if tr==nil {continue}
        items:=make([]*snap.StorageData,0)
        it:=trie.NewIterator(tr.NodeIterator(nil))
        for it.Next(){
            hash:=common.BytesToHash(it.Key)
            if len(req.Origin)>0&&bytes.Compare(hash[:],req.Origin)<0 {continue}
            if len(req.Limit)>0&&bytes.Compare(hash[:],req.Limit)>0 {break}
            items=append(items,&snap.StorageData{Hash:hash,Body:append([]byte(nil),it.Value...)})
        }
        if it.Err!=nil{return nil,nil,it.Err}
        if len(items)>0{sets=append(sets,items)}
    }
    // Every requested storage subtree is small and fully delivered,
    // permitting verification by recomputing its root with no range proofs.
    return sets,nil,nil
}
func(s *rP2NStateSource) trieNodes(req snap.GetTrieNodesPacket)([][]byte,error){
    var out [][]byte
    for _,paths:=range req.Paths{
        if len(paths)==1{
            blob,_,err:=s.account.TryGetNode(paths[0])
            if err!=nil{return nil,err}
            if len(blob)>0{out=append(out,blob)}
        }else if len(paths)>1{
            tr:=s.storage[common.BytesToHash(paths[0])]
            if tr==nil{continue}
            for _,path:=range paths[1:]{
                blob,_,err:=tr.TryGetNode(path)
                if err!=nil{return nil,err}
                if len(blob)>0{out=append(out,blob)}
            }
        }
    }
    return out,nil
}
func rP2NSend(rw p2p.MsgReadWriter,code uint64,pkt interface{},stat *rP2NStats)error{
    b,err:=rlp.EncodeToBytes(pkt);if err!=nil{return err}
    if len(b)>4<<20{return fmt.Errorf("R_P2N_BOUNDED_PACKET_EXCEEDED size=%d",len(b))}
    err=rw.WriteMsg(p2p.Msg{Code:code,Size:uint32(len(b)),Payload:bytes.NewReader(b)})
    if err==nil{stat.replyBytes.Add(int64(len(b)))}
    return err
}
func rP2NAdversarialProtocol(s *rP2NStateSource,mode string,stat *rP2NStats)p2p.Protocol{
    return p2p.Protocol{
        Name:snap.ProtocolName,Version:snap.SNAP1,Length:8,
        Run:func(_ *p2p.Peer,rw p2p.MsgReadWriter)error{
            stat.connected.Add(1)
            defer stat.disconnect.Add(1)
            for{
                msg,err:=rw.ReadMsg()
                if err!=nil{return err}
                switch msg.Code{
                case snap.GetAccountRangeMsg:
                    var q snap.GetAccountRangePacket
                    err=msg.Decode(&q);msg.Discard()
                    if err!=nil{return err}
                    stat.accountReq.Add(1)
                    if q.Root!=s.root{return fmt.Errorf("R_P2N_ROOT_UNEXPECTED %s",q.Root)}
                    accounts,proof,dup,err:=s.accountRange(q,mode)
                    if err!=nil{return err}
                    stat.duplicateProofBytes.Add(dup)
                    if mode=="unsolicited-id"{
                        err=rP2NSend(rw,snap.AccountRangeMsg,&snap.AccountRangePacket{
                            ID:q.ID^0x77700000,Accounts:accounts,Proof:proof,
                        },stat)
                        if err!=nil{return err}
                        stat.fakeIDs.Add(1)
                    }
                    err=rP2NSend(rw,snap.AccountRangeMsg,&snap.AccountRangePacket{
                        ID:q.ID,Accounts:accounts,Proof:proof,
                    },stat)
                    if err!=nil{return err}
                case snap.GetStorageRangesMsg:
                    var q snap.GetStorageRangesPacket
                    err=msg.Decode(&q);msg.Discard()
                    if err!=nil{return err}
                    stat.storageReq.Add(1)
                    slots,proof,err:=s.storageRanges(q)
                    if err!=nil{return err}
                    if mode=="corrupt-storage"&&len(slots)>0&&len(slots[0])>0{
                        slots[0][0].Body=append([]byte(nil),slots[0][0].Body...)
                        slots[0][0].Body[len(slots[0][0].Body)-1]^=0x01
                    }
                    if err:=rP2NSend(rw,snap.StorageRangesMsg,&snap.StorageRangesPacket{
                        ID:q.ID,Slots:slots,Proof:proof,
                    },stat);err!=nil{return err}
                case snap.GetByteCodesMsg:
                    var q snap.GetByteCodesPacket
                    err=msg.Decode(&q);msg.Discard()
                    if err!=nil{return err}
                    stat.codeReq.Add(1)
                    codes:=make([][]byte,0,len(q.Hashes))
                    for _,hash:=range q.Hashes {codes=append(codes,rawdb.ReadCode(s.db,hash))}
                    if mode=="corrupt-code"&&len(codes)>0{codes[0]=[]byte("P2N_DIFFERENT_CODE")}
                    if err:=rP2NSend(rw,snap.ByteCodesMsg,&snap.ByteCodesPacket{
                        ID:q.ID,Codes:codes,
                    },stat);err!=nil{return err}
                case snap.GetTrieNodesMsg:
                    var q snap.GetTrieNodesPacket
                    err=msg.Decode(&q);msg.Discard()
                    if err!=nil{return err}
                    stat.trieReq.Add(1)
                    nodes,err:=s.trieNodes(q)
                    if err!=nil{return err}
                    if mode=="corrupt-trienode"&&len(nodes)>0{
                        nodes[0]=append([]byte(nil),nodes[0]...)
                        nodes[0][len(nodes[0])-1]^=0x01
                    }
                    if err:=rP2NSend(rw,snap.TrieNodesMsg,&snap.TrieNodesPacket{
                        ID:q.ID,Nodes:nodes,
                    },stat);err!=nil{return err}
                default:
                    msg.Discard()
                    return fmt.Errorf("R_P2N_UNEXPECTED_SNAP_REQUEST code=%d",msg.Code)
                }
            }
        },
    }
}
func rP2NServer(t *testing.T,name string,proto p2p.Protocol)*p2p.Server {
    t.Helper()
    key,err:=crypto.GenerateKey();if err!=nil{t.Fatal(err)}
    srv:=&p2p.Server{Config:p2p.Config{
        Name:name,PrivateKey:key,MaxPeers:2,NoDiscovery:true,NoDial:true,
        ListenAddr:"127.0.0.1:0",Protocols:[]p2p.Protocol{proto},
    }}
    if err:=srv.Start();err!=nil{t.Fatal(err)}
    return srv
}
type rP2NCase struct {
    mode string
    disk int64
    snapshotCount int
    complete bool
    stats *rP2NStats
}
func rP2NRun(t *testing.T,dir string,source *rP2NStateSource,chain *core.BlockChain,mode string)rP2NCase{
    t.Helper()
    db:=rP2NOpen(t,dir)
    before:=rP2NPhysical(t,dir)
    var once sync.Once
    cancel:=make(chan struct{})
    stop:=func(){once.Do(func(){close(cancel)})}
    timeout:=time.AfterFunc(10*time.Second,stop)
    defer timeout.Stop()
    stats:=new(rP2NStats)
    syncer:=snap.NewSyncer(db)
    backend:=&rP2NBackend{chain:chain,syncer:syncer,stat:stats,cancel:stop}
    ready:=make(chan struct{},1)
    recvProto:=p2p.Protocol{Name:snap.ProtocolName,Version:snap.SNAP1,Length:8,
        Run:func(p *p2p.Peer,rw p2p.MsgReadWriter)error{
            sp:=snap.NewPeer(snap.SNAP1,p,rw)
            if err:=syncer.Register(sp);err!=nil{return err}
            defer syncer.Unregister(sp.ID())
            ready<-struct{}{}
            return snap.Handle(backend,sp) // certified parser and bounded decoder
        },
    }
    remote:=rP2NServer(t,"p2n-remote-"+mode,rP2NAdversarialProtocol(source,mode,stats))
    local:=rP2NServer(t,"p2n-recipient-"+mode,recvProto)
    defer remote.Stop()
    defer local.Stop()
    local.AddPeer(remote.Self())
    select{
    case <-ready:
    case <-time.After(5*time.Second):
        t.Fatal("R_P2N_LOOPBACK_SNAP1_HANDSHAKE_FAILED")
    }
    if local.PeerCount()<1||remote.PeerCount()<1{
        t.Fatalf("R_P2N_SNAP1_TRANSPORT_NOT_CONNECTED mode=%s",mode)
    }
    t.Logf("R_P2N_REAL_RLPX_SNAP1_PEER_CONNECTED mode=%s local=%s remote=%s source_root=%s",
        mode,local.ListenAddr,remote.ListenAddr,source.root)
    err:=syncer.Sync(source.root,cancel)
    stop()
    local.Stop();remote.Stop()
    if stats.accountReq.Load()<1 {
        t.Fatalf("R_P2N_STATE_SYNC_NO_ACTUAL_ACCOUNT_REQUEST mode=%s err=%v",mode,err)
    }
    positive:=mode=="honest"||mode=="duplicate-proofs"||mode=="unsolicited-id"
    if positive&&err!=nil{t.Fatalf("R_P2N_VALID_SNAP_SYNC_FAIL mode=%s err=%v",mode,err)}
    if !positive&&err==nil{t.Fatalf("R_P2N_CORRUPT_SNAP_SYNC_UNEXPECTED_COMPLETION mode=%s",mode)}
    if !positive&&stats.rejected.Load()==0 {
        t.Fatalf("R_P2N_CORRUPT_PAYLOAD_NOT_REJECTED mode=%s requests=%d/%d/%d/%d",
            mode,stats.accountReq.Load(),stats.storageReq.Load(),stats.codeReq.Load(),stats.trieReq.Load())
    }
    pre:=rP2NPhysical(t,dir)-before
    if err:=db.Compact(nil,nil);err!=nil{t.Fatal(err)}
    if err:=db.Close();err!=nil{t.Fatal(err)}
    check:=rP2NOpen(t,dir)
    snapshots:=0
    for _,a:=range source.accounts {
        if len(rawdb.ReadAccountSnapshot(check,a.Hash))>0{snapshots++}
    }
    if positive {
        tr,err:=trie.New(source.root,trie.NewDatabase(check))
        if err!=nil{t.Fatalf("R_P2N_RESTART_VALID_ROOT_MISSING mode=%s err=%v",mode,err)}
        it:=trie.NewIterator(tr.NodeIterator(nil))
        count:=0
        for it.Next(){count++}
        if it.Err!=nil{t.Fatal(it.Err)}
        if count!=len(source.accounts)||snapshots!=count {
            t.Fatalf("R_P2N_RESTART_STATE_INCOMPLETE mode=%s trie=%d flat=%d expected=%d",
                mode,count,snapshots,len(source.accounts))
        }
        if stats.storageReq.Load()==0||stats.codeReq.Load()==0||stats.trieReq.Load()==0 {
            t.Fatalf("R_P2N_FULL_PATH_NOT_EXERCISED mode=%s account=%d storage=%d code=%d trie=%d",
                mode,stats.accountReq.Load(),stats.storageReq.Load(),stats.codeReq.Load(),stats.trieReq.Load())
        }
    }
    if err:=check.Close();err!=nil{t.Fatal(err)}
    disk:=rP2NPhysical(t,dir)
    t.Logf("R_P2N_MODE mode=%s full_sync=%t live_snap1_connected=%d requested_account=%d requested_storage=%d requested_code=%d requested_trienodes=%d received_responses=%d rejected_responses=%d unknown_ID_responses=%d extra_proof_bytes=%d outbound_peer_bytes=%d live_growth=%d durable_after_restart=%d snapshot_accounts=%d sync_err=%v",
        mode,positive,stats.connected.Load(),stats.accountReq.Load(),stats.storageReq.Load(),
        stats.codeReq.Load(),stats.trieReq.Load(),stats.received.Load(),stats.rejected.Load(),
        stats.fakeIDs.Load(),stats.duplicateProofBytes.Load(),stats.replyBytes.Load(),
        pre,disk,snapshots,err)
    return rP2NCase{mode:mode,disk:disk,snapshotCount:snapshots,complete:positive,stats:stats}
}
func TestRQBFTFinalizedRootLiveSnap1StateIngestion(t *testing.T) {
    folder:=os.Getenv("R_P2N_DISK_ROOT")
    if folder==""{t.Skip("R_P2N_DISK_ROOT unset")}
    if err:=os.MkdirAll(folder,0700);err!=nil{t.Fatal(err)}
    freeBefore:=rP2NAvailable(t,folder)
    if freeBefore<160<<20{t.Fatal("R_P2N_HEALTHY_DISK_PRECONDITION")}
    keys,addresses:=rP1HValidators(t)
    senderKey,err:=crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
    if err!=nil{t.Fatal(err)}
    genesis:=rQBFTNetworkGenesis(t,keys,crypto.PubkeyToAddress(senderKey.PublicKey))
    // A contract plus many ordinary accounts force all four SNAP categories:
    // account range, bytecode, contract storage range, trienode healing.
    caddr:=common.HexToAddress("0x00000000000000000000000000000000aabb1122")
    code:=[]byte{0x60,0x04,0x60,0x00,0x52,0x60,0x20,0x60,0x00,0xf3}
    genesis.Alloc[caddr]=core.GenesisAccount{
        Balance:big.NewInt(1),Code:code,Storage:map[common.Hash]common.Hash{
            common.BigToHash(big.NewInt(1)):common.BigToHash(big.NewInt(101)),
            common.BigToHash(big.NewInt(2)):common.BigToHash(big.NewInt(102)),
            common.BigToHash(big.NewInt(3)):common.BigToHash(big.NewInt(103)),
        },
    }
    for i:=0;i<96;i++{
        addr:=common.BigToAddress(big.NewInt(int64(50000+i)))
        genesis.Alloc[addr]=core.GenesisAccount{Balance:big.NewInt(int64(100+i))}
    }
    db,chain,be:=rQBFTStartChain(t,genesis,keys[0])
    defer func(){be.Stop();chain.Stop();db.Close()}()
    tx:=rP1HSignedTx(t,chain,senderKey,0xB9)
    finalized:=rQBFTBuildAndImport(t,chain,be,db,keys,addresses,tx)
    if err:=be.VerifyHeader(chain,finalized.Header(),true);err!=nil {
        t.Fatalf("R_P2N_QBFT_FINALITY_VERIFICATION_FAILED %v",err)
    }
    extra,err:=types.ExtractQBFTExtra(finalized.Header());if err!=nil{t.Fatal(err)}
    if len(extra.CommittedSeal)!=3{t.Fatalf("R_P2N_BAD_QBFT_QUORUM %d",len(extra.CommittedSeal))}
    stateRoot:=finalized.Root()
    source:=rP2NSource(t,db,stateRoot)
    if len(source.storage)==0||len(source.accounts)<96 {t.Fatal("R_P2N_FIXTURE_MISSING_STORAGE_OR_ACCOUNTS")}
    t.Logf("R_P2N_QBFT_FINALIZED_ROOT_VERIFIED block_number=%d block_hash=%s state_root=%s committed_seals=%d validator_count=4 state_accounts=%d contract_tries=%d attacker_validator_keys=0",
        finalized.NumberU64(),finalized.Hash(),stateRoot,len(extra.CommittedSeal),len(source.accounts),len(source.storage))
    modes:=[]string{"honest","duplicate-proofs","unsolicited-id","corrupt-account","corrupt-code","corrupt-storage","corrupt-trienode"}
    outcomes:=make(map[string]rP2NCase)
    for _,mode:=range modes{
        t.Run(mode,func(t *testing.T){
            outcomes[mode]=rP2NRun(t,filepath.Join(folder,mode),source,chain,mode)
        })
    }
    honest:=outcomes["honest"].disk
    for _,mode:=range []string{"duplicate-proofs","unsolicited-id"}{
        got:=outcomes[mode]
        if got.disk>honest+64<<10{
            t.Fatalf("R_P2N_DURABLE_EXCESS_OVER_VALID_STATE mode=%s bytes=%d honest=%d",
                mode,got.disk,honest)
        }
    }
    if outcomes["duplicate-proofs"].stats.duplicateProofBytes.Load()==0{
        t.Fatal("R_P2N_DUPLICATE_WITNESS_NOT_TRANSMITTED")
    }
    if outcomes["unsolicited-id"].stats.fakeIDs.Load()==0{
        t.Fatal("R_P2N_UNKNOWN_ID_NOT_SENT")
    }
    for _,mode:=range []string{"corrupt-account","corrupt-code","corrupt-storage","corrupt-trienode"}{
        if outcomes[mode].stats.rejected.Load()==0{
            t.Fatalf("R_P2N_NEGATIVE_CASE_NOT_REJECTED mode=%s",mode)
        }
    }
    after:=rP2NAvailable(t,folder)
    t.Logf("R_P2N_DURABLE_STATE_ORACLE positive_honest=%d duplicate_proofs=%d unsolicited_ID=%d duplicate_excess=%d unknown_ID_excess=%d free_before=%d free_after=%d",
        honest,outcomes["duplicate-proofs"].disk,outcomes["unsolicited-id"].disk,
        outcomes["duplicate-proofs"].disk-honest,outcomes["unsolicited-id"].disk-honest,
        freeBefore,after)
    if after<100<<20 {t.Fatal("R_P2N_HEALTHY_DISK_EXHAUSTED")}
    t.Log("R_P2N_VALIDATED tcp_rlpx_snap1=true shipped_snap_message_parser=true real_production_SnapSyncer=true QBFT_3of4_finalized_root=true account_storage_bytecode_trienode_requests=true real_LevelDB_reopen=true unprivileged_peer=true full_eth_plus_snap_registration=NOT_TESTED remote_validator_termination=NOT_PROVEN")
}
