//go:build linux

// Worker R P2l: a zero-validator-key ETH/66 peer advertises a forged
// noncanonical QBFT successor and transmits bounded NodeData response
// variants. Compare physical LevelDB allocation with an independent direct
// canonical import and measure process-level CPU, latency and session churn.
//
// Only the fixture signs the canonical and future blocks. The malicious
// network peer never receives the validator keys. The matched NodeData request
// is diagnostic, not an assertion of a production state-sync persistence path.
package eth

import (
    "bytes"
    "fmt"
    "math/big"
    "os"
    "path/filepath"
    "runtime"
    "sync"
    "sync/atomic"
    "syscall"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/forkid"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/eth/downloader"
    ethproto "github.com/electroneum/electroneum-sc/eth/protocols/eth"
    "github.com/electroneum/electroneum-sc/p2p"
    "github.com/electroneum/electroneum-sc/rlp"
)

type rP2LWireSession struct {
    rw p2p.MsgReadWriter
    mu sync.Mutex
    outboundBytes atomic.Int64
    headerRequests atomic.Int64
    nodeRequests atomic.Int64
    bodyRequests atomic.Int64
    replies atomic.Int64
}
func (s *rP2LWireSession) send(code uint64, packet interface{}) (int,error) {
    raw,err:=rlp.EncodeToBytes(packet)
    if err!=nil {return 0,err}
    if len(raw)>9<<20 {return 0,fmt.Errorf("R_P2L_OVERSIZED_TEST_FRAME len=%d",len(raw))}
    s.mu.Lock()
    defer s.mu.Unlock()
    err=s.rw.WriteMsg(p2p.Msg{Code:code,Size:uint32(len(raw)),Payload:bytes.NewReader(raw)})
    if err==nil {s.outboundBytes.Add(int64(len(raw)))}
    return len(raw),err
}

type rP2LRemoteControl struct {
    ready chan *rP2LWireSession
    replyMode string
    canonical *types.Block
    invalid *types.Block
    genesis *types.Block
    td *big.Int
    fid forkid.ID
}
func rP2LAdversarialProtocol(control *rP2LRemoteControl) p2p.Protocol {
    return p2p.Protocol{
        Name:ethproto.ProtocolName,Version:ethproto.ETH66,Length:17,
        Run:func(p *p2p.Peer,rw p2p.MsgReadWriter)error{
            ep:=ethproto.NewPeer(ethproto.ETH66,p,rw,newTestTxPool())
            defer ep.Close()
            if err:=ep.Handshake(1,control.td,control.canonical.Hash(),
                control.genesis.Hash(),control.fid,func(forkid.ID)error{return nil});err!=nil{return err}
            wire:=&rP2LWireSession{rw:rw}
            control.ready<-wire
            for {
                msg,err:=rw.ReadMsg()
                if err!=nil{return err}
                switch msg.Code {
                case ethproto.GetBlockHeadersMsg:
                    var query ethproto.GetBlockHeadersPacket66
                    err=msg.Decode(&query)
                    msg.Discard()
                    if err!=nil{return err}
                    wire.headerRequests.Add(1)
                    var headers []*types.Header
                    if query.Origin.Hash==control.invalid.Hash() ||
                        (query.Origin.Hash==(common.Hash{}) && query.Origin.Number==control.invalid.NumberU64()) {
                        headers=[]*types.Header{control.invalid.Header()}
                    } else {
                        headers=rP1HRemoteHeaders(query.GetBlockHeadersPacket,control.genesis.Header(),control.canonical.Header())
                    }
                    _,err=wire.send(ethproto.BlockHeadersMsg,&ethproto.BlockHeadersPacket66{
                        RequestId:query.RequestId,BlockHeadersPacket:headers,
                    })
                    if err!=nil{return err}
                    wire.replies.Add(1)
                case ethproto.GetBlockBodiesMsg:
                    var query ethproto.GetBlockBodiesPacket66
                    err=msg.Decode(&query)
                    msg.Discard()
                    if err!=nil{return err}
                    wire.bodyRequests.Add(1)
                    var bodies ethproto.BlockBodiesPacket
                    for _,hash:=range query.GetBlockBodiesPacket {
                        if hash==control.invalid.Hash(){
                            bodies=append(bodies,&ethproto.BlockBody{Transactions:control.invalid.Transactions(),Uncles:control.invalid.Uncles()})
                        }else if hash==control.canonical.Hash(){
                            bodies=append(bodies,&ethproto.BlockBody{Transactions:control.canonical.Transactions(),Uncles:control.canonical.Uncles()})
                        }
                    }
                    _,err=wire.send(ethproto.BlockBodiesMsg,&ethproto.BlockBodiesPacket66{
                        RequestId:query.RequestId,BlockBodiesPacket:bodies,
                    })
                    if err!=nil{return err}
                    wire.replies.Add(1)
                case ethproto.GetNodeDataMsg:
                    var query ethproto.GetNodeDataPacket66
                    err=msg.Decode(&query)
                    msg.Discard()
                    if err!=nil{return err}
                    wire.nodeRequests.Add(1)
                    // This peer sends data without any trie proof. A matching
                    // ETH66 ID tests dispatcher acceptance, NOT persistence.
                    payload:=bytes.Repeat([]byte{0x41,0x42,0x43,0x44},8<<10) // 32 KiB
                    if control.replyMode=="wrongtype" {
                        _,err=wire.send(ethproto.BlockBodiesMsg,&ethproto.BlockBodiesPacket66{
                            RequestId:query.RequestId,
                            BlockBodiesPacket:ethproto.BlockBodiesPacket{},
                        })
                    } else {
                        nodes:=ethproto.NodeDataPacket{payload}
                        if control.replyMode=="overlimit" {
                            nodes=append(nodes,append([]byte(nil),payload...))
                        }
                        _,err=wire.send(ethproto.NodeDataMsg,&ethproto.NodeDataPacket66{
                            RequestId:query.RequestId,NodeDataPacket:nodes,
                        })
                    }
                    if err!=nil{return err}
                    wire.replies.Add(1)
                default:
                    msg.Discard()
                }
            }
        },
    }
}

func rP2LProcessCPUus(t *testing.T) int64 {
    t.Helper()
    var r syscall.Rusage
    if err:=syscall.Getrusage(syscall.RUSAGE_SELF,&r);err!=nil{t.Fatal(err)}
    return (r.Utime.Sec+r.Stime.Sec)*1_000_000+
        (r.Utime.Usec+r.Stime.Usec)
}

func rP2LNoCanonicalLeak(t *testing.T,chain *core.BlockChain,head,invalid *types.Block) {
    t.Helper()
    if chain.CurrentBlock().Hash()!=head.Hash(){
        t.Fatalf("R_P2L_UNTRUSTED_CANONICAL_REWRITE got=%s want=%s",
            chain.CurrentBlock().Hash(),head.Hash())
    }
    if chain.GetBlockByHash(invalid.Hash())!=nil{
        t.Fatalf("R_P2L_UNTRUSTED_NONCANONICAL_BLOCK_PERSISTED hash=%s",invalid.Hash())
    }
}

func TestRQBFTLowerAuthorityNodeDataNoncanonicalChurn(t *testing.T) {
    root:=os.Getenv("R_P2L_DISK_ROOT")
    if root==""{t.Skip("R_P2L_DISK_ROOT unset")}
    if err:=os.MkdirAll(root,0700);err!=nil{t.Fatal(err)}
    if rG6AvailBytes(t,root)<128<<20{t.Fatal("R_P2L_HEALTHY_RESERVE_PRECONDITION_FAIL")}
    startFree:=rG6AvailBytes(t,root)

    f,senderKey:=rP1HBaseFixture(t)
    defer f.close()
    canonicalTx:=rP1HSignedTx(t,f.remoteChain,senderKey,0xC1)
    canonical:=rQBFTBuildAndImport(t,f.remoteChain,f.remoteQBFT,f.remoteDB,
        f.validatorKeys,f.validators,canonicalTx)
    futureTx:=rP1HSignedTx(t,f.remoteChain,senderKey,0xC2)
    futureValid:=rQBFTBuildAndImport(t,f.remoteChain,f.remoteQBFT,f.remoteDB,
        f.validatorKeys,f.validators,futureTx)
    invalid:=rP1HMakeSubquorum(t,futureValid,f.validatorKeys)
    if invalid.Hash()!=futureValid.Hash(){t.Fatal("R_P2L_BAD_COMMITMENT_HASH_DOMAIN")}
    // This is a nonvalidator relay adversary: it can remove seals but cannot
    // make the missing third seal itself.
    for futureValid.Time()>uint64(time.Now().Unix())+5 {time.Sleep(100*time.Millisecond)}

    genesis:=rQBFTNetworkGenesis(t,f.validatorKeys,crypto.PubkeyToAddress(senderKey.PublicKey))
    wirePath,directPath:=filepath.Join(root,"eth66"),filepath.Join(root,"direct")
    wireDB,wireChain,wireBE:=rP2JDiskChain(t,wirePath,genesis,f.validatorKeys[0])
    directDB,directChain,directBE:=rP2JDiskChain(t,directPath,genesis,f.validatorKeys[0])
    wireClosed,directClosed:=false,false
    t.Cleanup(func(){
        if !wireClosed{_ = rP2JStopChain(wireBE,wireChain,wireDB)}
        if !directClosed{_ = rP2JStopChain(directBE,directChain,directDB)}
    })
    directBefore:=rG6PhysicalBytes(t,directPath)
    if i,err:=directChain.InsertChain(types.Blocks{canonical});err!=nil{
        t.Fatalf("R_P2L_DIRECT_BASELINE_IMPORT_FAIL idx=%d err=%v",i,err)
    }
    directAfter:=rG6PhysicalBytes(t,directPath)
    rP2JValidateCanonical(t,directDB,directChain,canonical,canonicalTx,nil)

    localHandler:=rDevP2PHandler(t,wireDB,wireChain)
    localServer:=rDevP2PServer(t,"r-p2l-receiver",localHandler,false)
    stopNetwork:=false
    t.Cleanup(func(){if !stopNetwork{localServer.Stop();localHandler.Stop()}})
    wireState:=new(rP1HWireState)
    remoteTD:=f.remoteChain.GetTd(canonical.Hash(),canonical.NumberU64())
    proto:=rP1HRemoteProtocol(t,wireChain.Genesis(),canonical,remoteTD,
        forkid.NewID(wireChain.Config(),wireChain.Genesis().Hash(),canonical.NumberU64()),wireState)
    honest:=rP1HRemoteServer(t,"r-p2l-honest-baseline",proto)
    honestStopped:=false
    t.Cleanup(func(){if !honestStopped{honest.Stop()}})
    wireBefore:=rG6PhysicalBytes(t,wirePath)
    localServer.AddPeer(honest.Self())
    peer:=rP1HWaitRegisteredPeer(t,localHandler,honest)
    hh,td:=peer.Head()
    if err:=localHandler.downloader.LegacySync(peer.ID(),hh,td,
        wireChain.Config().TerminalTotalDifficulty,downloader.FullSync);err!=nil{
        t.Fatalf("R_P2L_REAL_ETH66_CANONICAL_SYNC_FAIL: %v",err)
    }
    rP2JValidateCanonical(t,wireDB,wireChain,canonical,canonicalTx,nil)
    if err:=wireBE.VerifyHeader(wireChain,invalid.Header(),true);err==nil {
        t.Fatal("R_P2L_SUBQUORUM_HEADER_UNEXPECTED_DIRECT_ACCEPT")
    } else {
        t.Logf("R_P2L_SUBQUORUM_DIRECT_VERIFIER_REJECTED seals=2of4 err=%v",err)
    }
    wireAfter:=rG6PhysicalBytes(t,wirePath)
    t.Logf("R_P2L_CANONICAL_BASELINE height=%d wire_growth=%d direct_growth=%d wire_body_responses=%d attacker_keys=0",
        canonical.NumberU64(),wireAfter-wireBefore,directAfter-directBefore,wireState.bodyResponses.Load())
    localServer.RemovePeer(honest.Self())
    honest.Stop()
    honestStopped=true

    var totalSessionUs,totalCPUus,totalAttackBytes,totalOutboundBytes,totalDelta int64
    var announced,requested,bodyRequested,disconnects int64
    var positiveNode,deniedNode,matchedInvalidHeaders,matchedInvalidBodies int
    // Use a fresh devp2p identity on each attempt to measure connection
    // churn. No loop performs more than one active malicious connection.
    modes:=[]string{"announcement","propagated","matched-invalid-header","matched-invalid-body",
        "matched-node","overlimit-node","wrongtype-node",
        "unsolicited-node-1","unsolicited-node-2","unsolicited-node-3"}
    const unsolicitedID=0xE9F0331155779911
    for idx,mode:=range modes{
        t.Run(mode,func(t *testing.T){
            scenario:="matched"
            if mode=="overlimit-node"{scenario="overlimit"}
            if mode=="wrongtype-node"{scenario="wrongtype"}
            control:=&rP2LRemoteControl{
                ready:make(chan *rP2LWireSession,1),
                replyMode:scenario,canonical:canonical,invalid:invalid,
                genesis:wireChain.Genesis(),td:remoteTD,
                fid:forkid.NewID(wireChain.Config(),wireChain.Genesis().Hash(),canonical.NumberU64()),
            }
            beforeBytes:=rG6PhysicalBytes(t,wirePath)
            cpuStart:=rP2LProcessCPUus(t)
            var mem0,mem1 runtime.MemStats
            runtime.ReadMemStats(&mem0)
            begin:=time.Now()
            malicious:=rP1HRemoteServer(t,fmt.Sprintf("r-p2l-attacker-%d",idx),rP2LAdversarialProtocol(control))
            localServer.AddPeer(malicious.Self())
            _=rP1HWaitRegisteredPeer(t,localHandler,malicious)
            var wire *rP2LWireSession
            select{
            case wire=<-control.ready:
            case <-time.After(3*time.Second):t.Fatal("R_P2L_ATTACKER_HANDSHAKE_NOT_READY")
            }
            var sent int
            switch mode{
            case "announcement":
                // Unknown announced QBFT hash with only 2/4 committed seals:
                // the peer responds to any fetcher-requested header/body.
                var p ethproto.NewBlockHashesPacket
                p=append(p,struct{Hash common.Hash;Number uint64}{
                    Hash:invalid.Hash(),Number:invalid.NumberU64(),
                })
                n,err:=wire.send(ethproto.NewBlockHashesMsg,&p)
                if err!=nil{t.Fatalf("R_P2L_NONCANONICAL_ANNOUNCE_SEND_FAIL: %v",err)}
                sent+=n
                time.Sleep(450*time.Millisecond)
                announced++
            case "propagated":
                pkt:=&ethproto.NewBlockPacket{
                    Block:invalid,TD:new(big.Int).Add(remoteTD,big.NewInt(1)),
                }
                n,err:=wire.send(ethproto.NewBlockMsg,pkt)
                if err!=nil{t.Fatalf("R_P2L_NONCANONICAL_BLOCK_SEND_FAIL: %v",err)}
                sent+=n
                time.Sleep(450*time.Millisecond)
            case "matched-invalid-header":
                rp:=localHandler.peers.peer(malicious.Self().ID().String())
                if rp==nil{t.Fatal("R_P2L_HEADER_PEER_LOST_BEFORE_REQUEST")}
                sink:=make(chan *ethproto.Response,1)
                req,err:=rp.RequestOneHeader(invalid.Hash(),sink)
                if err!=nil{t.Fatalf("R_P2L_INVALID_HEADER_REQUEST_FAILED: %v",err)}
                select{
                case response:=<-sink:
                    headers,ok:=response.Res.(*ethproto.BlockHeadersPacket)
                    if !ok || len(*headers)!=1 || (*headers)[0].Hash()!=invalid.Hash(){
                        response.Done<-fmt.Errorf("R_P2L_INVALID_HEADER_WRONG_RESPONSE")
                        t.Fatal("R_P2L_INVALID_HEADER_WIRE_MISMATCH")
                    }
                    err:=wireBE.VerifyHeader(wireChain,(*headers)[0],true)
                    response.Done<-nil
                    if err==nil {t.Fatal("R_P2L_INVALID_HEADER_VERIFIER_UNEXPECTED_ACCEPT")}
                    matchedInvalidHeaders++
                    t.Logf("R_P2L_NONCANONICAL_REQUEST_VERIFIER_REJECTED header_hash=%s committed_seals=2/4 err=%v",invalid.Hash(),err)
                case <-time.After(4*time.Second):
                    _=req.Close()
                    t.Fatal("R_P2L_INVALID_HEADER_RESPONSE_NOT_DELIVERED")
                }
            case "matched-invalid-body":
                rp:=localHandler.peers.peer(malicious.Self().ID().String())
                if rp==nil{t.Fatal("R_P2L_BODY_PEER_LOST_BEFORE_REQUEST")}
                sink:=make(chan *ethproto.Response,1)
                req,err:=rp.RequestBodies([]common.Hash{invalid.Hash()},sink)
                if err!=nil{t.Fatalf("R_P2L_INVALID_BODY_REQUEST_FAILED: %v",err)}
                select{
                case response:=<-sink:
                    bodies,ok:=response.Res.(*ethproto.RawBlockBodiesPacket)
                    if !ok || len(*bodies)!=1 {
                        response.Done<-fmt.Errorf("R_P2L_INVALID_BODY_WRONG_RESPONSE")
                        t.Fatal("R_P2L_INVALID_BODY_WIRE_MISMATCH")
                    }
                    txs,_,err:=(*bodies)[0].Decode()
                    response.Done<-nil
                    if err!=nil || len(txs)!=1 || txs[0].Hash()!=futureTx.Hash(){
                        t.Fatalf("R_P2L_INVALID_BODY_CONTENT_MISMATCH err=%v count=%d",err,len(txs))
                    }
                    matchedInvalidBodies++
                    t.Logf("R_P2L_NONCANONICAL_BODY_WIRE_DELIVERED body_tx_count=%d invalid_header_seals=2/4 direct_import_not_attempted=true",len(txs))
                case <-time.After(4*time.Second):
                    _=req.Close()
                    t.Fatal("R_P2L_INVALID_BODY_RESPONSE_NOT_DELIVERED")
                }
            case "matched-node","overlimit-node","wrongtype-node":
                rp:=localHandler.peers.peer(malicious.Self().ID().String())
                if rp==nil{t.Fatal("R_P2L_NODE_PEER_LOST_BEFORE_REQUEST")}
                sink:=make(chan *ethproto.Response,1)
                hashes:=[]common.Hash{crypto.Keccak256Hash([]byte("R_P2L_DIAGNOSTIC_NODE_HASH"))}
                req,err:=rp.RequestNodeData(hashes,sink)
                if err!=nil{t.Fatalf("R_P2L_NODE_REQUEST_FAILED: %v",err)}
                if mode=="matched-node" {
                    select{
                    case response:=<-sink:
                        data,ok:=response.Res.(*ethproto.NodeDataPacket)
                        if !ok||len(*data)!=1||len((*data)[0])!=32<<10{
                            response.Done<-fmt.Errorf("R_P2L_MATCHED_NODE_PAYLOAD_INVALID")
                            t.Fatal("R_P2L_NODE_REQUEST_RESPONSE_BAD_PAYLOAD")
                        }
                        response.Done<-nil
                        positiveNode++
                    case <-time.After(4*time.Second):
                        _=req.Close()
                        t.Fatal("R_P2L_NODE_VALID_RESPONSE_NOT_DELIVERED")
                    }
                }else{
                    // Incorrect item count/type must disconnect without data
                    // being handed to the downloader or persisted.
                    rWaitFor(t,4*time.Second,"R_P2L_BAD_NODE_RESPONSE_PEER_NOT_DROPPED",func()bool{
                        return localHandler.peers.peer(malicious.Self().ID().String())==nil
                    })
                    deniedNode++
                }
            default:
                payload:=bytes.Repeat([]byte{0x65,0x31,0x42,0xA8},16<<10) //64KiB
                n,err:=wire.send(ethproto.NodeDataMsg,&ethproto.NodeDataPacket66{
                    RequestId:unsolicitedID+uint64(idx),
                    NodeDataPacket:ethproto.NodeDataPacket{payload},
                })
                if err!=nil{t.Fatalf("R_P2L_NODE_UNSOLICITED_SEND_FAILED: %v",err)}
                sent+=n
                rWaitFor(t,4*time.Second,"R_P2L_UNSOLICITED_NODE_NOT_DROPPED",func()bool{
                    return localHandler.peers.peer(malicious.Self().ID().String())==nil
                })
            }
            rP2LNoCanonicalLeak(t,wireChain,canonical,invalid)
            localServer.RemovePeer(malicious.Self())
            malicious.Stop()
            afterBytes:=rG6PhysicalBytes(t,wirePath)
            runtime.ReadMemStats(&mem1)
            elapsedUs:=time.Since(begin).Microseconds()
            cpuUs:=rP2LProcessCPUus(t)-cpuStart
            delta:=afterBytes-beforeBytes
            totalSessionUs+=elapsedUs
            totalCPUus+=cpuUs
            totalAttackBytes+=int64(sent)
            totalOutboundBytes+=wire.outboundBytes.Load()
            totalDelta+=delta
            requested+=wire.headerRequests.Load()
            bodyRequested+=wire.bodyRequests.Load()
            disconnects++
            t.Logf("R_P2L_CASE mode=%s session_wall_including_dwell_us=%d aggregate_process_cpu_us=%d injected_bytes=%d all_remote_outbound_bytes=%d response_count=%d headers_requested=%d node_requests=%d body_requests=%d physical_db_delta=%d heap_alloc_delta=%d peer_detached=true",
                mode,elapsedUs,cpuUs,sent,wire.outboundBytes.Load(),wire.replies.Load(),
                wire.headerRequests.Load(),wire.nodeRequests.Load(),wire.bodyRequests.Load(),
                delta,int64(mem1.HeapAlloc)-int64(mem0.HeapAlloc))
        })
    }
    rP2LNoCanonicalLeak(t,wireChain,canonical,invalid)
    t.Logf("R_P2L_CHURN_TOTAL sessions=%d total_wall_including_dwell_us=%d aggregate_process_cpu_us=%d injected_attack_bytes=%d total_peer_outbound_bytes=%d persistent_growth_during_sessions=%d protocol_header_requests=%d protocol_body_requests=%d requested_invalid_headers=%d requested_invalid_bodies=%d successfully_matched_node=%d rejected_bad_node=%d peer_detachments=%d",
        len(modes),totalSessionUs,totalCPUus,totalAttackBytes,totalOutboundBytes,totalDelta,
        requested,bodyRequested,matchedInvalidHeaders,matchedInvalidBodies,positiveNode,deniedNode,disconnects)
    if positiveNode!=1||deniedNode!=2||matchedInvalidHeaders!=1||matchedInvalidBodies!=1||
        requested<1||bodyRequested<1||disconnects!=int64(len(modes)){
        t.Fatalf("R_P2L_COVERAGE_GATE_FAILED matched_node=%d denied_node=%d invalid_headers=%d invalid_bodies=%d requests_headers=%d requests_bodies=%d detach=%d",
            positiveNode,deniedNode,matchedInvalidHeaders,matchedInvalidBodies,requested,bodyRequested,disconnects)
    }
    if announced!=1 {t.Fatal("R_P2L_ANNOUNCEMENT_NOT_SENT")}

    localServer.Stop()
    localHandler.Stop()
    stopNetwork=true
    preW,preD:=rG6PhysicalBytes(t,wirePath),rG6PhysicalBytes(t,directPath)
    if err:=wireDB.Compact(nil,nil);err!=nil{t.Fatal(err)}
    if err:=directDB.Compact(nil,nil);err!=nil{t.Fatal(err)}
    compactW,compactD:=rG6PhysicalBytes(t,wirePath),rG6PhysicalBytes(t,directPath)
    t.Logf("R_P2L_COMPACTION_ORACLE wire_pre=%d direct_pre=%d wire_post=%d direct_post=%d",
        preW,preD,compactW,compactD)
    if err:=rP2JStopChain(wireBE,wireChain,wireDB);err!=nil{t.Fatal(err)}
    wireClosed=true
    if err:=rP2JStopChain(directBE,directChain,directDB);err!=nil{t.Fatal(err)}
    directClosed=true

    reopenW:=rQBFTOpenDisk(t,wirePath)
    chainW,beW:=rQBFTEngine(t,reopenW,f.validatorKeys[0])
    rP2JValidateCanonical(t,reopenW,chainW,canonical,canonicalTx,nil)
    rP2LNoCanonicalLeak(t,chainW,canonical,invalid)
    if err:=rP2JStopChain(beW,chainW,reopenW);err!=nil{t.Fatal(err)}
    reopenD:=rQBFTOpenDisk(t,directPath)
    chainD,beD:=rQBFTEngine(t,reopenD,f.validatorKeys[0])
    rP2JValidateCanonical(t,reopenD,chainD,canonical,canonicalTx,nil)
    if err:=rP2JStopChain(beD,chainD,reopenD);err!=nil{t.Fatal(err)}
    finalW,finalD:=rG6PhysicalBytes(t,wirePath),rG6PhysicalBytes(t,directPath)
    free:=rG6AvailBytes(t,root)
    t.Logf("R_P2L_RESTART_STORAGE_ORACLE_PASS head=%d durable_wire=%d durable_direct=%d durable_excess=%d free_before=%d free_after=%d",
        canonical.NumberU64(),finalW,finalD,finalW-finalD,startFree,free)
    if finalW>finalD+64<<10 {
        t.Fatalf("R_P2L_EXCESS_DURABLE_BYTES wire=%d direct=%d",finalW,finalD)
    }
    if free<100<<20 {t.Fatal("R_P2L_HEALTHY_RESERVE_LOST")}
    t.Log("R_P2L_VALIDATED nonvalidator_peer=true noncanonical_invalid_QBFT_2of4=true matched_invalid_header_and_body_wire_delivery=true verified_invalid_seals=true matched_node_dispatch=true unsolicited_node_ids_rejected=true oversized_node_count_rejected=true wrong_node_message_type_rejected=true measured_churn=true compaction_restart=true")
}
