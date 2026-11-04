//go:build linux

// Isolated evidence: compare two valid QBFT blocks delivered by a lower-trust
// TCP/RLPx/ETH66 peer against the SAME blocks imported directly. The receiver
// starts with a healthy, measured filesystem reserve. Replayed syncs are
// measured independently. No public network or validator service is accessed.
package eth

import (
 "fmt"
 "os"
 "path/filepath"
 "syscall"
 "testing"

 "github.com/electroneum/electroneum-sc/consensus/istanbul"
 istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/core/rawdb"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/core/vm"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/eth/downloader"
 "github.com/electroneum/electroneum-sc/ethdb"
)

func healthyPeerFreeBytes(t *testing.T, path string) uint64 {
 t.Helper()
 var s syscall.Statfs_t
 if err:=syscall.Statfs(path,&s);err!=nil{t.Fatal(err)}
 return s.Bavail*uint64(s.Bsize)
}

func TestHealthyReserveTwoHeightLowerTrustPeerGrowth(t *testing.T) {
 mount:=os.Getenv("HEALTHY_PEER_STORAGE_ROOT")
 if mount==""{t.Skip("HEALTHY_PEER_STORAGE_ROOT is required")}
 if err:=os.MkdirAll(mount,0700);err!=nil{t.Fatal(err)}
 freeStart:=healthyPeerFreeBytes(t,mount)
 if freeStart<64<<20{t.Fatalf("test storage is pre-exhausted: free=%d, requires >=64 MiB",freeStart)}
 t.Logf("HEALTHY_PEER_INITIAL_RESERVE_PASS available_bytes=%d minimum_bytes=%d",freeStart,64<<20)

 f,senderKey:=rP1HBaseFixture(t)
 defer f.close()
 sender:=crypto.PubkeyToAddress(senderKey.PublicKey)

 blocks:=make(types.Blocks,0,2)
 txs:=make([]*types.Transaction,0,2)
 for n:=0;n<2;n++{
   tx:=rG6LargeSignedTx(t,f.remoteChain,senderKey)
   block:=rQBFTBuildAndImport(t,f.remoteChain,f.remoteQBFT,f.remoteDB,f.validatorKeys,f.validators,tx)
   if block.NumberU64()!=uint64(n+1){t.Fatalf("unexpected block height %d",block.NumberU64())}
   blocks=append(blocks,block);txs=append(txs,tx)
 }
 t.Logf("HEALTHY_PEER_QUORUM_VALID_HISTORY_PASS heights=2 block_1_bytes=%v block_2_bytes=%v",blocks[0].Size(),blocks[1].Size())

 base:=filepath.Join(mount,"two-heights")
 if err:=os.MkdirAll(base,0700);err!=nil{t.Fatal(err)}
 defer os.RemoveAll(base)
 genesis:=rQBFTNetworkGenesis(t,f.validatorKeys,sender)

 makeReceiver:=func(dir string)(ethdb.Database,*core.BlockChain,*istanbulbackend.Backend,*rQBFTObservedDB){
   if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
   db:=rQBFTOpenDisk(t,dir)
   gen:=genesis.MustCommit(db)
   if gen.Hash()!=blocks[0].ParentHash(){t.Fatalf("genesis mismatch: %s vs %s",gen.Hash(),blocks[0].ParentHash())}
   observed:=&rQBFTObservedDB{Database:db}
   be:=istanbulbackend.New(*istanbul.DefaultConfig,f.validatorKeys[0],observed)
   chain,err:=core.NewBlockChain(observed,nil,genesis.Config,be,vm.Config{},nil,nil)
   if err!=nil{t.Fatalf("chain create: %v",err)}
   if err:=be.Start(chain,chain.CurrentBlock,rawdb.HasBadBlock);err!=nil{t.Fatalf("engine start: %v",err)}
   for _,block:=range blocks{
     if err:=be.VerifyHeader(chain,block.Header(),true);err!=nil {
       if block.NumberU64()!=1 { // verify may require prior ancestor; actual import validates each
         break
       }
       t.Fatalf("first block QBFT verification: %v",err)
     }
   }
   return db,chain,be,observed
 }

 wireDir:=filepath.Join(base,"eth66")
 directDir:=filepath.Join(base,"direct")
 wireDB,wireChain,wireBE,obs:=makeReceiver(wireDir)
 defer func(){_ = wireBE.Stop();wireChain.Stop();_ = wireDB.Close()}()
 directDB,directChain,directBE,_:=makeReceiver(directDir)
 defer func(){_ = directBE.Stop();directChain.Stop();_ = directDB.Close()}()

 directBefore:=rG6PhysicalBytes(t,directDir)
 if index,err:=directChain.InsertChain(blocks);err!=nil{t.Fatalf("direct import failed at %d: %v",index,err)}
 directDelta:=rG6PhysicalBytes(t,directDir)-directBefore
 if directDelta<=0{t.Fatalf("invalid direct baseline %d",directDelta)}
 if directChain.CurrentBlock().Hash()!=blocks[1].Hash(){t.Fatal("direct head invalid")}

 localHandler:=rDevP2PHandler(t,obs,wireChain)
 defer localHandler.Stop()
 remoteHandler:=rDevP2PHandler(t,f.remoteDB,f.remoteChain)
 defer remoteHandler.Stop()
 localServer:=rDevP2PServer(t,"healthy-storage-local",localHandler,false)
 defer localServer.Stop()
 remoteServer:=rDevP2PServer(t,"healthy-storage-peer",remoteHandler,true)
 defer remoteServer.Stop()
 localServer.AddPeer(remoteServer.Self())
 peer:=rP1HWaitRegisteredPeer(t,localHandler,remoteServer)
 head,td:=peer.Head()
 if head!=blocks[1].Hash(){t.Fatalf("advertised peer head mismatch got=%s want=%s",head,blocks[1].Hash())}
 t.Log("HEALTHY_PEER_REAL_TCP_RLPX_ETH66_HANDSHAKE_PASS")

 reserveBeforeImport:=healthyPeerFreeBytes(t,mount)
 wireBefore:=rG6PhysicalBytes(t,wireDir)
 if err:=localHandler.downloader.LegacySync(peer.ID(),head,td,wireChain.Config().TerminalTotalDifficulty,downloader.FullSync);err!=nil{
   t.Fatalf("actual ETH66 2-height sync failed: %v",err)
 }
 wireDelta:=rG6PhysicalBytes(t,wireDir)-wireBefore
 if wireChain.CurrentBlock().Hash()!=blocks[1].Hash(){t.Fatal("wire head not canonical height 2")}
 for _,tx:=range txs{
   receipt,_,_,_:=rawdb.ReadReceipt(wireDB,tx.Hash(),wireChain.Config())
   directReceipt,_,_,_:=rawdb.ReadReceipt(directDB,tx.Hash(),directChain.Config())
   if receipt==nil||directReceipt==nil||receipt.Status!=1||directReceipt.Status!=1{t.Fatalf("missing verified canonical receipts for %s",tx.Hash())}
 }
 t.Log("HEALTHY_PEER_TWO_HEIGHT_CANONICAL_RECEIPTS_PASS")

 replayBefore:=rG6PhysicalBytes(t,wireDir)
 successes,errors:=0,0
 for n:=0;n<5;n++ {
   err:=localHandler.downloader.LegacySync(peer.ID(),head,td,wireChain.Config().TerminalTotalDifficulty,downloader.FullSync)
   if err==nil{successes++}else{errors++;t.Logf("HEALTHY_PEER_REPLAY_REJECTED attempt=%d err=%v",n+1,err)}
   if wireChain.CurrentBlock().Hash()!=blocks[1].Hash(){t.Fatal("replay mutated canonical head")}
 }
 replayDelta:=rG6PhysicalBytes(t,wireDir)-replayBefore
 reserveAfter:=healthyPeerFreeBytes(t,mount)
 if reserveAfter<32<<20{t.Fatalf("receiver unexpectedly lost healthy reserve: before=%d after=%d",reserveBeforeImport,reserveAfter)}
 if wireDelta<=0{t.Fatalf("wire produced no stored canonical data: %d",wireDelta)}
 ratio:=float64(wireDelta)/float64(directDelta)
 t.Logf("HEALTHY_PEER_DISK_RATIO_MEASURED wire_bytes=%d direct_bytes=%d ratio=%.4f replay_delta=%d repeat_calls=5 success=%d errors=%d free_before=%d free_after=%d",wireDelta,directDelta,ratio,replayDelta,successes,errors,reserveBeforeImport,reserveAfter)
 if ratio<=1.10&&replayDelta<=4096{
   t.Log("HEALTHY_PEER_REMOTE_AMPLIFICATION_NOT_OBSERVED_IN_TESTED_TWO_HEIGHT_CASE")
 }else{
   t.Logf("HEALTHY_PEER_PERSISTENCE_DIFFERENCE_REQUIRES_REVIEW ratio=%.4f replay=%d",ratio,replayDelta)
 }
 t.Log(fmt.Sprintf("HEALTHY_PEER_NO_FATAL_EXIT_OBSERVED free_remaining=%d",reserveAfter))
}