//go:build linux

// Worker R P2m. Certified, unmodified SnapSyncer.Sync -> VerifyRangeProof /
// bytecode-hash validation -> actual LevelDB batch writes and recovery.
// This is a Snap SyncPeer callback harness (actual production ingestion logic),
// NOT a real TCP/RLPx snap/1 peer. Never report the latter as established.
// All targets live in disposable ext4; no third-party or public node traffic.
package snap

import (
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "sync/atomic"
    "syscall"
    "testing"
    "time"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/trie"
)

func rP2MPhysicalBytes(t *testing.T,path string) int64 {
    t.Helper()
    var out int64
    err:=filepath.Walk(path,func(p string,info os.FileInfo,err error)error{
        if err!=nil{return err}
        if !info.Mode().IsRegular(){return nil}
        st,ok:=info.Sys().(*syscall.Stat_t)
        if !ok{return fmt.Errorf("R_P2M_NOT_POSIX_STAT")}
        out+=st.Blocks*512
        return nil
    })
    if err!=nil{t.Fatalf("R_P2M_PHYSICAL_WALK_FAIL path=%s err=%v",path,err)}
    return out
}
func rP2MAvailable(t *testing.T,path string) uint64 {
    t.Helper()
    var st syscall.Statfs_t
    if err:=syscall.Statfs(path,&st);err!=nil{t.Fatal(err)}
    return st.Bavail*uint64(st.Bsize)
}
func rP2MOpen(t *testing.T,path string) ethdb.Database {
    t.Helper()
    if err:=os.MkdirAll(path,0700);err!=nil{t.Fatal(err)}
    db,err:=rawdb.NewLevelDBDatabase(path,16,16,"r-p2m-snap",false)
    if err!=nil{t.Fatalf("R_P2M_LEVELDB_OPEN_FAIL %v",err)}
    return db
}
func rP2MSnapshotCount(db ethdb.KeyValueReader,entries entrySlice) int {
    count:=0
    for _,entry:=range entries{
        if len(rawdb.ReadAccountSnapshot(db,common.BytesToHash(entry.k)))>0 {count++}
    }
    return count
}

type rP2MResponseStats struct {
    account atomic.Int64
    code atomic.Int64
    validReplies atomic.Int64
    unknownIDs atomic.Int64
    rejected atomic.Int64
    proofBytes atomic.Int64
    accountBytes atomic.Int64
}

type rP2MCase struct {
    mode string
    path string
    durable int64
    snapCount int
    accountReqs int64
    codeReqs int64
    invalidIDs int64
    rejects int64
    proofBytes int64
    accountBytes int64
    synced bool
    errorText string
}

// Deliberately use the certified package's existing testPeer (SyncPeer)
// scaffold to route real producer-chosen request IDs and peer replies into
// production NewSyncer(db).Sync(root). The state is persisted by the shipped
// syncer's own batch writers, not by the harness.
func rP2MRunSnapCase(t *testing.T,root common.Hash,sourceTrie *trie.Trie,entries entrySlice,
    dir string,mode string) rP2MCase {
    t.Helper()
    db:=rP2MOpen(t,dir)
    before:=rP2MPhysicalBytes(t,dir)
    var once sync.Once
    cancel:=make(chan struct{})
    stop:=func(){once.Do(func(){close(cancel)})}
    timer:=time.AfterFunc(12*time.Second,stop)
    defer timer.Stop()
    stats:=new(rP2MResponseStats)
    peer:=newTestPeer("p2m-"+mode,t,stop)
    peer.accountTrie=sourceTrie
    peer.accountValues=entries
    syncer:=NewSyncer(db)
    if err:=syncer.Register(peer);err!=nil{t.Fatal(err)}
    peer.remote=syncer
    // Controlled callback receives a request ID created by production syncer.
    // No peer can directly write recipient DB in any attack scenario.
    peer.accountRequestHandler=func(p *testPeer,id uint64,r,origin,limit common.Hash,cap uint64)error{
        stats.account.Add(1)
        hashes,values,proofs:=createAccountRequestResponse(p,r,origin,limit,cap)
        for _,v:=range values{stats.accountBytes.Add(int64(len(v)))}
        for _,v:=range proofs{stats.proofBytes.Add(int64(len(v)))}
        switch mode{
        case "mismatched-leaf":
            if len(values)==0 {t.Error("R_P2M_BAD_FIXTURE_NO_VALUES");stop();return nil}
            mutated:=make([][]byte,len(values))
            copy(mutated,values)
            mutated[0]=append([]byte(nil),values[0]...)
            mutated[0][len(mutated[0])-1]^=0x01
            err:=p.remote.OnAccounts(p,id,hashes,mutated,proofs)
            if err==nil {t.Error("R_P2M_MUTANT_ACCOUNT_PROOF_UNEXPECTED_ACCEPT")}
            if err!=nil {stats.rejected.Add(1)}
            stop()
            return nil
        case "duplicate-proofs":
            if len(proofs)==0 {t.Error("R_P2M_VALID_PROOF_MISSING");stop();return nil}
            // A low-authority provider can repeat otherwise valid proof
            // witnesses without controlling the trie root. The same
            // canonical accounts and proof are delivered as honest control.
            for i:=0;i<24;i++ {
                blob:=append([]byte(nil),proofs[0]...)
                proofs=append(proofs,blob)
                stats.proofBytes.Add(int64(len(blob)))
            }
        case "unsolicited-ids":
            for i:=0;i<4;i++{
                wrongID:=id^(uint64(i+1)<<54)
                // These IDs are not registered; the syncer should ignore all.
                err:=p.remote.OnAccounts(p,wrongID,hashes,values,proofs)
                if err!=nil{t.Errorf("R_P2M_UNSOLICITED_ID_REJECTED_WITH_ERROR id=%d err=%v",wrongID,err)}
                stats.unknownIDs.Add(1)
            }
        }
        err:=p.remote.OnAccounts(p,id,hashes,values,proofs)
        if err!=nil {stats.rejected.Add(1);t.Errorf("R_P2M_VALID_ACCOUNT_REJECTED mode=%s err=%v",mode,err);stop()} else{stats.validReplies.Add(1)}
        return nil
    }
    peer.codeRequestHandler=func(p *testPeer,id uint64,hashes []common.Hash,max uint64)error{
        stats.code.Add(1)
        codes:=make([][]byte,0,len(hashes))
        for _,h:=range hashes{codes=append(codes,getCodeByHash(h))}
        if mode=="mismatched-code"&&len(codes)>0{
            // A response with unrelated code cannot satisfy its requested
            // Keccak hash, even when the account range proof was valid.
            codes[0]=[]byte("P2M_NOT_THE_REQUESTED_BYTECODE")
        }
        err:=p.remote.OnByteCodes(p,id,codes)
        if mode=="mismatched-code" {
            if err==nil{t.Error("R_P2M_MUTANT_CODE_UNEXPECTED_ACCEPT")}else{stats.rejected.Add(1)}
            stop()
            return nil
        }
        if err!=nil{t.Errorf("R_P2M_VALID_CODE_REJECTED mode=%s err=%v",mode,err);stop()}
        return nil
    }
    err:=syncer.Sync(root,cancel)
    timer.Stop()
    count:=rP2MSnapshotCount(db,entries)
    synced:=mode=="honest"||mode=="duplicate-proofs"||mode=="unsolicited-ids"
    if synced{
        if err!=nil {t.Fatalf("R_P2M_POSITIVE_SNAP_SYNC_FAILED mode=%s err=%v",mode,err)}
        if count!=len(entries){
            t.Fatalf("R_P2M_VALID_SNAPSHOTS_INCOMPLETE mode=%s got=%d expected=%d",mode,count,len(entries))
        }
        verifyTrie(db,root,t)
        t.Logf("R_P2M_STATE_INGESTION_CONFIRMED mode=%s accounts=%d root=%s requests=%d",mode,count,root,stats.account.Load())
    }else{
        if err==nil {t.Fatalf("R_P2M_MALICIOUS_SNAP_SYNC_UNEXPECTED_COMPLETE mode=%s",mode)}
        if stats.rejected.Load()==0 {t.Fatalf("R_P2M_MALICIOUS_INPUT_NOT_REJECTED mode=%s",mode)}
        if mode=="mismatched-leaf"&&count!=0{
            t.Fatalf("R_P2M_MUTATED_ACCOUNT_PERSISTED snap_count=%d",count)
        }
        if mode=="mismatched-code"&&count!=0{
            t.Fatalf("R_P2M_MUTATED_CODE_PREMATURE_SNAPSHOT snap_count=%d",count)
        }
    }
    after:=rP2MPhysicalBytes(t,dir)
    t.Logf("R_P2M_LIVE_SYNC mode=%s synced=%t request_account=%d request_code=%d unknown_request_ids=%d rejected_responses=%d accepted_responses=%d account_value_bytes=%d proof_bytes=%d snapshot_accounts=%d physical_growth=%d sync_err=%v",
        mode,synced,stats.account.Load(),stats.code.Load(),stats.unknownIDs.Load(),
        stats.rejected.Load(),stats.validReplies.Load(),stats.accountBytes.Load(),
        stats.proofBytes.Load(),count,after-before,err)
    if err:=db.Compact(nil,nil);err!=nil{t.Fatalf("R_P2M_LEVELDB_COMPACT_FAIL mode=%s err=%v",mode,err)}
    if err:=db.Close();err!=nil{t.Fatal(err)}
    reopened:=rP2MOpen(t,dir)
    restartCount:=rP2MSnapshotCount(reopened,entries)
    if restartCount!=count{
        t.Fatalf("R_P2M_RESTART_SNAPSHOT_MISMATCH mode=%s before=%d after=%d",mode,count,restartCount)
    }
    if synced {verifyTrie(reopened,root,t)}
    if err:=reopened.Close();err!=nil{t.Fatal(err)}
    physical:=rP2MPhysicalBytes(t,dir)
    t.Logf("R_P2M_PERSISTENT_RESTART mode=%s durable_physical_bytes=%d persisted_accounts=%d full_root=%t",mode,physical,restartCount,synced)
    result:=rP2MCase{mode:mode,path:dir,durable:physical,snapCount:restartCount,
        accountReqs:stats.account.Load(),codeReqs:stats.code.Load(),
        invalidIDs:stats.unknownIDs.Load(),rejects:stats.rejected.Load(),
        proofBytes:stats.proofBytes.Load(),accountBytes:stats.accountBytes.Load(),synced:synced}
    if err!=nil {result.errorText=err.Error()}
    return result
}

func TestRProductionSnapStatePersistenceUntrustedResponses(t *testing.T) {
    rootDir:=os.Getenv("R_P2M_SNAP_DISK_ROOT")
    if rootDir==""{t.Skip("R_P2M_SNAP_DISK_ROOT unset")}
    if err:=os.MkdirAll(rootDir,0700);err!=nil{t.Fatal(err)}
    freeBefore:=rP2MAvailable(t,rootDir)
    if freeBefore<128<<20{t.Fatalf("R_P2M_HEALTHY_RESERVE_REQUIRED free=%d",freeBefore)}
    // Production SnapSyncer operates on real persisted LevelDB. The source
    // state is fixture-generated and fixed; the unprivileged network provider
    // only controls returned ranges / IDs / code payload.
    source,entries:=makeAccountTrieNoStorage(96)
    stateRoot:=source.Hash()
    // Concurrency=1 ensures the malicious payload has a single attributable
    // request, preventing other honest parallel requests from obscuring writes.
    saved:=accountConcurrency
    accountConcurrency=1
    defer func(){accountConcurrency=saved}()
    modes:=[]string{"honest","duplicate-proofs","unsolicited-ids","mismatched-leaf","mismatched-code"}
    result:=make(map[string]rP2MCase)
    for _,mode:=range modes{
        t.Run(mode,func(t *testing.T){
            result[mode]=rP2MRunSnapCase(t,stateRoot,source,entries,filepath.Join(rootDir,mode),mode)
        })
    }
    for _,mode:=range []string{"honest","duplicate-proofs","unsolicited-ids"}{
        r:=result[mode]
        if !r.synced||r.snapCount!=len(entries)||r.accountReqs==0||r.codeReqs==0{
            t.Fatalf("R_P2M_POSITIVE_INGESTION_COVERAGE_FAILED mode=%s accounts=%d account_req=%d code_req=%d",
                mode,r.snapCount,r.accountReqs,r.codeReqs)
        }
    }
    if result["unsolicited-ids"].invalidIDs<4{
        t.Fatal("R_P2M_UNSOLICITED_REQUEST_ID_COVERAGE_MISSING")
    }
    for _,mode:=range []string{"mismatched-leaf","mismatched-code"} {
        if result[mode].rejects==0||result[mode].synced{
            t.Fatalf("R_P2M_MALICIOUS_RESPONSE_REJECTION_MISSING mode=%s",mode)
        }
    }
    honest:=result["honest"].durable
    extraProof:=result["duplicate-proofs"].proofBytes-result["honest"].proofBytes
    if extraProof<=0{t.Fatalf("R_P2M_PROOF_PADDING_NOT_EXERCISED extra=%d",extraProof)}
    padded:=result["duplicate-proofs"].durable
    unknown:=result["unsolicited-ids"].durable
    t.Logf("R_P2M_SNAP_FULL_IMPORT_ORACLE accounts=%d valid_baseline=%d duplicated_proofs=%d unsolicited_id_then_valid=%d extra_proof_bytes=%d duplicated_proof_durable_excess=%d unsolicited_id_durable_excess=%d",
        len(entries),honest,padded,unknown,extraProof,padded-honest,unknown-honest)
    // LevelDB file granularity and timing may differ by a 4KiB filesystem
    // block on a tiny fixture. A significant positive excess is explicitly
    // triaged, not automatically called a remotely exploitable DoS.
    const limit=64<<10
    if padded-honest>limit || unknown-honest>limit {
        t.Fatalf("R_P2M_UNEXPECTED_DURABLE_EXCESS padded_minus_honest=%d unknown_minus_honest=%d",
            padded-honest,unknown-honest)
    }
    freeAfter:=rP2MAvailable(t,rootDir)
    t.Logf("R_P2M_DURABLE_MATRIX free_initial=%d free_final=%d honest=%d valid_padded=%d valid_wrong_ID_first=%d rejected_wrong_leaf=%d rejected_wrong_code=%d",
        freeBefore,freeAfter,result["honest"].durable,result["duplicate-proofs"].durable,
        result["unsolicited-ids"].durable,result["mismatched-leaf"].durable,result["mismatched-code"].durable)
    if freeAfter<100<<20 {t.Fatal("R_P2M_HEALTHY_RESERVE_EXHAUSTED")}
    t.Log("R_P2M_COMPLETED state_sync=real_production_SnapSyncer.Sync writes=real_LevelDB_Commit_and_restart matched_requests=true actual_Merkle_VerifyRangeProof=true production_bytecode_Keccak_check=true snap_protocol_TCP_wire=NOT_EXERCISED validator_signing=NOT_CONTROLLED healthy_disk_exhaustion=NOT_PROVEN")
}
