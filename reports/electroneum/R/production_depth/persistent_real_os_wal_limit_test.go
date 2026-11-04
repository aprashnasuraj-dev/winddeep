//go:build linux

// Worker R P2f: Linux-enforced real filesystem write failure on the actual
// goleveldb WAL. RLIMIT_FSIZE triggers SIGXFSZ / EFBIG inside write(2).
// This models local disk-write failure, not power loss, fsync, a forged
// *successful* LevelDB acknowledgement, or unprivileged network reachability.
// A subprocess is mandatory: BlockChain invokes log.Crit -> os.Exit(1).
package core

import (
    "bytes"
    "errors"
    "fmt"
    "math"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
    "syscall"
    "testing"

    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/core/vm"
)

// Passive observation of the *underlying* actual LevelDB.Batch.Write error.
// Unlike P2d, this wrapper NEVER changes an error or reports a fake failure.
type rOSObservedDB struct{ethdb.Database}
type rOSObservedBatch struct{ethdb.Batch}
func (d *rOSObservedDB) NewBatch() ethdb.Batch {
    return &rOSObservedBatch{Batch:d.Database.NewBatch()}
}
func (d *rOSObservedDB) NewBatchWithSize(n int) ethdb.Batch {
    return &rOSObservedBatch{Batch:d.Database.NewBatchWithSize(n)}
}
func (b *rOSObservedBatch) Write() error {
    err:=b.Batch.Write()
    if err!=nil {
        fmt.Fprintf(os.Stderr,"R_OS_UNMODIFIED_LEVELDB_WRITE_ERROR err=%q\n",err.Error())
    }
    return err
}
func rOSActiveWAL(t *testing.T,dir string) (string,int64) {
    t.Helper()
    entries,err:=os.ReadDir(dir)
    if err!=nil{t.Fatal(err)}
    names:=make([]string,0,3)
    for _,e:=range entries{
        if e.IsDir()||!strings.HasSuffix(e.Name(),".log"){continue}
        label:=strings.TrimSuffix(e.Name(),".log")
        if len(label)!=6||strings.Trim(label,"0123456789")!=""{continue}
        names=append(names,e.Name())
    }
    sort.Strings(names)
    if len(names)==0{t.Fatalf("R_OS_WAL_MISSING dir=%s",dir)}
    last:=filepath.Join(dir,names[len(names)-1])
    info,err:=os.Stat(last)
    if err!=nil{t.Fatal(err)}
    return last,info.Size()
}

func TestRLevelDBRealOSFileSizeChild(t *testing.T){
    if os.Getenv("R_OS_LIMIT_CHILD")!="1"{return}
    stage:=os.Getenv("R_OS_LIMIT_STAGE")
    path:=os.Getenv("R_OS_LIMIT_DB")
    if !strings.HasPrefix(stage,"wal_plus_"){t.Fatalf("R_OS_LIMIT_UNKNOWN_STAGE %s",stage)}
    delta,err:=strconv.ParseInt(strings.TrimPrefix(stage,"wal_plus_"),10,64)
    if err!=nil || delta<0 || delta>1600 {t.Fatalf("R_OS_LIMIT_UNKNOWN_STAGE %s err=%v",stage,err)}
    _,blocks,_:=rBatchFixture(t)
    db:=rOpenPersist(t,path)
    cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
    if cfg==nil{t.Fatal("R_OS_LIMIT_MISSING_GENESIS_CONFIG")}
    chain,err:=NewBlockChain(&rOSObservedDB{Database:db},nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
    if err!=nil{t.Fatal(err)}
    if chain.CurrentBlock().NumberU64()!=0{t.Fatal("R_OS_LIMIT_BAD_INITIAL_HEAD")}
    wal,initial:=rOSActiveWAL(t,path)
    limit:=initial+delta
    if limit<0||limit>math.MaxInt32{t.Fatalf("R_OS_LIMIT_BAD_LIMIT %d",limit)}
    // The signal is ignored *only within the child* so the Linux write
    // syscall exposes EFBIG rather than terminating via SIGXFSZ.
    signal.Ignore(syscall.SIGXFSZ)
    if err:=syscall.Setrlimit(syscall.RLIMIT_FSIZE,&syscall.Rlimit{
        Cur:uint64(limit), Max:uint64(limit),
    });err!=nil{t.Fatalf("R_OS_SET_RLIMIT_FAILED: %v",err)}
    // Independent syscall witness that this is a REAL OS rejection, not
    // synthetic ethdb.Batch.Write error substitution.
    probe:=filepath.Join(t.TempDir(),"os-write-probe")
    err=os.WriteFile(probe,make([]byte,int(limit)+4096),0600)
    if !errors.Is(err,syscall.EFBIG){
        t.Fatalf("R_OS_PROBE_EXPECTED_EFBIG stage=%s err=%v",stage,err)
    }
    fmt.Fprintf(os.Stderr,"R_OS_RLIMIT_REAL_EFBIG_PROBE_PASS stage=%s limit=%d wal_initial=%d wal_file=%s\n",stage,limit,initial,filepath.Base(wal))
    fmt.Fprintf(os.Stderr,"R_OS_CHAIN_INSERT_START stage=%s\n",stage)
    _,insertErr:=chain.InsertChain(types.Blocks(blocks))
    t.Fatalf("R_OS_EXPECTED_CRIT_EXIT_MISSING stage=%s err=%v",stage,insertErr)
}

func TestRLevelDBRealOSFileSizeRecovery(t *testing.T){
    gspec,blocks,tx:=rBatchFixture(t)
    baseline:=filepath.Join(t.TempDir(),"genesis-only")
    db:=rOpenPersist(t,baseline)
    if genesis:=gspec.MustCommit(db);genesis.Hash()!=blocks[0].ParentHash(){
        db.Close()
        t.Fatal("R_OS_GENESIS_ONLY_CONTROL_FAIL")
    }
    if err:=db.Close();err!=nil{t.Fatal(err)}
    stages:=[]string{"wal_plus_0","wal_plus_64","wal_plus_512","wal_plus_1024"}
    // Deliberately focus on the payload (~835 B) / marker (~199 B)
    // WAL boundary rather than mutate arbitrary bytes post-exit.
    for n:=768;n<=1408;n+=32{stages=append(stages,fmt.Sprintf("wal_plus_%d",n))}
    var postcommitObserved int
    for _,stage:=range stages{
        t.Run(stage,func(t *testing.T){
            path:=filepath.Join(t.TempDir(),"chaindata")
            rWALCopyDirectory(t,baseline,path)
            child:=exec.Command(os.Args[0],"-test.run=^TestRLevelDBRealOSFileSizeChild$","-test.v")
            child.Env=append(os.Environ(),"R_OS_LIMIT_CHILD=1","R_OS_LIMIT_STAGE="+stage,"R_OS_LIMIT_DB="+path)
            output,err:=child.CombinedOutput()
            exit,ok:=err.(*exec.ExitError)
            if !ok||exit.ExitCode()!=1||
                !bytes.Contains(output,[]byte("R_OS_RLIMIT_REAL_EFBIG_PROBE_PASS stage="+stage))||
                !bytes.Contains(output,[]byte("R_OS_CHAIN_INSERT_START stage="+stage))||
                !bytes.Contains(output,[]byte("R_OS_UNMODIFIED_LEVELDB_WRITE_ERROR"))||
                bytes.Contains(output,[]byte("R_OS_EXPECTED_CRIT_EXIT_MISSING")){
                t.Fatalf("R_OS_LIMIT_CHILD_DID_NOT_FATAL_AT_WRITE stage=%s err=%v output=%s",stage,err,output)
            }
            t.Logf("R_OS_REAL_WRITE_ERROR_FATAL_EXIT stage=%s exit=1",stage)
            reopened:=rOpenPersist(t,path)
            cfg:=rawdb.ReadChainConfig(reopened,rawdb.ReadCanonicalHash(reopened,0))
            if cfg==nil {reopened.Close();t.Fatalf("R_OS_LIMIT_GENESIS_LOST stage=%s",stage)}
            payload:=rawdb.ReadBody(reopened,blocks[0].Hash(),1)!=nil
            rawReceipts:=rawdb.ReadRawReceipts(reopened,blocks[0].Hash(),1)!=nil
            canon:=rawdb.ReadCanonicalHash(reopened,1)==blocks[0].Hash()
            indexed:=rawdb.ReadTxLookupEntry(reopened,tx.Hash())!=nil
            head:=rawdb.ReadHeadBlockHash(reopened)==blocks[0].Hash()
            if (canon!=head)||(indexed!=head)||(head&&(!payload||!rawReceipts)){
                reopened.Close()
                t.Fatalf("R_OS_WRONG_HEAD_WITHOUT_COMPLETE_BLOCK stage=%s head=%t body=%t receipts=%t canonical=%t indexed=%t",
                    stage,head,payload,rawReceipts,canon,indexed)
            }
            t.Logf("R_OS_RECOVERED_WAL_STATE stage=%s payload=%t receipts=%t canonical=%t indexed=%t head=%t",
                stage,payload,rawReceipts,canon,indexed,head)
            if head {
                postcommitObserved++
                t.Logf("R_OS_REAL_WRITE_ERROR_POSTCOMMIT_VISIBILITY_CANDIDATE stage=%s",stage)
            }
            rBatchVerifyReimport(t,reopened,blocks,tx,stage,1)
            if err:=reopened.Close();err!=nil{t.Fatal(err)}
            again:=rOpenPersist(t,path)
            rBatchVerifyReimport(t,again,blocks,tx,stage,2)
            if err:=again.Close();err!=nil{t.Fatal(err)}
            t.Logf("R_OS_REAL_WRITE_ERROR_REPLAY_PASS stage=%s full=2",stage)
        })
    }
    t.Logf("R_OS_REAL_WAL_LIMIT_SWEEP_DONE cases=%d head_committed_on_error=%d",len(stages),postcommitObserved)
    t.Log("R_OS_REAL_WAL_WRITE_EFBIG_MATRIX_PASS linux_rlimit_file_growth_not_powerloss")
}
