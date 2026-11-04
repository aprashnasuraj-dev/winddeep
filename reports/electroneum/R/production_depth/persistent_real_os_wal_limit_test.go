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
    "strings"
    "syscall"
    "testing"

    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
)

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
    delta:=int64(0)
    switch stage{
    case "wal_plus_0":delta=0
    case "wal_plus_64":delta=64
    case "wal_plus_512":delta=512
    case "wal_plus_1024":delta=1024
    default:t.Fatalf("R_OS_LIMIT_UNKNOWN_STAGE %s",stage)
    }
    _,blocks,_:=rBatchFixture(t)
    db:=rOpenPersist(t,path)
    cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
    if cfg==nil{t.Fatal("R_OS_LIMIT_MISSING_GENESIS_CONFIG")}
    chain,err:=NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
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
    for _,stage:=range []string{"wal_plus_0","wal_plus_64","wal_plus_512","wal_plus_1024"}{
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
            if head&&(!canon||!payload||!rawReceipts||!indexed){
                reopened.Close()
                t.Fatalf("R_OS_WRONG_HEAD_WITHOUT_COMPLETE_BLOCK stage=%s head=%t body=%t receipts=%t canonical=%t indexed=%t",
                    stage,head,payload,rawReceipts,canon,indexed)
            }
            t.Logf("R_OS_RECOVERED_WAL_STATE stage=%s payload=%t receipts=%t canonical=%t indexed=%t head=%t",
                stage,payload,rawReceipts,canon,indexed,head)
            rBatchVerifyReimport(t,reopened,blocks,tx,stage,1)
            if err:=reopened.Close();err!=nil{t.Fatal(err)}
            again:=rOpenPersist(t,path)
            rBatchVerifyReimport(t,again,blocks,tx,stage,2)
            if err:=again.Close();err!=nil{t.Fatal(err)}
            t.Logf("R_OS_REAL_WRITE_ERROR_REPLAY_PASS stage=%s full=2",stage)
        })
    }
    t.Log("R_OS_REAL_WAL_WRITE_EFBIG_MATRIX_PASS linux_rlimit_file_growth_not_powerloss")
}
