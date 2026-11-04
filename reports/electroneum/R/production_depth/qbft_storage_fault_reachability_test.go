//go:build linux

// Worker R P2g: production QBFT verification and local disk-error crash.
// No network attacker, filesystem damage, fake seals, or third-party financial
// impact is implied by a local synthetic acknowledgement error.
package eth

import (
    "bytes"
    "context"
    "crypto/ecdsa"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "sort"
    "strings"
    "syscall"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/istanbul"
    istanbulbackend "github.com/electroneum/electroneum-sc/consensus/istanbul/backend"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/internal/ethapi"
    "github.com/electroneum/electroneum-sc/rlp"
    "github.com/electroneum/electroneum-sc/rpc"
)

type rQBFTCrashDB struct { ethdb.Database }
type rQBFTCrashBatch struct { ethdb.Batch; head bool }
func (d *rQBFTCrashDB) NewBatch() ethdb.Batch {
    return &rQBFTCrashBatch{Batch:d.Database.NewBatch()}
}
func (d *rQBFTCrashDB) NewBatchWithSize(size int) ethdb.Batch {
    return &rQBFTCrashBatch{Batch:d.Database.NewBatchWithSize(size)}
}
func (b *rQBFTCrashBatch) Put(k,v []byte) error {
    if bytes.Equal(k,[]byte("LastBlock")) {b.head=true}
    return b.Batch.Put(k,v)
}
func (b *rQBFTCrashBatch) Write() error {
    if !b.head{return b.Batch.Write()}
    if err:=b.Batch.Write();err!=nil{return err}
    fmt.Fprintln(os.Stderr,"R_QBFT_SYNTHETIC_HEAD_BATCH_COMMITTED_THEN_ERROR")
    return errors.New("R_QBFT_SYNTHETIC_POSTCOMMIT_ERROR")
}

func rQBFTOpenDisk(t *testing.T,path string) ethdb.Database {
    t.Helper()
    db,err:=rawdb.NewLevelDBDatabase(path,16,16,"r-qbft-disk-fault",false)
    if err!=nil{t.Fatal(err)}
    return db
}
func rQBFTActiveWAL(t *testing.T,path string) (string,int64) {
    t.Helper()
    entries,err:=os.ReadDir(path)
    if err!=nil{t.Fatal(err)}
    var logs []string
    for _,e:=range entries{
        n:=e.Name()
        if e.IsDir() || !strings.HasSuffix(n,".log"){continue}
        label:=strings.TrimSuffix(n,".log")
        if len(label)!=6||strings.Trim(label,"0123456789")!=""{continue}
        logs=append(logs,n)
    }
    sort.Strings(logs)
    if len(logs)==0{t.Fatal("R_QBFT_REAL_OS_NO_WAL")}
    f:=filepath.Join(path,logs[len(logs)-1])
    info,err:=os.Stat(f)
    if err!=nil{t.Fatal(err)}
    return f,info.Size()
}
func rQBFTEngine(t *testing.T,db ethdb.Database,signer *ecdsa.PrivateKey)(*core.BlockChain,*istanbulbackend.Backend){
    t.Helper()
    cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
    if cfg==nil||cfg.IBFT==nil||cfg.Ethash!=nil{
        t.Fatalf("R_QBFT_PRODUCTION_ENGINE_CONFIG_REQUIRED config=%v",cfg)
    }
    // Shipped defaults; this test does not broaden the accepted future window.
    conf:=*istanbul.DefaultConfig
    be:=istanbulbackend.New(conf,signer,db)
    chain,err:=core.NewBlockChain(db,nil,cfg,be,vm.Config{},nil,nil)
    if err!=nil{t.Fatalf("R_QBFT_REAL_ENGINE_CREATE_FAIL: %v",err)}
    if err:=be.Start(chain,chain.CurrentBlock,rawdb.HasBadBlock);err!=nil{
        chain.Stop()
        t.Fatalf("R_QBFT_ENGINE_START_FAIL: %v",err)
    }
    return chain,be
}
func rQBFTReadFixture(t *testing.T)(*types.Block,*ecdsa.PrivateKey) {
    t.Helper()
    data,err:=os.ReadFile(os.Getenv("R_QBFT_FAULT_BLOCK_RLP"))
    if err!=nil{t.Fatal(err)}
    var block types.Block
    if err:=rlp.DecodeBytes(data,&block);err!=nil{t.Fatal(err)}
    keyBytes,err:=hex.DecodeString(os.Getenv("R_QBFT_FAULT_KEY_HEX"))
    if err!=nil{t.Fatal(err)}
    key,err:=crypto.ToECDSA(keyBytes)
    if err!=nil{t.Fatal(err)}
    return &block,key
}

func TestRQBFTStorageCrashChild(t *testing.T) {
    if os.Getenv("R_QBFT_STORAGE_CHILD")!="1"{return}
    mode:=os.Getenv("R_QBFT_STORAGE_MODE")
    path:=os.Getenv("R_QBFT_STORAGE_DB")
    block,key:=rQBFTReadFixture(t)
    disk:=rQBFTOpenDisk(t,path)
    var db ethdb.Database=disk
    if mode=="head_after" {db=&rQBFTCrashDB{Database:disk}}
    chain,be:=rQBFTEngine(t,db,key)
    if chain.CurrentBlock().NumberU64()!=0{t.Fatal("R_QBFT_BAD_START_HEAD")}
    if err:=be.VerifyHeader(chain,block.Header(),true);err!=nil{
        t.Fatalf("R_QBFT_3OF4_SEALED_BLOCK_VERIFIER_REJECTED: %v",err)
    }
    signers,err:=be.Signers(block.Header())
    if err!=nil||len(signers)<3{
        t.Fatalf("R_QBFT_SIGNER_QUORUM_FAILED: count=%d err=%v",len(signers),err)
    }
    fmt.Fprintf(os.Stderr,"R_QBFT_DEFAULT_VERIFIER_ACCEPTED mode=%s signatures=%d validators=4\n",mode,len(signers))
    if mode=="os_fsize"{
        wal,n:=rQBFTActiveWAL(t,path)
        limit:=uint64(n+64)
        signal.Ignore(syscall.SIGXFSZ)
        if err:=syscall.Setrlimit(syscall.RLIMIT_FSIZE,&syscall.Rlimit{Cur:limit,Max:limit});err!=nil{t.Fatal(err)}
        err:=os.WriteFile(filepath.Join(t.TempDir(),"os-ebig-proof"),make([]byte,int(limit)+4096),0600)
        if !errors.Is(err,syscall.EFBIG){t.Fatalf("R_QBFT_OS_EFBIG_PROBE_FAILED: %v",err)}
        fmt.Fprintf(os.Stderr,"R_QBFT_REAL_OS_EFBIG_CONFIRMED wal=%s before=%d limit=%d\n",filepath.Base(wal),n,limit)
    }else if mode!="head_after"{
        t.Fatalf("R_QBFT_BAD_CHILD_MODE %s",mode)
    }
    fmt.Fprintf(os.Stderr,"R_QBFT_VALID_BLOCK_IMPORT_START mode=%s\n",mode)
    _,err=chain.InsertChain(types.Blocks{block})
    t.Fatalf("R_QBFT_FATAL_EXIT_MISSING mode=%s err=%v",mode,err)
}

func TestRProductionQBFTStorageCrashMatrix(t *testing.T){
    // Validator-controlled positive control only: 4 real ECDSA validator keys,
    // actual QBFT engine, 3 distinct committed signatures and stateful import.
    f,senderKey:=rP1HBaseFixture(t)
    defer f.close()
    tx:=rP1HSignedTx(t,f.remoteChain,senderKey,0xA7)
    block:=rQBFTBuildAndImport(t,f.remoteChain,f.remoteQBFT,f.remoteDB,f.validatorKeys,f.validators,tx)
    if block==nil||block.NumberU64()!=1{
        t.Fatal("R_QBFT_VALID_BLOCK_NOT_CREATED")
    }
    validSigners,err:=f.localQBFT.Signers(block.Header())
    if err!=nil||len(validSigners)<3{
        t.Fatalf("R_QBFT_SEAL_COUNT_NOT_QUORUM signers=%d err=%v",len(validSigners),err)
    }
    if err:=f.localQBFT.VerifyHeader(f.localChain,block.Header(),true);err!=nil{
        t.Fatalf("R_QBFT_VALID_FULL_VERIFIER_FAIL %v",err)
    }
    subquorum:=rP1HMakeSubquorum(t,block,f.validatorKeys)
    if err:=f.localQBFT.VerifyHeader(f.localChain,subquorum.Header(),true);err==nil{
        t.Fatal("R_QBFT_2OF4_VALIDATOR_BYPASS_FALSE_POSITIVE")
    }
    t.Log("R_QBFT_QUORUM_STRICT_CONTROL_PASS validators=4 accepted=3 rejected=2")
    // Independent persistence: the *only* on-disk state is the genesis.
    genesis:=rQBFTNetworkGenesis(t,f.validatorKeys,crypto.PubkeyToAddress(senderKey.PublicKey))
    dir:=t.TempDir()
    path:=filepath.Join(dir,"qbft-db")
    db:=rQBFTOpenDisk(t,path)
    g:=genesis.MustCommit(db)
    if g.Hash()!=block.ParentHash() || rawdb.ReadCanonicalHash(db,1)!=(common.Hash{}){
        db.Close()
        t.Fatalf("R_QBFT_GENESIS_ONLY_FAILED got=%s want=%s",g.Hash(),block.ParentHash())
    }
    if err:=db.Close();err!=nil{t.Fatal(err)}
    encoded,err:=rlp.EncodeToBytes(block)
    if err!=nil{t.Fatal(err)}
    blockFile:=filepath.Join(dir,"committed_block.rlp")
    if err:=os.WriteFile(blockFile,encoded,0600);err!=nil{t.Fatal(err)}
    keyHex:=hex.EncodeToString(crypto.FromECDSA(f.validatorKeys[0]))
    for _,mode:=range []string{"head_after","os_fsize"}{
        t.Run(mode,func(t *testing.T){
            runDir:=filepath.Join(t.TempDir(),"chaindata")
            if err:=os.MkdirAll(runDir,0700);err!=nil{t.Fatal(err)}
            // Copy completed Genesis LevelDB only, not the in-memory validator
            // chain that generated the block (which is a distinct database).
            entries,err:=os.ReadDir(path)
            if err!=nil{t.Fatal(err)}
            for _,e:=range entries{
                if e.IsDir(){t.Fatal("R_QBFT_DB_UNEXPECTED_SUBDIR")}
                data,err:=os.ReadFile(filepath.Join(path,e.Name()))
                if err!=nil{t.Fatal(err)}
                if err:=os.WriteFile(filepath.Join(runDir,e.Name()),data,0600);err!=nil{t.Fatal(err)}
            }
            child:=exec.Command(os.Args[0],"-test.run=^TestRQBFTStorageCrashChild$","-test.v")
            child.Env=append(os.Environ(),
                "R_QBFT_STORAGE_CHILD=1",
                "R_QBFT_STORAGE_MODE="+mode,
                "R_QBFT_STORAGE_DB="+runDir,
                "R_QBFT_FAULT_BLOCK_RLP="+blockFile,
                "R_QBFT_FAULT_KEY_HEX="+keyHex,
            )
            output,err:=child.CombinedOutput()
            exit,ok:=err.(*exec.ExitError)
            if !ok||exit.ExitCode()!=1||
                !bytes.Contains(output,[]byte("R_QBFT_DEFAULT_VERIFIER_ACCEPTED mode="+mode))||
                !bytes.Contains(output,[]byte("R_QBFT_VALID_BLOCK_IMPORT_START mode="+mode))||
                bytes.Contains(output,[]byte("R_QBFT_FATAL_EXIT_MISSING")){
                t.Fatalf("R_QBFT_CHILD_EXPECTED_FATAL_NOT_REACHED mode=%s err=%v output=%s",mode,err,output)
            }
            if mode=="head_after"{
                if !bytes.Contains(output,[]byte("R_QBFT_SYNTHETIC_HEAD_BATCH_COMMITTED_THEN_ERROR")){
                    t.Fatalf("R_QBFT_HEAD_AFTER_TRIGGER_MISSING output=%s",output)
                }
            }else if !bytes.Contains(output,[]byte("R_QBFT_REAL_OS_EFBIG_CONFIRMED")){
                t.Fatalf("R_QBFT_REAL_OS_PROOF_MISSING output=%s",output)
            }
            t.Logf("R_QBFT_FAULT_EXPECTED_EXIT_PASS mode=%s",mode)
            recoveredDB:=rQBFTOpenDisk(t,runDir)
            reopened,reopenedBE:=rQBFTEngine(t,recoveredDB,f.validatorKeys[0])
            if err:=reopenedBE.VerifyHeader(reopened,block.Header(),true);err!=nil{
                reopenedBE.Stop();reopened.Stop();recoveredDB.Close()
                t.Fatalf("R_QBFT_POSTCRASH_VALID_SEAL_REJECTED mode=%s err=%v",mode,err)
            }
            latest:=reopened.CurrentBlock()
            if latest==nil||latest.NumberU64()!=0{
                reopenedBE.Stop();reopened.Stop();recoveredDB.Close()
                t.Fatalf("R_QBFT_CRASH_BAD_FULL_HEAD mode=%s full=%v",mode,latest)
            }
            canon:=reopened.GetCanonicalHash(1)==block.Hash()
            svc:=&Ethereum{blockchain:reopened,chainDb:recoveredDB}
            backend:=&EthAPIBackend{eth:svc}
            txApi:=ethapi.NewPublicTransactionPoolAPI(backend,new(ethapi.AddrLocker))
            blockApi:=ethapi.NewPublicBlockChainAPI(backend)
            rpcServer:=rpc.NewServer()
            if err:=rpcServer.RegisterName("eth",txApi);err!=nil{t.Fatal(err)}
            if err:=rpcServer.RegisterName("eth",blockApi);err!=nil{t.Fatal(err)}
            client:=rpc.DialInProc(rpcServer)
            ctx:=context.Background()
            var receipt map[string]interface{}
            err=client.CallContext(ctx,&receipt,"eth_getTransactionReceipt",tx.Hash())
            if err!=nil{t.Fatalf("R_QBFT_JSONRPC_RECEIPT_QUERY_FAILED mode=%s err=%v",mode,err)}
            var latestBlock map[string]interface{}
            err=client.CallContext(ctx,&latestBlock,"eth_getBlockByNumber","latest",false)
            if err!=nil||latestBlock==nil||latestBlock["number"]!="0x0"{
                t.Fatalf("R_QBFT_JSONRPC_LATEST_QUERY_WRONG mode=%s latest=%v err=%v",mode,latestBlock,err)
            }
            visible:=receipt!=nil&&receipt["blockHash"]==block.Hash().Hex()&&receipt["blockNumber"]=="0x1"
            if mode=="head_after"{
                if !canon||!visible{
                    t.Fatalf("R_QBFT_EXPECTED_SYNTHETIC_PUBLIC_INCONSISTENCY_MISSING canon=%t receipt=%v",canon,receipt)
                }
                t.Log("R_QBFT_SYNTHETIC_POSTCOMMIT_PUBLIC_MISMATCH_CONFIRMED latest=0x0 receipt=0x1 seals=3")
            }else{
                if canon||visible{
                    t.Fatalf("R_QBFT_REAL_OS_LIMIT_UNEXPECTED_EXPOSURE canon=%t receipt=%v",canon,receipt)
                }
                t.Log("R_QBFT_REAL_OS_EFBIG_NO_RECEIPT_EXPOSURE_PASS latest=0x0 receipt=null")
            }
            client.Close()
            rpcServer.Stop()
            _=reopenedBE.Stop()
            reopened.Stop()
            if err:=recoveredDB.Close();err!=nil{t.Fatal(err)}
        })
    }
    t.Log("R_QBFT_STORAGE_BOUNDARY_MATRIX_PASS 3of4_seals_default_engine_real_os_vs_synthetic_ack")
}
