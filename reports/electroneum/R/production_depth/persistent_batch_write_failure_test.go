// Worker R P2d: local deterministic Batch.Write fault injection across the
// production BlockChain.InsertChain call. This is a contract-level error seam,
// not an OS power cut, torn WAL write, filesystem fault, or remote attack.
// This file is mounted only in a certified-source disposable GitHub CI scratch.
package core

import (
    "bytes"
    "errors"
    "fmt"
    "math/big"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/ethdb"
)

// Embed the full production DB interface; intercept only NewBatch/WithSize,
// leaving direct Put/Get, trie storage, ancient storage, and real LevelDB intact.
type rBatchFaultDB struct {
    ethdb.Database
    target string // payload or head
    phase string  // before or after an actual underlying batch.Write
}
func (d *rBatchFaultDB) NewBatch() ethdb.Batch {
    return &rBatchFaultBatch{Batch:d.Database.NewBatch(), owner:d}
}
func (d *rBatchFaultDB) NewBatchWithSize(n int) ethdb.Batch {
    return &rBatchFaultBatch{Batch:d.Database.NewBatchWithSize(n), owner:d}
}
type rBatchFaultBatch struct {
    ethdb.Batch
    owner *rBatchFaultDB
    touchedPayload bool
    touchedHead bool
}
func (b *rBatchFaultBatch) Put(key, value []byte) error {
    if bytes.Equal(key, []byte("LastBlock")) {
        b.touchedHead = true
    }
    // Exact LevelDB body and receipt schema: prefix b/r, height 8 bytes,
    // block hash 32 bytes. Avoid matching an unrelated one-byte prefix.
    if len(key)==41 && (key[0]=='b' || key[0]=='r') {
        b.touchedPayload = true
    }
    return b.Batch.Put(key,value)
}
func (b *rBatchFaultBatch) Write() error {
    hit := (b.owner.target=="payload" && b.touchedPayload && !b.touchedHead) ||
        (b.owner.target=="head" && b.touchedHead)
    if !hit { return b.Batch.Write() }
    if b.owner.phase=="after" {
        // Deliberately return failure after a SUCCESSFUL storage commit.
        // This models an ambiguous acknowledgement, not real LevelDB behavior.
        if err:=b.Batch.Write(); err!=nil { return err }
    } else if b.owner.phase!="before" {
        return fmt.Errorf("R_BATCH_BAD_PHASE: %s", b.owner.phase)
    }
    fmt.Fprintf(os.Stderr,"R_BATCH_FAILURE_TRIGGER target=%s phase=%s payload_keys=%t head_key=%t batch_bytes=%d\n",
        b.owner.target,b.owner.phase,b.touchedPayload,b.touchedHead,b.Batch.ValueSize())
    return errors.New("R_BATCH_SYNTHETIC_WRITE_ERROR_expected_fatal_process_exit")
}

// Construct the block fixture in MEMORY: the persistent faulted LevelDB gets
// ONLY genesis, not a pre-materialized block-1 state trie. This prevents the
// test from passing because state was accidentally persisted in setup.
func rBatchFixture(t *testing.T) (*Genesis,types.Blocks,*types.Transaction) {
    t.Helper()
    mem := rawdb.NewMemoryDatabase()
    gspec, first, _, expectedTx := rPersistFixture(t,mem)
    genesis := rawdb.ReadBlock(mem,rawdb.ReadCanonicalHash(mem,0),0)
    if genesis==nil { t.Fatal("R_BATCH_MEMORY_GENESIS_MISSING") }
    key,err:=crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
    if err!=nil { t.Fatal(err) }
    sender:=crypto.PubkeyToAddress(key.PublicKey)
    dst:=common.HexToAddress("0x0000000000000000000000000000000000000099")
    signer:=types.LatestSigner(gspec.Config)
    var tx *types.Transaction
    blocks,_:=GenerateChain(gspec.Config,genesis,ethash.NewFaker(),mem,2,func(i int,b *BlockGen) {
        if i==0 {
            var signErr error
            tx,signErr=types.SignTx(types.NewTransaction(
                b.TxNonce(sender),dst,big.NewInt(7),100000,b.BaseFee(),[]byte{0xaa,0xbb},
            ),signer,key)
            if signErr!=nil { t.Fatal(signErr) }
            b.AddTx(tx)
        }
    })
    if len(blocks)!=2 || tx==nil || tx.Hash()!=expectedTx.Hash() ||
        blocks[0].Hash()!=first.Hash() || blocks[1].ParentHash()!=first.Hash() {
        t.Fatalf("R_BATCH_MEMORY_POSITIVE_FIXTURE_INVALID want=%s got=%s",first.Hash(),blocks[0].Hash())
    }
    return gspec,blocks,tx
}

func TestRLevelDBBatchFailureProcessChild(t *testing.T) {
    if os.Getenv("R_BATCH_CHILD")!="1" { return }
    path:=os.Getenv("R_BATCH_PATH")
    stage:=os.Getenv("R_BATCH_STAGE")
    parts:=strings.Split(stage,"_")
    if len(parts)!=2 || (parts[0]!="payload" && parts[0]!="head") ||
        (parts[1]!="before" && parts[1]!="after") {
        t.Fatalf("R_BATCH_CHILD_BAD_STAGE: %s",stage)
    }
    _,blocks,_:=rBatchFixture(t)
    db:=rOpenPersist(t,path)
    genesisHash:=rawdb.ReadCanonicalHash(db,0)
    cfg:=rawdb.ReadChainConfig(db,genesisHash)
    if cfg==nil || rawdb.ReadCanonicalHash(db,1)!=(common.Hash{}) {
        t.Fatal("R_BATCH_CHILD_NONEMPTY_INITIAL_CHAIN")
    }
    wrapper:=&rBatchFaultDB{Database:db,target:parts[0],phase:parts[1]}
    chain,err:=NewBlockChain(wrapper,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
    if err!=nil { t.Fatalf("R_BATCH_CHILD_INIT_FAIL: %v",err) }
    if chain.CurrentBlock().NumberU64()!=0 { t.Fatal("R_BATCH_CHILD_INITIAL_HEAD_NOT_ZERO") }
    // Both candidate batches live inside this full production chain insertion.
    // The intended Write() returns an error, and log.Crit must exit(1).
    _,err=chain.InsertChain(blocks)
    t.Fatalf("R_BATCH_CHILD_FATAL_EXIT_MISSING stage=%s err=%v",stage,err)
}

func rBatchVerifyReimport(t *testing.T,db ethdb.Database,blocks types.Blocks,tx *types.Transaction) {
    t.Helper()
    cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
    if cfg==nil { t.Fatal("R_BATCH_MISSING_CONFIG") }
    chain,err:=NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
    if err!=nil { t.Fatalf("R_BATCH_CHAIN_REOPEN_FAIL: %v",err) }
    current:=chain.CurrentBlock()
    if current==nil || current.NumberU64()>1 ||
        (current.NumberU64()==1 && current.Hash()!=blocks[0].Hash()) {
        chain.Stop()
        t.Fatalf("R_BATCH_REOPEN_UNEXPECTED_FULL_HEAD current=%v",current)
    }
    before:=current.NumberU64()
    if index,err:=chain.InsertChain(blocks); err!=nil {
        chain.Stop()
        t.Fatalf("R_BATCH_RECOVERED_INSERT_FAIL from=%d index=%d err=%v",before,index,err)
    }
    if chain.CurrentBlock().Hash()!=blocks[1].Hash() ||
        chain.CurrentHeader().Hash()!=blocks[1].Hash() ||
        chain.CurrentFastBlock().Hash()!=blocks[1].Hash() ||
        chain.GetCanonicalHash(1)!=blocks[0].Hash() ||
        chain.GetCanonicalHash(2)!=blocks[1].Hash() {
        chain.Stop()
        t.Fatalf("R_BATCH_RECOVERED_HEADS_OR_CANONICAL_MISMATCH from=%d",before)
    }
    found,h,n,i:=rawdb.ReadTransaction(db,tx.Hash())
    receipt,rh,rn,ri:=rawdb.ReadReceipt(db,tx.Hash(),cfg)
    if found==nil || found.Hash()!=tx.Hash() || h!=blocks[0].Hash() || n!=1 || i!=0 ||
        receipt==nil || receipt.TxHash!=tx.Hash() || receipt.Status!=types.ReceiptStatusSuccessful ||
        rh!=blocks[0].Hash() || rn!=1 || ri!=0 {
        chain.Stop()
        t.Fatalf("R_BATCH_RECOVERED_TX_RECEIPT_MISMATCH from=%d",before)
    }
    t.Logf("R_BATCH_RECOVERED_IMPORT_PASS from=%d to=2 tx=1 receipt=1",before)
    chain.Stop()
}

func TestRLevelDBBatchWriteBoundary(t *testing.T) {
    // Baseline persists exactly the funded genesis. Generated block states
    // remain in the independent in-memory fixture database.
    base:=filepath.Join(t.TempDir(),"genesis-db")
    gspec,blocks,tx:=rBatchFixture(t)
    original:=rOpenPersist(t,base)
    committed:=gspec.MustCommit(original)
    if committed.Hash()!=blocks[0].ParentHash() ||
        rawdb.ReadCanonicalHash(original,1)!=(common.Hash{}) {
        original.Close()
        t.Fatal("R_BATCH_GENESIS_ONLY_CONTROL_FAIL")
    }
    if err:=original.Close();err!=nil{t.Fatal(err)}

    scenarios:=[]struct{name,target,phase string;payloadPersisted,headPersisted bool}{
        {"payload_before","payload","before",false,false},
        {"payload_after","payload","after",true,false},
        {"head_before","head","before",true,false},
        {"head_after","head","after",true,true},
    }
    for _,tc:=range scenarios {
        t.Run(tc.name,func(t *testing.T){
            path:=filepath.Join(t.TempDir(),"chaindata")
            rWALCopyDirectory(t,base,path)
            child:=exec.Command(os.Args[0],"-test.run=^TestRLevelDBBatchFailureProcessChild$","-test.v")
            child.Env=append(os.Environ(),"R_BATCH_CHILD=1","R_BATCH_PATH="+path,"R_BATCH_STAGE="+tc.name)
            out,err:=child.CombinedOutput()
            exit,ok:=err.(*exec.ExitError)
            marker:="R_BATCH_FAILURE_TRIGGER target="+tc.target+" phase="+tc.phase
            if !ok || exit.ExitCode()!=1 || !bytes.Contains(out,[]byte(marker)) ||
                bytes.Contains(out,[]byte("R_BATCH_CHILD_FATAL_EXIT_MISSING")) {
                t.Fatalf("R_BATCH_CHILD_NOT_EXPECTED_CRIT_EXIT stage=%s err=%v output=%s",tc.name,err,out)
            }
            t.Logf("R_BATCH_EXPECTED_FATAL_EXIT_PASS stage=%s exit=1",tc.name)
            db:=rOpenPersist(t,path)
            gotBody:=rawdb.ReadBody(db,blocks[0].Hash(),1)!=nil
            gotReceipt:=rawdb.ReadRawReceipts(db,blocks[0].Hash(),1)!=nil
            gotCanon:=rawdb.ReadCanonicalHash(db,1)==blocks[0].Hash()
            gotHead:=rawdb.ReadHeadBlockHash(db)==blocks[0].Hash()
            if gotBody!=tc.payloadPersisted || gotReceipt!=tc.payloadPersisted ||
                gotCanon!=tc.headPersisted || gotHead!=tc.headPersisted {
                db.Close()
                t.Fatalf("R_BATCH_BOUNDARY_ATOMICITY_FAIL stage=%s body=%t receipt=%t canonical=%t head=%t",
                    tc.name,gotBody,gotReceipt,gotCanon,gotHead)
            }
            if !tc.headPersisted {
                if found,_,_,_:=rawdb.ReadTransaction(db,tx.Hash());found!=nil {
                    db.Close()
                    t.Fatalf("R_BATCH_UNCOMMITTED_TX_EXPOSED stage=%s",tc.name)
                }
            }
            t.Logf("R_BATCH_WRITE_BOUNDARY_PASS stage=%s payload=%t canonical=%t head=%t",
                tc.name,gotBody,gotCanon,gotHead)
            rBatchVerifyReimport(t,db,blocks,tx)
            if err:=db.Close();err!=nil{t.Fatal(err)}
            reopened:=rOpenPersist(t,path)
            rBatchVerifyReimport(t,reopened,blocks,tx)
            t.Logf("R_BATCH_SECOND_RESTART_PASS stage=%s head=2",tc.name)
            if err:=reopened.Close();err!=nil{t.Fatal(err)}
        })
    }
    t.Log("R_BATCH_WRITE_BOUNDARY_MATRIX_PASS synthetic_Batch_Write_failure_not_disk_fs_sync_or_remote_exploit")
}
