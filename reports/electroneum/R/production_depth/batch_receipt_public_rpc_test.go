// Worker R P2e: observe public API receipt after fatal, synthetic post-commit
// batch acknowledgement failure. No fsync/power-cut or remote exploit is claimed.
// Mounted only in the disposable certified-source /internal/ethapi scratch.
package ethapi

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "math/big"
    "os"
    "os/exec"
    "path/filepath"
    "testing"

    "github.com/electroneum/electroneum-sc/common"
    "github.com/electroneum/electroneum-sc/common/hexutil"
    "github.com/electroneum/electroneum-sc/consensus/ethash"
    "github.com/electroneum/electroneum-sc/core"
    "github.com/electroneum/electroneum-sc/core/rawdb"
    "github.com/electroneum/electroneum-sc/core/types"
    "github.com/electroneum/electroneum-sc/core/vm"
    "github.com/electroneum/electroneum-sc/crypto"
    "github.com/electroneum/electroneum-sc/ethdb"
    "github.com/electroneum/electroneum-sc/params"
    "github.com/electroneum/electroneum-sc/rpc"
)
type rRPCHeadFailDB struct{ ethdb.Database }
type rRPCHeadFailBatch struct { ethdb.Batch; seenHead bool }
func(d *rRPCHeadFailDB) NewBatch() ethdb.Batch {
    return &rRPCHeadFailBatch{Batch:d.Database.NewBatch()}
}
func(d *rRPCHeadFailDB) NewBatchWithSize(n int) ethdb.Batch {
    return &rRPCHeadFailBatch{Batch:d.Database.NewBatchWithSize(n)}
}
func(b *rRPCHeadFailBatch) Put(k,v []byte)error{
    if bytes.Equal(k,[]byte("LastBlock")){b.seenHead=true}
    return b.Batch.Put(k,v)
}
func(b *rRPCHeadFailBatch) Write()error{
    if !b.seenHead{return b.Batch.Write()}
    if err:=b.Batch.Write();err!=nil{return err}
    fmt.Fprintln(os.Stderr,"R_RPC_HEAD_BATCH_COMMITTED_THEN_ERROR")
    return errors.New("R_RPC_SYNTHETIC_POST_COMMIT_ACK_FAILURE")
}
func rRPCFixture(t *testing.T)(*core.Genesis,*types.Block,*types.Transaction){
    t.Helper()
    mem:=rawdb.NewMemoryDatabase()
    key,err:=crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
    if err!=nil{t.Fatal(err)}
    sender:=crypto.PubkeyToAddress(key.PublicKey)
    dest:=common.HexToAddress("0x0000000000000000000000000000000000000099")
    cfg:=*params.TestChainConfig
    g:=&core.Genesis{Config:&cfg,GasLimit:8_000_000,Alloc:core.GenesisAlloc{
        sender:{Balance:new(big.Int).Mul(big.NewInt(1000),big.NewInt(1e18))},
    }}
    genesis:=g.MustCommit(mem)
    signer:=types.LatestSigner(&cfg)
    var tx *types.Transaction
    blocks,_:=core.GenerateChain(&cfg,genesis,ethash.NewFaker(),mem,1,func(_ int,b *core.BlockGen){
        tx,err=types.SignTx(types.NewTransaction(b.TxNonce(sender),dest,big.NewInt(7),100000,b.BaseFee(),[]byte{0xaa,0xbb}),signer,key)
        if err!=nil{t.Fatal(err)}
        b.AddTx(tx)
    })
    if len(blocks)!=1||tx==nil{t.Fatal("R_RPC_BLOCK_FIXTURE_INVALID")}
    return g,blocks[0],tx
}
func rRPCOpen(t *testing.T,path string)ethdb.Database{
    t.Helper()
    db,err:=rawdb.NewLevelDBDatabase(path,16,16,"r-rpc-crash",false)
    if err!=nil{t.Fatal(err)}
    return db
}
type rRPCTestBackend struct { Backend; db ethdb.Database; chain *core.BlockChain }
func(b *rRPCTestBackend) ChainConfig()*params.ChainConfig{return b.chain.Config()}
func(b *rRPCTestBackend) GetTransaction(_ context.Context,h common.Hash)(*types.Transaction,common.Hash,uint64,uint64,error){
    tx,bh,bn,i:=rawdb.ReadTransaction(b.db,h)
    return tx,bh,bn,i,nil
}
func(b *rRPCTestBackend) GetReceipts(_ context.Context,h common.Hash)(types.Receipts,error){
    return b.chain.GetReceiptsByHash(h),nil
}
func(b *rRPCTestBackend) HeaderByHash(_ context.Context,h common.Hash)(*types.Header,error){
    return b.chain.GetHeaderByHash(h),nil
}
func TestRPublicReceiptAfterHeadBatchCrashChild(t *testing.T){
    if os.Getenv("R_RPC_BATCH_CHILD")!="1"{return}
    _,block,_:=rRPCFixture(t)
    db:=rRPCOpen(t,os.Getenv("R_RPC_BATCH_PATH"))
    cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
    if cfg==nil||rawdb.ReadCanonicalHash(db,1)!=(common.Hash{}){t.Fatal("R_RPC_BAD_SEED")}
    chain,err:=core.NewBlockChain(&rRPCHeadFailDB{Database:db},nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
    if err!=nil{t.Fatal(err)}
    if chain.CurrentBlock().NumberU64()!=0{t.Fatal("R_RPC_BAD_INITIAL_FULL_HEAD")}
    _,err=chain.InsertChain(types.Blocks{block})
    t.Fatalf("R_RPC_CHILD_UNEXPECTED_RETURN err=%v",err)
}
func TestRPublicReceiptCrashVisibility(t *testing.T){
    g,block,tx:=rRPCFixture(t)
    path:=filepath.Join(t.TempDir(),"crashdb")
    db:=rRPCOpen(t,path)
    if genesis:=g.MustCommit(db);genesis.Hash()!=block.ParentHash(){
        db.Close();t.Fatal("R_RPC_GENESIS_DISAGREEMENT")
    }
    if err:=db.Close();err!=nil{t.Fatal(err)}
    child:=exec.Command(os.Args[0],"-test.run=^TestRPublicReceiptAfterHeadBatchCrashChild$","-test.v")
    child.Env=append(os.Environ(),"R_RPC_BATCH_CHILD=1","R_RPC_BATCH_PATH="+path)
    out,err:=child.CombinedOutput()
    exit,ok:=err.(*exec.ExitError)
    if !ok||exit.ExitCode()!=1||!bytes.Contains(out,[]byte("R_RPC_HEAD_BATCH_COMMITTED_THEN_ERROR"))||
        bytes.Contains(out,[]byte("R_RPC_CHILD_UNEXPECTED_RETURN")){
        t.Fatalf("R_RPC_FATAL_CHILD_CONTROL_FAIL err=%v output=%s",err,out)
    }
    db=rRPCOpen(t,path)
    if rawdb.ReadHeadBlockHash(db)!=block.Hash()||rawdb.ReadCanonicalHash(db,1)!=block.Hash(){
        db.Close();t.Fatal("R_RPC_HEAD_INDEX_PERSISTENCE_CONTROL_FAIL")
    }
    cfg:=rawdb.ReadChainConfig(db,rawdb.ReadCanonicalHash(db,0))
    chain,err:=core.NewBlockChain(db,nil,cfg,ethash.NewFaker(),vm.Config{},nil,nil)
    if err!=nil{db.Close();t.Fatal(err)}
    fullHead:=chain.CurrentBlock().NumberU64()
    if fullHead!=0||chain.GetCanonicalHash(1)!=block.Hash(){
        chain.Stop();db.Close()
        t.Fatalf("R_RPC_PRE_REPLAY_STATE_WRONG full=%d canonical=%s",fullHead,chain.GetCanonicalHash(1))
    }
    api:=NewPublicTransactionPoolAPI(&rRPCTestBackend{db:db,chain:chain},nil)
    ctx:=context.Background()
    receipt,err:=api.GetTransactionReceipt(ctx,tx.Hash())
    if err!=nil||receipt==nil||receipt["blockHash"]!=block.Hash()||
        receipt["transactionHash"]!=tx.Hash()||receipt["blockNumber"]!=hexutil.Uint64(1){
        chain.Stop();db.Close()
        t.Fatalf("R_RPC_PUBLIC_METHOD_RECEIPT_MISSING err=%v result=%v",err,receipt)
    }
    t.Logf("R_RPC_PUBLIC_METHOD_RECEIPT_VISIBLE full_head=%d receipt_height=1",fullHead)
    server:=rpc.NewServer()
    if err:=server.RegisterName("eth",api);err!=nil{
        chain.Stop();db.Close();t.Fatal(err)
    }
    client:=rpc.DialInProc(server)
    var returned map[string]interface{}
    err=client.CallContext(ctx,&returned,"eth_getTransactionReceipt",tx.Hash())
    if err!=nil||returned==nil||returned["blockHash"]!=block.Hash().Hex(){
        client.Close();server.Stop();chain.Stop();db.Close()
        t.Fatalf("R_RPC_INPROC_RECEIPT_MISSING err=%v result=%v",err,returned)
    }
    t.Logf("R_RPC_JSONRPC_RECEIPT_VISIBLE full_head=%d returned_block=%v",fullHead,returned["blockHash"])
    client.Close()
    server.Stop()
    chain.Stop()
    if err:=db.Close();err!=nil{t.Fatal(err)}
    t.Log("R_RPC_BATCH_CRASH_VISIBILITY_PASS local_synthetic_post_commit_only")
}
