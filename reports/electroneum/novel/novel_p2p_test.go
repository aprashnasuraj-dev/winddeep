package eth
import (
 "encoding/binary"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/rlp"
)
type novelCountingPool struct{lookups int}
func (p *novelCountingPool) Get(common.Hash)*types.Transaction{p.lookups++;return nil}
type novelPooledBackend struct{Backend;pool *novelCountingPool}
func (b *novelPooledBackend) TxPool() TxPool{return b.pool}
func novelHash(i uint64)common.Hash{var h common.Hash;binary.BigEndian.PutUint64(h[24:],i+1);return h}
func TestNovelGetPooledUnknownHashLookupAmplification(t *testing.T){
 for _,n:=range []int{256,1024,8192,100000}{
  req:=make(GetPooledTransactionsPacket,n)
  for i:=range req{req[i]=novelHash(uint64(i))}
  wire,err:=rlp.EncodeToBytes(GetPooledTransactionsPacket66{RequestId:1,GetPooledTransactionsPacket:req})
  if err!=nil{t.Fatal(err)}
  if len(wire)>maxMessageSize{t.Fatalf("wire cap exceeded %d",len(wire))}
  var decoded GetPooledTransactionsPacket66
  if err:=rlp.DecodeBytes(wire,&decoded);err!=nil{t.Fatal(err)}
  if len(decoded.GetPooledTransactionsPacket)!=n{t.Fatal("decode lost request hashes")}
  pool:=&novelCountingPool{}
  backend:=&novelPooledBackend{pool:pool}
  start:=time.Now()
  out,txs:=answerGetPooledTransactions(backend,decoded.GetPooledTransactionsPacket,nil)
  elapsed:=time.Since(start)
  if pool.lookups!=n||len(out)!=0||len(txs)!=0{t.Fatalf("invariant missing lookups=%d expected=%d",pool.lookups,n)}
  t.Logf("NOVEL_POOL_LOOKUP wire_bytes=%d requested=%d target_pool_Get_calls=%d response_count=%d elapsed=%s",len(wire),n,pool.lookups,len(out),elapsed)
 }
}
func TestNovelNewBlockHashesUnboundedRLPAndUnpack(t *testing.T){
 for _,n:=range []int{256,1024,8192,100000}{
  packet:=make(NewBlockHashesPacket,n)
  for i:=range packet{packet[i].Hash=novelHash(uint64(i));packet[i].Number=uint64(i+1)}
  wire,err:=rlp.EncodeToBytes(packet);if err!=nil{t.Fatal(err)}
  if len(wire)>maxMessageSize{t.Fatalf("wire cap exceeded %d",len(wire))}
  var decoded NewBlockHashesPacket
  start:=time.Now()
  if err:=rlp.DecodeBytes(wire,&decoded);err!=nil{t.Fatal(err)}
  hashes,nums:=decoded.Unpack()
  elapsed:=time.Since(start)
  if len(hashes)!=n||len(nums)!=n||hashes[n-1]!=novelHash(uint64(n-1))||nums[n-1]!=uint64(n){t.Fatal("invalid unpack")}
  t.Logf("NOVEL_HASH_ANNOUNCE wire_bytes=%d decoded=%d unpacked_hashes=%d unpacked_numbers=%d elapsed=%s",len(wire),len(decoded),len(hashes),len(nums),elapsed)
 }
}
