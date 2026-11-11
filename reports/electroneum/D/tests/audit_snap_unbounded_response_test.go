package snap

// Bounded, local SNAP response decoding research fixture. This test never
// connects to a public network. Run against the immutable certified target.
import (
 "bytes"
 "encoding/binary"
 "fmt"
 "io"
 "runtime"
 "testing"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/core"
 "github.com/electroneum/electroneum-sc/p2p"
 "github.com/electroneum/electroneum-sc/p2p/enode"
 "github.com/electroneum/electroneum-sc/rlp"
)

type auditSnapRW struct {
 code uint64
 payload []byte
 used bool
}
func (rw *auditSnapRW) ReadMsg() (p2p.Msg,error) {
 if rw.used {return p2p.Msg{},io.EOF}
 rw.used=true
 return p2p.Msg{Code:rw.code,Size:uint32(len(rw.payload)),Payload:bytes.NewReader(rw.payload)},nil
}
func (rw *auditSnapRW) WriteMsg(msg p2p.Msg) error {return nil}

type auditSnapBackend struct{ packets, accounts, slots int }
func (*auditSnapBackend) Chain() *core.BlockChain {return nil}
func (*auditSnapBackend) RunPeer(peer *Peer, handler Handler) error {return handler(peer)}
func (*auditSnapBackend) PeerInfo(id enode.ID) interface{} {return nil}
func (b *auditSnapBackend) Handle(peer *Peer, p Packet) error {
 b.packets++
 switch x:=p.(type){
 case *AccountRangePacket: b.accounts=len(x.Accounts)
 case *StorageRangesPacket:
  for _, group:=range x.Slots {b.slots+=len(group)}
 }
 return nil
}
func auditSnapHash(i uint64) common.Hash {
 var h common.Hash
 binary.BigEndian.PutUint64(h[24:],i)
 return h
}
func auditSnapSendUnsolicited(code uint64, b []byte) (*auditSnapBackend,uint64,error) {
 backend:=new(auditSnapBackend)
 peer:=NewFakePeer(1,"audit-snap-peer-0001",&auditSnapRW{code:code,payload:b})
 var before,after runtime.MemStats
 runtime.ReadMemStats(&before)
 err:=HandleMessage(backend,peer)
 runtime.ReadMemStats(&after)
 return backend,after.TotalAlloc-before.TotalAlloc,err
}
func auditSnapAccounts(n int)([]byte,error){
 accounts:=make([]*AccountData,n)
 for i:=range accounts {
  accounts[i]=&AccountData{Hash:auditSnapHash(uint64(i+1)),Body:rlp.RawValue{0x80}}
 }
 return rlp.EncodeToBytes(&AccountRangePacket{ID:987654321,Accounts:accounts})
}
func auditSnapStorage(n int)([]byte,error){
 slots:=make([]*StorageData,n)
 for i:=range slots {
  slots[i]=&StorageData{Hash:auditSnapHash(uint64(i+1)),Body:[]byte{}}
 }
 return rlp.EncodeToBytes(&StorageRangesPacket{ID:987654321,Slots:[][]*StorageData{slots}})
}

// Demonstrates that the shipped decoder caps proof nodes but not Accounts.
// We never register/request ID 987654321; the packet is unsolicited.
func TestAuditSnapUnsolicitedAccounts(t *testing.T){
 for _,n:=range []int{32,4096,4097,65536}{
  t.Run(fmt.Sprintf("n_%d",n),func(t *testing.T){
   enc,err:=auditSnapAccounts(n);if err!=nil{t.Fatal(err)}
   if len(enc)>maxMessageSize{t.Fatalf("wire cap exceeded %d",len(enc))}
   observed,allocated,err:=auditSnapSendUnsolicited(AccountRangeMsg,enc)
   if err!=nil{t.Fatalf("actual HandleMessage rejected count %d: %v",n,err)}
   if observed.packets!=1||observed.accounts!=n {
    t.Fatalf("unexpected callback: packets %d accounts %d",observed.packets,observed.accounts)
   }
   // Counterfactual *illustrative* 4096 cap, not an endorsed production
   // threshold; legitimate small accounts may exceed 4096 per 2MiB response.
   var guarded AccountRangePacket
   msg:=p2p.Msg{Code:AccountRangeMsg,Size:uint32(len(enc)),Payload:bytes.NewReader(enc)}
   guardErr:=decodeLimited(msg,&guarded,fieldLimit{1,4096},fieldLimit{2,maxProofNodes})
   if (n>4096)==(guardErr==nil){t.Fatalf("counterfactual guard result inconsistent: count=%d err=%v",n,guardErr)}
   if n>4096{
    t.Logf("SNAP_ACCOUNT_UNCAPPED count=%d wire=%d decoder_alloc=%d unsolicited=true illustrative_guard_rejected=true",n,len(enc),allocated)
   }else{
    t.Logf("SNAP_ACCOUNT_HONEST_CONTROL count=%d wire=%d decoder_alloc=%d",n,len(enc),allocated)
   }
  })
 }
}

// Demonstrates an additional dimension: the existing top-level Slots list
// cap does not cap the number of entries in one nested storage-slot group.
func TestAuditSnapUnsolicitedNestedStorage(t *testing.T){
 for _,n:=range []int{32,4096,4097,65536}{
  t.Run(fmt.Sprintf("n_%d",n),func(t *testing.T){
   enc,err:=auditSnapStorage(n);if err!=nil{t.Fatal(err)}
   if len(enc)>maxMessageSize{t.Fatalf("wire cap exceeded %d",len(enc))}
   observed,allocated,err:=auditSnapSendUnsolicited(StorageRangesMsg,enc)
   if err!=nil{t.Fatalf("actual HandleMessage rejected nested count %d: %v",n,err)}
   if observed.packets!=1||observed.slots!=n {
    t.Fatalf("unexpected callback: packets %d slots %d",observed.packets,observed.slots)
   }
   var raw rlp.RawValue
   msg:=p2p.Msg{Code:StorageRangesMsg,Size:uint32(len(enc)),Payload:bytes.NewReader(enc)}
   if err:=msg.Decode(&raw);err!=nil{t.Fatal(err)}
   outer,err:=packetField(raw,1);if err!=nil{t.Fatal(err)}
   count,err:=countItems(outer,maxPacketItems);if err!=nil||count!=1{t.Fatalf("top-level: count=%d err=%v",count,err)}
   content,_,err:=rlp.SplitList(outer);if err!=nil{t.Fatal(err)}
   inner,_,err:=splitRaw(content);if err!=nil{t.Fatal(err)}
   _,guardErr:=countItems(inner,4096)
   if (n>4096)==(guardErr==nil){t.Fatalf("inner illustrative guard result inconsistent: n=%d err=%v",n,guardErr)}
   if n>4096{
    t.Logf("SNAP_NESTED_STORAGE_UNCAPPED count=%d outer=1 wire=%d decoder_alloc=%d unsolicited=true illustrative_guard_rejected=true",n,len(enc),allocated)
   }else{
    t.Logf("SNAP_NESTED_STORAGE_HONEST_CONTROL count=%d wire=%d decoder_alloc=%d",n,len(enc),allocated)
   }
  })
 }
}
