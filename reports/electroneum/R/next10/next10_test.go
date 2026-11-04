// Independent adversarial tests: certified Electroneum source only; no live chain,
// real wallet secrets, remote endpoints or modifications to the certified tree.
package audit_r_next10

import (
 "bytes"
 "encoding/binary"
 "encoding/json"
 "math/big"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/electroneum/electroneum-sc/accounts/abi"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/common/hexutil"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/rlp"
 "github.com/electroneum/electroneum-sc/rpc"
)

func TestRNext10RPCIngress(t *testing.T) {
 s:=rpc.NewServer(); defer s.Stop()
 valid:=[]byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rpc_modules\"}")
 cases:=[]struct{name,method,media string; length int64; expected int}{
  {"valid",http.MethodPost,"application/json",0,http.StatusOK},
  {"put",http.MethodPut,"application/json",0,http.StatusMethodNotAllowed},
  {"delete",http.MethodDelete,"application/json",0,http.StatusMethodNotAllowed},
  {"wrong_media",http.MethodPost,"text/plain",0,http.StatusUnsupportedMediaType},
  {"missing_media",http.MethodPost,"",0,http.StatusUnsupportedMediaType},
  {"oversize",http.MethodPost,"application/json",1<<30,http.StatusRequestEntityTooLarge},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  req:=httptest.NewRequest(tc.method,"http://example.invalid/rpc",bytes.NewReader(valid))
  if tc.media!=""{req.Header.Set("Content-Type",tc.media)}
  if tc.length>0{req.ContentLength=tc.length}
  rec:=httptest.NewRecorder();s.ServeHTTP(rec,req)
  if rec.Code!=tc.expected{t.Fatalf("status=%d want=%d body=%s",rec.Code,tc.expected,rec.Body.String())}
  if tc.expected==http.StatusOK&&!bytes.Contains(rec.Body.Bytes(),[]byte("\"result\"")){t.Fatalf("valid request produced no result: %s",rec.Body.String())}
 })}
 t.Log("R10_RPC_INGRESS_CONTROLS_PASS")
}

func TestRNext10RPCBatch(t *testing.T) {
 s:=rpc.NewServer();defer s.Stop()
 body:="[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rpc_modules\"},{\"jsonrpc\":\"2.0\",\"id\":\"bad\",\"method\":\"rpc_nonexistent\"},{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"rpc_modules\"}]"
 req:=httptest.NewRequest(http.MethodPost,"http://example.invalid/rpc",strings.NewReader(body));req.Header.Set("Content-Type","application/json")
 rec:=httptest.NewRecorder();s.ServeHTTP(rec,req)
 if rec.Code!=http.StatusOK{t.Fatalf("status %d: %s",rec.Code,rec.Body.String())}
 var result []map[string]json.RawMessage
 if err:=json.Unmarshal(rec.Body.Bytes(),&result);err!=nil{t.Fatalf("response not a JSON batch: %v %s",err,rec.Body.String())}
 if len(result)!=3{t.Fatalf("responses=%d expected 3",len(result))}
 seen:=map[string]bool{}
 for _,item:=range result{
  key:=string(item["id"]);if seen[key]{t.Fatalf("duplicate id=%s",key)};seen[key]=true
  hasError:=item["error"]!=nil&&string(item["error"])!="null"
  hasResult:=item["result"]!=nil&&string(item["result"])!="null"
  switch key{
  case "\"bad\"":if !hasError||hasResult{t.Fatalf("unknown method didn't fail alone: %v",item)}
  case "1","3":if hasError||!hasResult{t.Fatalf("valid result contaminated: %v",item)}
  default:t.Fatalf("unexpected response ID=%s",key)
  }
 }
 if !seen["1"]||!seen["3"]||!seen["\"bad\""]{t.Fatalf("missing IDs: %v",seen)}
 t.Log("R10_RPC_BATCH_ID_ISOLATION_PASS")
}

func TestRNext10RPCQuantity(t *testing.T) {
 for _,v:=range []uint64{0,1,15,16,255,256,65535,1<<32,1<<63,^uint64(0)}{
  enc:=hexutil.EncodeUint64(v);got,err:=hexutil.DecodeUint64(enc)
  if err!=nil||got!=v{t.Fatalf("roundtrip value=%d enc=%s got=%d err=%v",v,enc,got,err)}
 }
 for _,s:=range []string{"","1","0x","0x00","0x01","0x000a","0x-1","0xzz","0x10000000000000000"}{
  if _,err:=hexutil.DecodeUint64(s);err==nil{t.Fatalf("noncanonical quantity accepted: %q",s)}
 }
 t.Log("R10_HEX_QUANTITY_CANONICALITY_PASS")
}

func TestRNext10RLPCanonical(t *testing.T) {
 for _,v:=range []uint64{0,1,127,128,255,256,65535,1<<32,^uint64(0)}{
  enc,err:=rlp.EncodeToBytes(v);if err!=nil{t.Fatal(err)}
  var got uint64
  if err=rlp.DecodeBytes(enc,&got);err!=nil||got!=v{t.Fatalf("roundtrip %d -> %d err=%v",v,got,err)}
 }
 for i,b:=range [][]byte{{0x00},{0x81,0x01},{0xb8,0x01,0x00},{0xc0},{0x01,0x01},{0xb9,0xff,0xff}}{
  var got uint64
  if err:=rlp.DecodeBytes(b,&got);err==nil{t.Fatalf("noncanonical sample %d accepted: %x",i,b)}
 }
 t.Log("R10_RLP_NONCANONICAL_LENGTH_TRAILING_PASS")
}

func TestRNext10ABIOffset(t *testing.T) {
 typ,err:=abi.NewType("bytes","",nil);if err!=nil{t.Fatal(err)}
 args:=abi.Arguments{{Type:typ}}
 valid,err:=args.Pack([]byte("audit"));if err!=nil{t.Fatal(err)}
 got,err:=args.Unpack(valid)
 if err!=nil||len(got)!=1{t.Fatalf("valid bytes failed: %v %v",got,err)}
 value,ok:=got[0].([]byte);if !ok||!bytes.Equal(value,[]byte("audit")){t.Fatalf("valid bytes altered: %v",got)}
 for i:=0;i<64;i++{
  bad:=append([]byte(nil),valid...)
  binary.BigEndian.PutUint64(bad[24:32],uint64(len(bad)+32+i*32))
  if _,err:=args.Unpack(bad);err==nil{t.Fatalf("out-of-bounds pointer %d accepted",i)}
 }
 bad:=append([]byte(nil),valid...);bad[0]=0xff
 if _,err:=args.Unpack(bad);err==nil{t.Fatal("256-bit offset accepted")}
 if _,err:=args.Unpack(valid[:31]);err==nil{t.Fatal("truncated offset accepted")}
 t.Log("R10_ABI_DYNAMIC_OFFSET_BOUNDS_PASS")
}

func TestRNext10ABIAllocation(t *testing.T) {
 typ,err:=abi.NewType("uint8[]","",nil);if err!=nil{t.Fatal(err)}
 args:=abi.Arguments{{Type:typ}}
 valid,err:=args.Pack([]uint8{1,2,3});if err!=nil{t.Fatal(err)}
 got,err:=args.Unpack(valid)
 if err!=nil||len(got)!=1{t.Fatalf("valid array failed: %v %v",got,err)}
 for _,n:=range []uint64{4,5,32,512,1<<20,1<<32,^uint64(0)}{
  bad:=append([]byte(nil),valid...)
  binary.BigEndian.PutUint64(bad[56:64],n)
  if _,err:=args.Unpack(bad);err==nil{t.Fatalf("invalid array count %d accepted",n)}
 }
 bad:=append([]byte(nil),valid...);bad[32]=0xff
 if _,err:=args.Unpack(bad);err==nil{t.Fatal("oversize array count accepted")}
 t.Log("R10_ABI_DYNAMIC_ARRAY_RESOURCE_BOUNDS_PASS")
}

func r10KeyBytes() []byte{b:=make([]byte,32);b[31]=1;return b}

func TestRNext10ScalarBounds(t *testing.T) {
 if _,err:=crypto.ToECDSA(r10KeyBytes());err!=nil{t.Fatalf("valid scalar rejected: %v",err)}
 n:=crypto.S256().Params().N
 nMinusOne:=new(big.Int).Sub(n,big.NewInt(1)).FillBytes(make([]byte,32))
 if _,err:=crypto.ToECDSA(nMinusOne);err!=nil{t.Fatalf("N-1 rejected: %v",err)}
 bad:=[][]byte{make([]byte,32),[]byte{1},n.FillBytes(make([]byte,32)),new(big.Int).Add(n,big.NewInt(1)).FillBytes(make([]byte,32))}
 for _,raw:=range bad{if _,err:=crypto.ToECDSA(raw);err==nil{t.Fatalf("out-of-domain scalar accepted: %x",raw)}}
 t.Log("R10_PRIVATE_SCALAR_BOUNDARIES_PASS")
}

func TestRNext10SignatureMalleability(t *testing.T) {
 key,err:=crypto.ToECDSA(r10KeyBytes());if err!=nil{t.Fatal(err)}
 digest:=crypto.Keccak256([]byte("worker R independent low-S oracle"))
 sig,err:=crypto.Sign(digest,key);if err!=nil{t.Fatal(err)}
 if len(sig)!=crypto.SignatureLength{t.Fatal("signature width mismatch")}
 pub,err:=crypto.SigToPub(digest,sig)
 if err!=nil{t.Fatalf("recover error %v",err)}
 if crypto.PubkeyToAddress(*pub)!=crypto.PubkeyToAddress(key.PublicKey){t.Fatal("valid signature recovered wrong signer")}
 r:=new(big.Int).SetBytes(sig[:32]);s:=new(big.Int).SetBytes(sig[32:64])
 if !crypto.ValidateSignatureValues(sig[64],r,s,true){t.Fatal("valid low-S rejected")}
 highS:=new(big.Int).Sub(crypto.S256().Params().N,s)
 if crypto.ValidateSignatureValues(sig[64],r,highS,true){t.Fatal("malleable high-S accepted")}
 if crypto.ValidateSignatureValues(2,r,s,true){t.Fatal("invalid recovery ID accepted")}
 t.Log("R10_SIGNATURE_MALLEABILITY_LOW_S_PASS")
}

func TestRNext10ChainIDReplay(t *testing.T) {
 key,err:=crypto.ToECDSA(r10KeyBytes());if err!=nil{t.Fatal(err)}
 addr:=crypto.PubkeyToAddress(key.PublicKey)
 for chain:=int64(1);chain<=16;chain++{
  signer:=types.NewEIP155Signer(big.NewInt(chain))
  tx,err:=types.SignTx(types.NewTransaction(uint64(chain),addr,big.NewInt(0),21000,big.NewInt(1),nil),signer,key)
  if err!=nil{t.Fatalf("sign chain %d: %v",chain,err)}
  got,err:=types.Sender(signer,tx)
  if err!=nil||got!=addr{t.Fatalf("valid chain %d rejected: %v",chain,err)}
  if _,err=types.Sender(types.NewEIP155Signer(big.NewInt(chain+1)),tx);err!=types.ErrInvalidChainId{t.Fatalf("foreign chain %d accepted or unexpected error: %v",chain+1,err)}
 }
 t.Log("R10_EIP155_16_DOMAIN_ANTIREPLAY_PASS")
}

func TestRNext10TypedTxEnvelope(t *testing.T) {
 to:=common.HexToAddress("0x0000000000000000000000000000000000001234")
 tx:=types.NewTx(&types.AccessListTx{ChainID:big.NewInt(1),Nonce:7,GasPrice:big.NewInt(1),Gas:21000,To:&to,Value:big.NewInt(2),Data:[]byte{1,2}})
 enc,err:=tx.MarshalBinary();if err!=nil{t.Fatal(err)}
 var got types.Transaction
 if err:=got.UnmarshalBinary(enc);err!=nil{t.Fatalf("valid typed binary rejected: %v",err)}
 if got.Hash()!=tx.Hash()||got.Type()!=tx.Type(){t.Fatal("valid typed transaction corrupted")}
 for _,bad:=range [][]byte{append([]byte{0x7f},enc[1:]...),enc[:1],enc[:3],enc[:len(enc)-1]}{
  var invalid types.Transaction
  if err:=invalid.UnmarshalBinary(bad);err==nil{t.Fatalf("unknown/truncated typed envelope accepted: %x",bad)}
 }
 t.Log("R10_TYPED_TX_ENVELOPE_UNKNOWN_TRUNCATED_PASS")
}
