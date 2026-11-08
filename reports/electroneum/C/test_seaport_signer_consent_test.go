package core_test

// Independent Seaport-v1.5-format EIP-712 consent-boundary test.
// Tests the shipped Electroneum signer with synthetic local accounts.
// No live contract, actual NFTs, real private keys, or public RPC used.
import (
 "bytes"
 "context"
 "errors"
 "fmt"
 "math/big"
 "strings"
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/common/math"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/signer/core"
 "github.com/electroneum/electroneum-sc/signer/core/apitypes"
 "github.com/electroneum/electroneum-sc/signer/fourbyte"
 "github.com/electroneum/electroneum-sc/signer/storage"
)
type seaportReviewUI struct {
 *headlessUi
 approvedPreview string
 previews []string
 raw [][]byte
}
func seaportReviewText(messages []*apitypes.NameValueType)string {
 var b strings.Builder
 for _,message:=range messages {b.WriteString(message.Pprint(1))}
 return b.String()
}
func(ui *seaportReviewUI)ApproveSignData(request *core.SignDataRequest)(core.SignDataResponse,error) {
 preview:=seaportReviewText(request.Messages)
 ui.previews=append(ui.previews,preview)
 ui.raw=append(ui.raw,append([]byte(nil),request.Rawdata...))
 return core.SignDataResponse{Approved:preview==ui.approvedPreview},nil
}
func seaportReviewOrder(owner,nft,safe,feeRecipient,contract common.Address, firstTokenId int64, secondStartAmount int64)apitypes.TypedData {
 const zeros="0x0000000000000000000000000000000000000000000000000000000000000000"
 const zeroAddr="0x0000000000000000000000000000000000000000"
 return apitypes.TypedData{
  Types:apitypes.Types{
   "EIP712Domain":{
    {Name:"name",Type:"string"},{Name:"version",Type:"string"},
    {Name:"chainId",Type:"uint256"},{Name:"verifyingContract",Type:"address"},
   },
   "OfferItem":{
    {Name:"itemType",Type:"uint8"},{Name:"token",Type:"address"},
    {Name:"identifierOrCriteria",Type:"uint256"},
    {Name:"startAmount",Type:"uint256"},{Name:"endAmount",Type:"uint256"},
   },
   "ConsiderationItem":{
    {Name:"itemType",Type:"uint8"},{Name:"token",Type:"address"},
    {Name:"identifierOrCriteria",Type:"uint256"},
    {Name:"startAmount",Type:"uint256"},{Name:"endAmount",Type:"uint256"},
    {Name:"recipient",Type:"address"},
   },
   "OrderComponents":{
    {Name:"offerer",Type:"address"},{Name:"zone",Type:"address"},
    {Name:"offer",Type:"OfferItem[]"},{Name:"consideration",Type:"ConsiderationItem[]"},
    {Name:"orderType",Type:"uint8"},{Name:"startTime",Type:"uint256"},
    {Name:"endTime",Type:"uint256"},{Name:"zoneHash",Type:"bytes32"},
    {Name:"salt",Type:"uint256"},{Name:"conduitKey",Type:"bytes32"},
    {Name:"counter",Type:"uint256"},
   },
  },
  PrimaryType:"OrderComponents",
  Domain:apitypes.TypedDataDomain{
   Name:"Seaport",Version:"1.5",
   ChainId:(*math.HexOrDecimal256)(big.NewInt(52014)),
   VerifyingContract:contract.Hex(),
  },
  Message:apitypes.TypedDataMessage{
   "offerer":owner.Hex(),"zone":zeroAddr,
   "offer":[]interface{}{
    map[string]interface{}{"itemType":"2","token":nft.Hex(),
        "identifierOrCriteria":fmt.Sprint(firstTokenId),"startAmount":"1","endAmount":"1"},
    map[string]interface{}{"itemType":"1","token":safe.Hex(),
        "identifierOrCriteria":"0","startAmount":fmt.Sprint(secondStartAmount),
        "endAmount":fmt.Sprint(secondStartAmount)},
   },
   "consideration":[]interface{}{
    map[string]interface{}{"itemType":"0","token":zeroAddr,
        "identifierOrCriteria":"0","startAmount":"1","endAmount":"1","recipient":feeRecipient.Hex()},
   },
   "orderType":"0","startTime":"0","endTime":"9999999999",
   "zoneHash":zeros,"salt":"995517","conduitKey":zeros,"counter":"0",
  },
 }
}
func TestWorkerCSeaportV15HiddenOfferConsent(t *testing.T){
 // This address is the public canonical Seaport 1.5 address.
 // Its deployment on ETN-SC 52014 is NOT established by this test.
 contract:=common.HexToAddress("0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC")
 for _,seed:=range []int{101,131,173}{
  t.Run(fmt.Sprintf("fresh-keystore-%d",seed),func(t *testing.T){
   db,e:=fourbyte.New();if e!=nil{t.Fatal(e)}
   ui:=&seaportReviewUI{headlessUi:&headlessUi{
    approveCh:make(chan string,8),inputCh:make(chan string,8)}}
   manager:=core.StartClefAccountManager(t.TempDir(),true,true,"")
   signer:=core.NewSignerAPI(manager,52014,true,ui,db,true,&storage.NoStorage{})
   ui.approveCh<-"Y";ui.inputCh<-"a_synthetic_testing_password"
   owner,e:=signer.New(context.Background());if e!=nil{t.Fatal(e)}
   time.Sleep(350*time.Millisecond)
   safe:=common.Address{0x21,byte(seed)}
   nft:=common.Address{0x31,byte(seed)}
   recipient:=common.Address{0x41,byte(seed)}
   honest:=seaportReviewOrder(owner,nft,safe,recipient,contract,17,1)
   honestMsgs,e:=honest.Format();if e!=nil{t.Fatal(e)}
   ui.approvedPreview=seaportReviewText(honestMsgs)
   if !strings.Contains(ui.approvedPreview,safe.Hex()) {
    t.Fatal("baseline readable offer absent")
   }
   mixed:=common.NewMixedcaseAddress(owner)
   ui.inputCh<-"a_synthetic_testing_password"
   goodSig,e:=signer.SignTypedData(context.Background(),mixed,honest)
   if e!=nil||len(goodSig)!=65{t.Fatalf("honest sign failed: %v",e)}
   malicious:=seaportReviewOrder(owner,nft,safe,recipient,contract,100000+int64(seed),1)
   ui.inputCh<-"a_synthetic_testing_password"
   hiddenSig,e:=signer.SignTypedData(context.Background(),mixed,malicious)
   if e!=nil||len(hiddenSig)!=65{t.Fatalf("hidden signed order failed: %v",e)}
   if len(ui.previews)!=2||ui.previews[0]!=ui.previews[1]{
    t.Fatal("hidden NFT ID affected human readable preview: hypothesis falsified")
   }
   if strings.Contains(ui.previews[1],fmt.Sprint(100000+seed)){
    t.Fatal("hidden NFT ID appeared in review")
   }
   if bytes.Equal(ui.raw[0],ui.raw[1])||bytes.Equal(goodSig,hiddenSig){
    t.Fatal("signed commitment unexpectedly unchanged")
   }
   compact:=append([]byte(nil),hiddenSig...)
   if compact[64]<27||compact[64]>28{t.Fatal("invalid recovery byte")}
   compact[64]-=27
   recovered,e:=crypto.SigToPub(crypto.Keccak256(ui.raw[1]),compact)
   if e!=nil||crypto.PubkeyToAddress(*recovered)!=owner{
    t.Fatalf("wrong signer: %v",e)
   }
   t.Logf("SEAPORT_C_HIDDEN_OFFER_SIGNED owner=%s state=%d hiddenNFT=%d rawSha=%x",
    owner,seed,100000+seed,crypto.Keccak256(ui.raw[1]))
   visible:=seaportReviewOrder(owner,nft,safe,recipient,contract,100000+int64(seed),2)
   denied,e:=signer.SignTypedData(context.Background(),mixed,visible)
   if !errors.Is(e,core.ErrRequestDenied)||len(denied)!=0{
    t.Fatalf("SEAPORT_C_VISIBLE_CONTROL_FAILED err=%v siglen=%d",e,len(denied))
   }
   t.Logf("SEAPORT_C_VISIBLE_CONTROL_DENIED seed=%d",seed)
  })
 }
 t.Log("SEAPORT_C_THREE_SIGNER_STATES_PASS_NO_DEPLOYMENT_CLAIM")
}
