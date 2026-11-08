package core_test

// Integration reproduction: real Clef SignerAPI.SignTypedData -> approval UI
// -> temporary keystore wallet -> ECDSA signature. No external endpoint,
// real-world funds, mainnet, or third-party keys.
import (
 "bytes"
 "context"
 "errors"
 "fmt"
 "strings"
 "testing"
 "time"

 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/crypto"
 "github.com/electroneum/electroneum-sc/signer/core"
 "github.com/electroneum/electroneum-sc/signer/core/apitypes"
 "github.com/electroneum/electroneum-sc/signer/fourbyte"
 "github.com/electroneum/electroneum-sc/signer/storage"
)

// The reference UI grants approval only when every field it displays matches
// its human-reviewed safe instruction; hidden fields cannot be consented to.
type cConsentUI struct {
 *headlessUi
 expectedLast string
 forbiddenFirst string
 approvals []bool
 previews []string
 payloads [][]byte
}
func (ui *cConsentUI) ApproveSignData(req *core.SignDataRequest)(core.SignDataResponse,error){
 var display strings.Builder
 for _,entry:=range req.Messages {display.WriteString(entry.Pprint(1))}
 preview:=display.String()
 allowed:=strings.Contains(preview,ui.expectedLast) && !strings.Contains(preview,ui.forbiddenFirst)
 ui.approvals=append(ui.approvals,allowed)
 ui.previews=append(ui.previews,preview)
 ui.payloads=append(ui.payloads,append([]byte(nil),req.Rawdata...))
 return core.SignDataResponse{Approved:allowed},nil
}
func cClefBatch(seed int) apitypes.TypedData {
 return apitypes.TypedData{
  Types:apitypes.Types{
   "EIP712Domain":{{Name:"name",Type:"string"}},
   "Batch":{{Name:"instructions",Type:"Instruction[]"}},
   "Instruction":{{Name:"payee",Type:"address"},{Name:"amount",Type:"uint256"}},
  },
  PrimaryType:"Batch",
  Domain:apitypes.TypedDataDomain{Name:fmt.Sprintf("C-Clef-Signing-%d",seed)},
  Message:apitypes.TypedDataMessage{"instructions":[]interface{}{
   map[string]interface{}{"payee":"0x0000000000000000000000000000000000000011","amount":fmt.Sprintf("%d",10000+seed)},
   map[string]interface{}{"payee":"0x0000000000000000000000000000000000000022","amount":fmt.Sprintf("%d",20000+seed)},
   map[string]interface{}{"payee":"0x0000000000000000000000000000000000000033","amount":fmt.Sprintf("%d",30000+seed)},
  }},
 }
}
func cVerifyClefSignature(t *testing.T,ui *cConsentUI,owner common.Address, signature []byte){
 t.Helper()
 if len(signature)!=65 {t.Fatalf("unexpected Clef signature length %d",len(signature))}
 if signature[64]<27 || signature[64]>28 {t.Fatalf("unexpected legacy recovery v %d",signature[64])}
 adapted:=append([]byte(nil),signature...)
 adapted[64]-=27
 preimage:=ui.payloads[len(ui.payloads)-1]
 digest:=crypto.Keccak256(preimage)
 pub,err:=crypto.SigToPub(digest,adapted)
 if err!=nil {t.Fatalf("cannot recover signature: %v",err)}
 if crypto.PubkeyToAddress(*pub)!=owner {t.Fatal("signature does not recover owner")}
}
func TestWorkerCClefApprovalMismatchEndToEnd(t *testing.T) {
 for _,seed:=range []int{71,73,79}{
  t.Run(fmt.Sprintf("fresh-local-keystore-%d",seed),func(t *testing.T){
   db,err:=fourbyte.New();if err!=nil{t.Fatal(err)}
   ui:=&cConsentUI{
    headlessUi:&headlessUi{approveCh:make(chan string,8),inputCh:make(chan string,8)},
    expectedLast:fmt.Sprintf("%d",30000+seed),
    forbiddenFirst:fmt.Sprintf("%d",10000+seed),
   }
   am:=core.StartClefAccountManager(t.TempDir(),true,true,"")
   api:=core.NewSignerAPI(am,1337,true,ui,db,true,&storage.NoStorage{})
   ui.approveCh<-"Y"
   ui.inputCh<-"a_long_password"
   owner,err:=api.New(context.Background())
   if err!=nil{t.Fatal(err)}
   time.Sleep(300*time.Millisecond) // asynchronous keystore cache refresh
   original:=cClefBatch(seed)
   userAddr:=common.NewMixedcaseAddress(owner)
   ui.inputCh<-"a_long_password"
   sig1,err:=api.SignTypedData(context.Background(),userAddr,original)
   if err!=nil{t.Fatalf("baseline Clef rejected: %v",err)}
   if len(ui.approvals)!=1 || !ui.approvals[0]{t.Fatal("baseline UI did not approve")}
   cVerifyClefSignature(t,ui,owner,sig1)
   t.Logf("C_E2E_SIGNER_BASELINE_ACCEPTED seed=%d",seed)
   // Adversarial dApp changes the first *unseen* payee, while the final
   // human-visible payee and amount remain untouched.
   malicious:=cClefBatch(seed)
   malicious.Message["instructions"].([]interface{})[0].(map[string]interface{})["payee"]="0x0000000000000000000000000000000000000044"
   ui.inputCh<-"a_long_password"
   sig2,err:=api.SignTypedData(context.Background(),userAddr,malicious)
   if err!=nil{t.Fatalf("malicious hidden-instruction signature rejected: %v",err)}
   if len(ui.approvals)!=2 || !ui.approvals[1] {t.Fatal("UI did not accept the unchanged reviewed preview")}
   if ui.previews[0]!=ui.previews[1] {t.Fatal("reviewed preview differed, hypothesis defeated")}
   if bytes.Equal(ui.payloads[0],ui.payloads[1]) || bytes.Equal(sig1,sig2) {
    t.Fatal("malicious first instruction was not cryptographically bound")
   }
   cVerifyClefSignature(t,ui,owner,sig2)
   t.Logf("C_E2E_UI_IDENTICAL_APPROVAL seed=%d",seed)
   t.Logf("C_E2E_SIGNED_HIDDEN_PAYEE_CHANGE seed=%d",seed)
   t.Logf("C_E2E_SIGNATURE_RECOVERED_OWNER seed=%d",seed)
   // Counterexample: a change to the actual visible *last* instruction
   // is caught and denied by this same approval policy.
   visible:=cClefBatch(seed)
   visible.Message["instructions"].([]interface{})[2].(map[string]interface{})["amount"]="999999999"
   denied,err:=api.SignTypedData(context.Background(),userAddr,visible)
   if !errors.Is(err,core.ErrRequestDenied) || len(denied)!=0 || ui.approvals[len(ui.approvals)-1] {
    t.Fatalf("visible mutation failed to trigger denial: sig=%d err=%v",len(denied),err)
   }
   t.Logf("C_E2E_VISIBLE_CHANGE_DENIED seed=%d",seed)
  })
 }
 t.Log("C_E2E_THREE_DISTINCT_TEMP_KEYSTORES_COMPLETE")
 t.Log("C_E2E_NO_BLOCKCHAIN_STATE_OR_SPEND_ASSERTED")
}
