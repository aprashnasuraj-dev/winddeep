package apitypes

// Security regression characterization for Clef EIP-712 approval rendering.
// All keys and messages are synthetic. No RPC or blockchain network is touched.
// This file is installed into an immutable Electroneum source scratch copy by CI.
import (
    "bytes"
    "encoding/json"
    "fmt"
    "strings"
    "testing"

    "github.com/electroneum/electroneum-sc/crypto"
)

const cRecipient1 = "0x0000000000000000000000000000000000000011"
const cRecipient2 = "0x0000000000000000000000000000000000000022"
const cRecipient3 = "0x0000000000000000000000000000000000000033"
const cRecipient4 = "0x0000000000000000000000000000000000000044"

func cInstruction(payee, amount string) map[string]interface{} {
    return map[string]interface{}{"payee":payee,"amount":amount}
}
func cApprovalBatch(seed int) TypedData {
    return TypedData{
        Types:Types{
            "EIP712Domain":{{Name:"name",Type:"string"}},
            "Batch":{{Name:"instructions",Type:"Instruction[]"}},
            "Instruction":{{Name:"payee",Type:"address"},{Name:"amount",Type:"uint256"}},
        },
        PrimaryType:"Batch",
        Domain:TypedDataDomain{Name:fmt.Sprintf("C-fixture-%d",seed)},
        Message:TypedDataMessage{"instructions":[]interface{}{
            cInstruction(cRecipient1,fmt.Sprintf("%d",10000+seed)),
            cInstruction(cRecipient2,fmt.Sprintf("%d",20000+seed)),
            cInstruction(cRecipient3,fmt.Sprintf("%d",30000+seed)),
        }},
    }
}
func cApprovalPreview(td *TypedData) (string,error) {
    msg,err:=td.Format()
    if err!=nil {return "",err}
    if len(msg)!=2 || msg[1].Name!=td.PrimaryType {return "",fmt.Errorf("unexpected EIP712 approval schema")}
    return msg[1].Pprint(1),nil
}
func cApprovalDigest(td *TypedData) ([]byte,error) {
    domain,err:=td.HashStruct("EIP712Domain",td.Domain.Map())
    if err!=nil{return nil,err}
    message,err:=td.HashStruct(td.PrimaryType,td.Message)
    if err!=nil{return nil,err}
    payload:=make([]byte,0,66)
    payload=append(payload,0x19,0x01)
    payload=append(payload,domain...)
    payload=append(payload,message...)
    return crypto.Keccak256(payload),nil
}
func cMutationNoPreviewChange(t *testing.T, original *TypedData, mutate func(*TypedData), marker string) {
    t.Helper()
    before,err:=cApprovalPreview(original);if err!=nil{t.Fatal(err)}
    oldDigest,err:=cApprovalDigest(original);if err!=nil{t.Fatal(err)}
    changed:=cApprovalBatch(cSeedFromDomain(original.Domain.Name))
    mutate(&changed)
    after,err:=cApprovalPreview(&changed);if err!=nil{t.Fatal(err)}
    newDigest,err:=cApprovalDigest(&changed);if err!=nil{t.Fatal(err)}
    if before!=after {t.Fatalf("%s: attack was visible in UI; preview before=%q after=%q",marker,before,after)}
    if bytes.Equal(oldDigest,newDigest) {t.Fatalf("%s: signed hash was unchanged; invalid discriminator",marker)}
    t.Logf("%s: signing preimage digest changed while human-readable approval stayed byte-identical",marker)
}
func cSeedFromDomain(name string) int {
    var seed int
    fmt.Sscanf(name,"C-fixture-%d",&seed)
    return seed
}
func TestWorkerCApprovalRenderingVsSignature(t *testing.T) {
    for _,seed:=range []int{71,73,79} {
        t.Run(fmt.Sprintf("independent-state-%d",seed),func(t *testing.T){
            original:=cApprovalBatch(seed)
            preview,err:=cApprovalPreview(&original);if err!=nil{t.Fatal(err)}
            oracle,err:=json.Marshal(original.Message);if err!=nil{t.Fatal(err)}
            amount1:=fmt.Sprintf("%d",10000+seed)
            amount2:=fmt.Sprintf("%d",20000+seed)
            amount3:=fmt.Sprintf("%d",30000+seed)
            if !bytes.Contains(oracle,[]byte(amount1)) || !bytes.Contains(oracle,[]byte(amount2)) || !bytes.Contains(oracle,[]byte(amount3)) {
                t.Fatal("independent JSON oracle does not contain all three instructions")
            }
            if strings.Contains(preview,amount1) || strings.Contains(preview,amount2) || !strings.Contains(preview,amount3) {
                t.Fatalf("unexpected approval rendering %q",preview)
            }
            t.Logf("C_TYPED_HIDDEN_FIRST: seed=%d hidden-amount=%s",seed,amount1)
            t.Logf("C_TYPED_HIDDEN_MIDDLE: seed=%d hidden-amount=%s",seed,amount2)
            t.Logf("C_TYPED_JSON_ORACLE_ALL_ITEMS: seed=%d",seed)
            // Attack: mutate a hidden field while retaining identical displayed approval.
            cMutationNoPreviewChange(t,&original,func(d *TypedData){
                d.Message["instructions"].([]interface{})[0].(map[string]interface{})["payee"]=cRecipient4
            },"C_TYPED_HIDDEN_PAYEE_MUTATION")
            cMutationNoPreviewChange(t,&original,func(d *TypedData){
                d.Message["instructions"].([]interface{})[0].(map[string]interface{})["amount"]="999999"
            },"C_TYPED_HIDDEN_AMOUNT_MUTATION")
            cMutationNoPreviewChange(t,&original,func(d *TypedData){
                a:=d.Message["instructions"].([]interface{})
                a[0],a[1]=a[1],a[0]
            },"C_TYPED_HIDDEN_REORDER")
            cMutationNoPreviewChange(t,&original,func(d *TypedData){
                a:=d.Message["instructions"].([]interface{})
                d.Message["instructions"]=append([]interface{}{cInstruction(cRecipient4,"888888")},a...)
            },"C_TYPED_HIDDEN_PREPEND")
            cMutationNoPreviewChange(t,&original,func(d *TypedData){
                a:=d.Message["instructions"].([]interface{})
                d.Message["instructions"]=[]interface{}{a[0],a[2]}
            },"C_TYPED_HIDDEN_MIDDLE_REMOVAL")
            // Control: a one-item struct array is truthfully shown.
            one:=cApprovalBatch(seed)
            a:=one.Message["instructions"].([]interface{})
            one.Message["instructions"]=[]interface{}{a[len(a)-1]}
            pv,err:=cApprovalPreview(&one);if err!=nil{t.Fatal(err)}
            if !strings.Contains(pv,amount3) {t.Fatalf("single-element approval hidden: %q",pv)}
            t.Logf("C_TYPED_SINGLE_ITEM_CONTROL: seed=%d",seed)
            // Control: scalar fields must visibly change when signed inputs change.
            scalar:=TypedData{
                Types:Types{
                    "EIP712Domain":{{Name:"name",Type:"string"}},
                    "Scalar":{{Name:"amount",Type:"uint256"}},
                },
                PrimaryType:"Scalar",
                Domain:TypedDataDomain{Name:"C-scalar"},
                Message:TypedDataMessage{"amount":"42"},
            }
            p42,err:=cApprovalPreview(&scalar);if err!=nil{t.Fatal(err)}
            scalar.Message["amount"]="43"
            p43,err:=cApprovalPreview(&scalar);if err!=nil{t.Fatal(err)}
            if p42==p43 {t.Fatal("scalar baseline did not update approval")}
            t.Logf("C_TYPED_SCALAR_CONTROL: seed=%d",seed)
            // Control: primitive arrays must not silently get a misleading approval.
            primitive:=TypedData{
                Types:Types{
                    "EIP712Domain":{{Name:"name",Type:"string"}},
                    "Numbers":{{Name:"numbers",Type:"uint256[]"}},
                },
                PrimaryType:"Numbers",
                Domain:TypedDataDomain{Name:"C-array"},
                Message:TypedDataMessage{"numbers":[]interface{}{"1","2"}},
            }
            if _,err:=primitive.HashStruct("Numbers",primitive.Message);err!=nil{t.Fatalf("primitive array signed baseline rejected: %v",err)}
            if _,err:=primitive.Format();err==nil{t.Fatal("primitive array unexpectedly approved; investigate its rendering")}
            t.Logf("C_TYPED_PRIMITIVE_ARRAY_FAIL_CLOSED: seed=%d",seed)
            // The signer path signs the digest, not the user-facing approval representation.
            digest,err:=cApprovalDigest(&original);if err!=nil{t.Fatal(err)}
            keyBytes:=make([]byte,32);keyBytes[31]=byte(seed)
            key,err:=crypto.ToECDSA(keyBytes);if err!=nil{t.Fatal(err)}
            sig,err:=crypto.Sign(digest,key);if err!=nil{t.Fatal(err)}
            recovered,err:=crypto.SigToPub(digest,sig);if err!=nil{t.Fatal(err)}
            if crypto.PubkeyToAddress(*recovered)!=crypto.PubkeyToAddress(key.PublicKey) {
                t.Fatal("synthetic signature failed recovery")
            }
            t.Logf("C_TYPED_SIGNATURE_DIGEST_CONTROL: seed=%d digest=%x",seed,digest)
        })
    }
    // Separate integer-width hypothesis: permissive signed integer sizes.
    width:=TypedData{
        Types:Types{"EIP712Domain":{{Name:"name",Type:"string"}},"Width":{{Name:"value",Type:"int8"}}},
        PrimaryType:"Width",Domain:TypedDataDomain{Name:"C-width"},
        Message:TypedDataMessage{"value":"255"},
    }
    if _,err:=width.HashStruct("Width",width.Message);err!=nil{
        t.Logf("C_TYPED_SIGNED_INT8_GUARDED: %v",err)
    }else{
        t.Log("C_TYPED_SIGNED_INT8_OUT_OF_RANGE_ACCEPTED: non-standard int8 255 accepted; no security impact demonstrated")
    }
    t.Log("C_TYPED_PROBE_COMPLETED_NOT_CANONICAL_CHAIN_PROOF")
}
