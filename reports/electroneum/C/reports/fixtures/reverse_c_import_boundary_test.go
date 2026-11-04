// Independent reverse audit R: actual exported keystore import trust boundary.
// Synthetic locally generated encrypted wallets only. No real keys/RPC exposure.
// This fixture is copied into a certified Electroneum scratch source tree.
package keystore

import (
 "encoding/json"
 "testing"

 "github.com/electroneum/electroneum-sc/crypto"
)

func reverseCEncryptedSyntheticFixture(t *testing.T) []byte {
 t.Helper()
 key,e:=crypto.GenerateKey()
 if e!=nil {t.Fatal(e)}
 encoded,e:=EncryptKey(newKeyFromECDSA(key),"fixture-password",16,1)
 if e!=nil {t.Fatal(e)}
 return encoded
}
func reverseCModifyJSON(t *testing.T,valid []byte,modify func(map[string]interface{})) []byte {
 t.Helper()
 var doc map[string]interface{}
 if e:=json.Unmarshal(valid,&doc);e!=nil{t.Fatal(e)}
 modify(doc)
 value,e:=json.Marshal(doc)
 if e!=nil {t.Fatal(e)}
 return value
}
func reverseCImport(t *testing.T,input []byte)(recovered interface{},err error){
 t.Helper()
 ks:=NewKeyStore(t.TempDir(),16,1)
 func(){
  defer func(){recovered=recover()}()
  _,err=ks.Import(input,"fixture-password","rotated-fixture-password")
 }()
 return recovered,err
}
func TestReverseCExportedKeyStoreImportMatrix(t *testing.T){
 valid:=reverseCEncryptedSyntheticFixture(t)
 t.Run("valid_encrypted_key_import",func(t *testing.T){
  caught,err:=reverseCImport(t,valid)
  if caught!=nil||err!=nil {t.Fatalf("valid synthetic import failed panic=%v error=%v",caught,err)}
  t.Log("REVERSE_C_VALID_KEYSTORE_IMPORT_PASS")
 })
 cases:=[]struct{
  name string
  mutation func(map[string]interface{})
  expectedPanic bool
 }{
  {"missing_salt",func(x map[string]interface{}){delete(x["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{}),"salt")},true},
  {"numeric_salt",func(x map[string]interface{}){x["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{})["salt"]=42},true},
  {"invalid_aes_ctr_iv",func(x map[string]interface{}){x["crypto"].(map[string]interface{})["cipherparams"].(map[string]interface{})["iv"]="00"},true},
  {"unsupported_cipher",func(x map[string]interface{}){x["crypto"].(map[string]interface{})["cipher"]="not-a-supported-cipher"},false},
  {"invalid_mac_hex",func(x map[string]interface{}){x["crypto"].(map[string]interface{})["mac"]="zz"},false},
 }
 for _,c:=range cases {t.Run(c.name,func(t *testing.T){
  input:=reverseCModifyJSON(t,valid,c.mutation)
  caught,err:=reverseCImport(t,input)
  if c.expectedPanic{
   if caught==nil {t.Fatalf("source behavior changed; expected caught panic, got error=%v",err)}
   t.Logf("REVERSE_C_EXPORTED_IMPORT_PANIC_OBSERVED case=%s type=%T value=%v",c.name,caught,caught)
   return
  }
  if caught!=nil||err==nil {t.Fatalf("invalid cipher/MAC control should return error: panic=%v err=%v",caught,err)}
  t.Logf("REVERSE_C_EXPORTED_IMPORT_CONTROLLED_ERROR case=%s err=%v",c.name,err)
 })}
}
func TestReverseCExportedImportFailClosedOracle(t *testing.T){
 valid:=reverseCEncryptedSyntheticFixture(t)
 bad:=reverseCModifyJSON(t,valid,func(x map[string]interface{}){
  delete(x["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{}),"salt")
 })
 caught,err:=reverseCImport(t,bad)
 if caught!=nil {
  t.Errorf("REVERSE_C_EXPORT_IMPORT_FAIL_CLOSED_ORACLE_MISMATCH: missing salt panicked type=%T value=%v",caught,caught)
  return
 }
 if err==nil {t.Fatal("missing salt malformed JSON unexpectedly imported")}
 t.Logf("REVERSE_C_EXPORT_IMPORT_FAIL_CLOSED_ORACLE_PASS err=%v",err)
}


// TestReverseCExportedImportUnrecoveredPanic intentionally does NOT recover.
// The CI wrapper must observe nonzero go-test exit and an exact KeyStore.Import
// panic stack. This proves process-level propagation for a local library caller;
// it is not evidence of default remote RPC reachability.
func TestReverseCExportedImportUnrecoveredPanic(t *testing.T){
 valid:=reverseCEncryptedSyntheticFixture(t)
 bad:=reverseCModifyJSON(t,valid,func(x map[string]interface{}){
  delete(x["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{}),"salt")
 })
 t.Log("REVERSE_C_UNRECOVERED_IMPORT_BEGIN")
 ks:=NewKeyStore(t.TempDir(),16,1)
 _,_ = ks.Import(bad,"fixture-password","rotated-fixture-password")
 t.Fatal("REVERSE_C_UNRECOVERED_IMPORT_UNEXPECTED_RETURN")
}
