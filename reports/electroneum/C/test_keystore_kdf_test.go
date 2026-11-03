package keystore

import (
 "encoding/json"
 "fmt"
 "testing"

 "github.com/electroneum/electroneum-sc/crypto"
)

// Worker C characterization: run only with certified, disposable Electroneum
// source materialization. No private keys, real wallets, or network traffic.
func TestWorkerCKDFMalformedInputCharacterization(t *testing.T) {
 baseline, err := EncryptDataV3([]byte("synthetic-only"), []byte("fixture-password"), 16, 1)
 if err != nil { t.Fatalf("baseline encryption: %v", err) }
 plain, err := DecryptDataV3(baseline, "fixture-password")
 if err != nil || string(plain) != "synthetic-only" { t.Fatalf("valid control: %q %v", plain, err) }
 t.Log("C_KDF_VALID_CONTROL_PASS")
 cases := []struct{name string; change func(*CryptoJSON)}{
  {"invalid_iv_length",func(c *CryptoJSON){c.CipherParams.IV="00"}},
  {"invalid_cipher",func(c *CryptoJSON){c.Cipher="aes-256-ctr"}},
  {"invalid_mac_hex",func(c *CryptoJSON){c.MAC="zz"}},
  {"missing_salt",func(c *CryptoJSON){delete(c.KDFParams,"salt")}},
  {"numeric_salt",func(c *CryptoJSON){c.KDFParams["salt"]=42}},
  {"string_dklen",func(c *CryptoJSON){c.KDFParams["dklen"]="32"}},
  {"short_dklen",func(c *CryptoJSON){c.KDFParams["dklen"]=8}},
  {"missing_n",func(c *CryptoJSON){delete(c.KDFParams,"n")}},
  {"invalid_scrypt_n",func(c *CryptoJSON){c.KDFParams["n"]=3}},
  {"missing_pbkdf2_prf",func(c *CryptoJSON){c.KDF="pbkdf2";c.KDFParams["c"]=1;delete(c.KDFParams,"prf")}},
  {"numeric_pbkdf2_prf",func(c *CryptoJSON){c.KDF="pbkdf2";c.KDFParams["c"]=1;c.KDFParams["prf"]=123}},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  c:=baseline
  c.KDFParams=make(map[string]interface{},len(baseline.KDFParams))
  for k,v:=range baseline.KDFParams {c.KDFParams[k]=v}
  tc.change(&c)
  var recovered interface{}
  var resultErr error
  var decrypted []byte
  func(){defer func(){recovered=recover()}(); decrypted,resultErr=DecryptDataV3(c,"fixture-password")}()
  if recovered!=nil {t.Logf("C_KDF_OBSERVED_PANIC case=%s type=%T detail=%v",tc.name,recovered,recovered)}
  if resultErr!=nil {t.Logf("C_KDF_OBSERVED_ERROR case=%s err=%v",tc.name,resultErr)}
  if tc.name == "short_dklen" {
   // Characterize and retain observed acceptance, do not mislabel as a safe rejection.
   key,keyErr := getKDFKey(c,"fixture-password")
   if keyErr != nil {t.Fatalf("derived key error: %v",keyErr)}
   t.Logf("C_KDF_SHORT_DKLEN_OBSERVED len=%d cap=%d panic=%t err=%v",len(key),cap(key),recovered!=nil,resultErr)
   if recovered!=nil || resultErr!=nil || string(decrypted)!="synthetic-only" {
    t.Fatalf("short KDF runtime behavior changed; panic=%v err=%v plaintext=%q",recovered,resultErr,decrypted)
   }
   return
  }
  if recovered==nil && resultErr==nil {t.Fatalf("malformed input unexpectedly decrypted: %s",tc.name)}
  t.Log(fmt.Sprintf("C_KDF_CASE_COMPLETED name=%s panic=%t error=%t",tc.name,recovered!=nil,resultErr!=nil))
 })}
}

 
// TestWorkerCImportMaliciousJSON tests the actual exported KeyStore.Import entry
// point using only synthetic local keyfiles. A panic through this boundary is
// NOT proof of remote RPC reachability, private-key theft, or mainnet harm.
func TestWorkerCImportMaliciousJSON(t *testing.T) {
 privateKey, err := crypto.GenerateKey()
 if err != nil {t.Fatal(err)}
 key := newKeyFromECDSA(privateKey)
 validJSON, err := EncryptKey(key,"fixture-password",16,1)
 if err != nil {t.Fatalf("synthetic encryption: %v",err)}
 ks := NewKeyStore(t.TempDir(),16,1)
 if _,err := ks.Import(validJSON,"fixture-password","new-fixture-password"); err != nil {
  t.Fatalf("valid JSON import: %v",err)
 }
 t.Log("C_IMPORT_VALID_JSON_PASS")

 var doc map[string]interface{}
 if err := json.Unmarshal(validJSON,&doc);err != nil {t.Fatal(err)}
 params,ok := doc["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{})
 if !ok {t.Fatal("unexpected keyfile KDF encoding")}
 delete(params,"salt")
 malformed,err:=json.Marshal(doc)
 if err != nil {t.Fatal(err)}
 var recovered interface{}
 var callErr error
 func(){
  defer func(){recovered=recover()}()
  _,callErr=ks.Import(malformed,"fixture-password","new-fixture-password")
 }()
 if recovered==nil {t.Fatalf("expected panic at KeyStore.Import; returned err=%v",callErr)}
 t.Logf("C_IMPORT_MALFORMED_JSON_PANIC_CONFIRMED type=%T detail=%v",recovered,recovered)

 var doc2 map[string]interface{}
 if err := json.Unmarshal(validJSON,&doc2); err != nil {t.Fatal(err)}
 doc2["crypto"].(map[string]interface{})["cipher"]="unsupported-cipher"
 rejected,err:=json.Marshal(doc2)
 if err != nil {t.Fatal(err)}
 var rejectedPanic interface{}
 var rejectedErr error
 func(){
  defer func(){rejectedPanic=recover()}()
  _,rejectedErr=ks.Import(rejected,"fixture-password","new-fixture-password")
 }()
 if rejectedPanic!=nil || rejectedErr==nil {t.Fatalf("expected controlled error for unsupported cipher; panic=%v err=%v",rejectedPanic,rejectedErr)}
 t.Logf("C_IMPORT_INVALID_CIPHER_RETURNED_ERROR err=%v",rejectedErr)
}
