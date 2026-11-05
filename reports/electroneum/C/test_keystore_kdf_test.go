package keystore

import (
 "encoding/json"
 "crypto/sha256"
 "encoding/hex"
 "github.com/electroneum/electroneum-sc/common/math"
 "golang.org/x/crypto/pbkdf2"
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
 // Additional independently specified malformed KDF fields must never import
 // a usable account. Characterize panic separately from controlled rejection.
 for _, tc := range []struct {
  name string
  mutate func(map[string]interface{})
 }{
  {"numeric_salt",func(p map[string]interface{}){p["salt"]=42}},
  {"string_dklen",func(p map[string]interface{}){p["dklen"]="32"}},
  {"invalid_scrypt_n",func(p map[string]interface{}){p["n"]=3}},
  {"missing_pbkdf2_prf",func(p map[string]interface{}){p["c"]=1;delete(p,"prf")}},
  {"numeric_pbkdf2_prf",func(p map[string]interface{}){p["c"]=1;p["prf"]=123}},
  {"unsupported_pbkdf2_prf",func(p map[string]interface{}){p["c"]=1;p["prf"]="hmac-sha1"}},
  {"fractional_pbkdf2_c",func(p map[string]interface{}){p["c"]=1.5;p["prf"]="hmac-sha256"}},
  {"negative_pbkdf2_c",func(p map[string]interface{}){p["c"]=-1;p["prf"]="hmac-sha256"}},
  {"string_pbkdf2_c",func(p map[string]interface{}){p["c"]="2";p["prf"]="hmac-sha256"}},
  {"fractional_pbkdf2_dklen",func(p map[string]interface{}){p["c"]=1;p["dklen"]=32.5;p["prf"]="hmac-sha256"}},
  {"negative_pbkdf2_dklen",func(p map[string]interface{}){p["c"]=1;p["dklen"]=-1;p["prf"]="hmac-sha256"}},
 } {
  t.Run(tc.name,func(t *testing.T){
   var candidate map[string]interface{}
   if err:=json.Unmarshal(validJSON,&candidate);err!=nil {t.Fatal(err)}
   cryptoDoc,ok:=candidate["crypto"].(map[string]interface{})
   if !ok {t.Fatal("missing crypto object")}
   kdfParams,ok:=cryptoDoc["kdfparams"].(map[string]interface{})
   if !ok {t.Fatal("missing KDF parameters")}
   tc.mutate(kdfParams)
   if tc.name=="missing_pbkdf2_prf" || tc.name=="numeric_pbkdf2_prf" || tc.name=="unsupported_pbkdf2_prf" || tc.name=="fractional_pbkdf2_c" || tc.name=="negative_pbkdf2_c" || tc.name=="string_pbkdf2_c" || tc.name=="fractional_pbkdf2_dklen" || tc.name=="negative_pbkdf2_dklen" {cryptoDoc["kdf"]="pbkdf2"}
   payload,err:=json.Marshal(candidate)
   if err!=nil {t.Fatal(err)}
   var panicValue interface{}
   var importErr error
   var imported bool
   func(){
    defer func(){panicValue=recover()}()
    account,e:=ks.Import(payload,"fixture-password","new-fixture-password")
    importErr=e
    imported=e==nil
    _=account
   }()
   // Independent safety oracle: malformed key metadata must not create a
   // successfully imported account. A panic is separately logged and is NOT
   // considered a safe rejection or proof of remotely reachable impact.
   if imported {t.Fatalf("C_IMPORT_ORACLE_VIOLATION: malformed %s imported",tc.name)}
   if panicValue!=nil {
    t.Logf("C_IMPORT_PANIC case=%s type=%T detail=%v",tc.name,panicValue,panicValue)
   } else if importErr!=nil {
    t.Logf("C_IMPORT_REJECTED case=%s err=%v",tc.name,importErr)
   } else {
    t.Fatalf("C_IMPORT_NO_OUTCOME case=%s",tc.name)
   }
  })
 }
}


// TestWorkerCPBKDF2AuthenticImport constructs a genuinely PBKDF2-encrypted
// synthetic keyfile. Unlike the older characterization, this fixture never
// relabels scrypt ciphertext as PBKDF2. Panic observations are not remote impact.
func TestWorkerCPBKDF2AuthenticImport(t *testing.T) {
 privateKey, err := crypto.GenerateKey()
 if err != nil { t.Fatal(err) }
 key := newKeyFromECDSA(privateKey)
 original, err := EncryptKey(key, "synthetic-pbkdf2-password", 16, 1)
 if err != nil { t.Fatal(err) }
 var doc map[string]interface{}
 if err := json.Unmarshal(original, &doc); err != nil { t.Fatal(err) }
 cryptoDoc := doc["crypto"].(map[string]interface{})
 salt := []byte("worker-c-pbkdf2-synthetic-salt-32")
 iv, err := hex.DecodeString(cryptoDoc["cipherparams"].(map[string]interface{})["iv"].(string))
 if err != nil { t.Fatal(err) }
 plaintext := math.PaddedBigBytes(privateKey.D, 32)
 derived := pbkdf2.Key([]byte("synthetic-pbkdf2-password"), salt, 16, 32, sha256.New)
 ciphertext, err := aesCTRXOR(derived[:16], plaintext, iv)
 if err != nil { t.Fatal(err) }
 cryptoDoc["ciphertext"] = hex.EncodeToString(ciphertext)
 cryptoDoc["mac"] = hex.EncodeToString(crypto.Keccak256(derived[16:32], ciphertext))
 cryptoDoc["kdf"] = "pbkdf2"
 cryptoDoc["kdfparams"] = map[string]interface{}{
  "salt": hex.EncodeToString(salt), "c": 16, "dklen": 32, "prf": "hmac-sha256",
 }
 valid, err := json.Marshal(doc)
 if err != nil { t.Fatal(err) }
 honestStore := NewKeyStore(t.TempDir(), 16, 1)
 imported, err := honestStore.Import(valid, "synthetic-pbkdf2-password", "synthetic-new-password")
 if err != nil { t.Fatalf("genuine PBKDF2 honest import failed: %v", err) }
 if imported.Address != key.Address { t.Fatal("genuine PBKDF2 imported wrong address") }
 t.Log("C_PBKDF2_AUTHENTIC_IMPORT_CONTROL_PASS")
 for _, tc := range []struct {
  name string
  mutate func(map[string]interface{})
 }{
  {"wrong_password", func(p map[string]interface{}){}},
  {"fractional_c", func(p map[string]interface{}){p["c"]=16.5}},
  {"negative_c", func(p map[string]interface{}){p["c"]=-1}},
  {"string_c", func(p map[string]interface{}){p["c"]="16"}},
  {"fractional_dklen", func(p map[string]interface{}){p["dklen"]=32.5}},
  {"negative_dklen", func(p map[string]interface{}){p["dklen"]=-1}},
  {"missing_prf", func(p map[string]interface{}){delete(p,"prf")}},
  {"numeric_prf", func(p map[string]interface{}){p["prf"]=7}},
 } {
  t.Run(tc.name, func(t *testing.T) {
   var candidate map[string]interface{}
   if err:=json.Unmarshal(valid,&candidate);err!=nil {t.Fatal(err)}
   p:=candidate["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{})
   tc.mutate(p)
   payload,err:=json.Marshal(candidate)
   if err!=nil {t.Fatal(err)}
   password:="synthetic-pbkdf2-password"
   if tc.name=="wrong_password" {password="synthetic-wrong-password"}
   store:=NewKeyStore(t.TempDir(),16,1)
   var panicValue interface{}
   var importErr error
   var succeeded bool
   func(){
    defer func(){panicValue=recover()}()
    _,importErr=store.Import(payload,password,"synthetic-new-password")
    succeeded=importErr==nil
   }()
   if succeeded {t.Fatalf("C_PBKDF2_UNEXPECTED_IMPORT name=%s",tc.name)}
   if panicValue!=nil {
    t.Logf("C_PBKDF2_SAFETY_ORACLE_PANIC_DETECTED name=%s type=%T",tc.name,panicValue)
   } else if importErr!=nil {
    t.Logf("C_PBKDF2_CONTROLLED_REJECTION name=%s err=%v",tc.name,importErr)
   } else {t.Fatalf("C_PBKDF2_NO_OUTCOME name=%s",tc.name)}
  })
 }
}
