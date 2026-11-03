package keystore

import (
 "fmt"
 "testing"
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
  func(){defer func(){recovered=recover()}(); _,resultErr=DecryptDataV3(c,"fixture-password")}()
  if recovered!=nil {t.Logf("C_KDF_OBSERVED_PANIC case=%s type=%T detail=%v",tc.name,recovered,recovered)}
  if resultErr!=nil {t.Logf("C_KDF_OBSERVED_ERROR case=%s err=%v",tc.name,resultErr)}
  if recovered==nil && resultErr==nil {t.Fatalf("malformed input unexpectedly decrypted: %s",tc.name)}
  t.Log(fmt.Sprintf("C_KDF_CASE_COMPLETED name=%s panic=%t error=%t",tc.name,recovered!=nil,resultErr!=nil))
 })}
}
