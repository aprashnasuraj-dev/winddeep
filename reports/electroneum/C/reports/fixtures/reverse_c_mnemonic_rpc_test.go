// Reverse Worker R, C-001: certify JSON-RPC confidentiality on callback error.
// This is a synthetic callback with the same (string,error) signature as
// PrivateAccountAPI.InitializeWallet; it does NOT simulate a real smartcard,
// authorize a remote client, or assert a live secret was disclosed.
package rpc

import (
 "context"
 "encoding/json"
 "errors"
 "reflect"
 "strings"
 "testing"
)

const reverseCSyntheticMnemonic = "synthetic-wallet-recovery-phrase-NEVER-A-REAL-KEY"

func reverseCMnemonicRPC(call func(context.Context)(string,error)) *jsonrpcMessage {
 h:=new(handler)
 request:=&jsonrpcMessage{Version:vsn,ID:json.RawMessage("17"),Method:"personal_initializeWallet"}
 cb:=&callback{fn:reflect.ValueOf(call),hasCtx:true,errPos:1}
 return h.runMethod(context.Background(),request,cb,nil)
}

func TestReverseCMnemonicRPCErrorAndRecovery(t *testing.T){
 t.Run("initialization_failure_never_serializes_mnemonic",func(t *testing.T){
  got:=reverseCMnemonicRPC(func(context.Context)(string,error){
   return reverseCSyntheticMnemonic,errors.New("synthetic smartcard initialization refused")
  })
  if got.Error==nil||got.Result!=nil {t.Fatalf("error path incorrectly exposed result: %+v",got)}
  b,err:=json.Marshal(got);if err!=nil{t.Fatal(err)}
  if strings.Contains(string(b),reverseCSyntheticMnemonic) {
   t.Fatal("REVERSE_C_RPC_ERROR_MNEMONIC_EXPOSURE: callback error returned secret")
  }
  t.Log("REVERSE_C_RPC_ERROR_RESULT_REDACTED_PASS")
 })
 t.Run("success_would_return_mnemonic_only_after_callback_success",func(t *testing.T){
  got:=reverseCMnemonicRPC(func(context.Context)(string,error){
   return reverseCSyntheticMnemonic,nil
  })
  if got.Error!=nil||string(got.Result)!="\""+reverseCSyntheticMnemonic+"\"" {
   t.Fatalf("successful callback output unexpectedly suppressed or incorrect: %+v",got)
  }
  t.Log("REVERSE_C_RPC_SUCCESS_CONDITIONED_ON_CALLBACK_PASS")
 })
 t.Run("panic_is_caught_and_does_not_return_mnemonic",func(t *testing.T){
  got:=reverseCMnemonicRPC(func(context.Context)(string,error){
   panic("synthetic smartcard failure")
  })
  if got.Error==nil||got.Result!=nil {t.Fatalf("panic callback produced secret result: %+v",got)}
  b,_:=json.Marshal(got)
  if strings.Contains(string(b),reverseCSyntheticMnemonic){t.Fatal("panic response leaked secret")}
  t.Log("REVERSE_C_RPC_PANIC_ERROR_NO_SECRET_PASS")
 })
}
