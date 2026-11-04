// Reverse Worker R: RPC must suppress successful-looking result when callback returns error.
// Copy only into certified scratch rpc package.
package rpc

import (
 "context"
 "errors"
 "reflect"
 "testing"
)

type reverseSecretService struct{}
func (*reverseSecretService) SecretOnError()(string,error){return "mnemonic-like-sensitive-result",errors.New("synthetic initialize failure")}
func (*reverseSecretService) SecretOnSuccess()(string,error){return "mnemonic-like-sensitive-result",nil}

func TestReverseCRPCErrorSuppressesSensitiveResult(t *testing.T){
 svc:=reflect.ValueOf(&reverseSecretService{})
 cbs:=suitableCallbacks(svc)
 errcb:=cbs["secretOnError"]
 if errcb==nil {t.Fatal("error callback missing")}
 res,err:=errcb.call(context.Background(),"reverse_secretOnError",nil)
 if err==nil {t.Fatal("expected callback error")}
 if res!=nil {
  // reflect.Value{} is returned internally as interface; ensure nothing usable leaks.
  if rv,ok:=res.(reflect.Value); !ok || rv.IsValid() {t.Fatalf("sensitive result survived error: %#v",res)}
 }
 t.Log("REVERSE_C_RPC_ERROR_RESULT_SUPPRESSED_PASS")

 okcb:=cbs["secretOnSuccess"]
 res,err=okcb.call(context.Background(),"reverse_secretOnSuccess",nil)
 if err!=nil||res!="mnemonic-like-sensitive-result" {t.Fatalf("success control failed res=%#v err=%v",res,err)}
 t.Log("REVERSE_C_RPC_SUCCESS_RESULT_CONTROL_PASS")
}
