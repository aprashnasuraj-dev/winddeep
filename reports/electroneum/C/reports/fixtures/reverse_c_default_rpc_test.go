// Reverse R: shipped default external transport module exposure counterexample.
// Only checks certified node.DefaultConfig; it is NOT a proof custom RPC
// deployments are safe and uses no hardware devices or remote endpoints.
package node

import "testing"

func reverseCHasModule(all []string, want string) bool {
 for _,name:=range all {if name==want{return true}}
 return false
}

func TestReverseCDefaultPrivateWalletRPCExposure(t *testing.T){
 cfg:=DefaultConfig
 if !reverseCHasModule(cfg.HTTPModules,"net")||!reverseCHasModule(cfg.HTTPModules,"web3") {
  t.Fatal("HTTP positive public-module controls missing")
 }
 if !reverseCHasModule(cfg.WSModules,"net")||!reverseCHasModule(cfg.WSModules,"web3") {
  t.Fatal("WS positive public-module controls missing")
 }
 for _,private:=range []string{"personal","debug","admin"}{
  if reverseCHasModule(cfg.HTTPModules,private)||reverseCHasModule(cfg.WSModules,private) {
   t.Fatalf("private namespace %q enabled by default externally",private)
  }
 }
 // Config's default transport host is empty: HTTP/WS listeners require explicit
 // enabling; verify exact shipped defaults, not a manually configured node.
 if cfg.HTTPHost!=""||cfg.WSHost!=""{
  t.Fatalf("default external RPC listeners unexpectedly active HTTP=%q WS=%q",cfg.HTTPHost,cfg.WSHost)
 }
 t.Log("REVERSE_C_DEFAULT_HTTP_WS_PRIVATE_NAMESPACE_EXCLUDED_PASS")
 t.Log("REVERSE_C_DEFAULT_RPC_NETWORK_LISTENERS_DISABLED_PASS")
}
