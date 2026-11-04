// Reverse Worker R: default external transports must not enable personal namespace.
// Copy only into certified scratch node package.
package node

import "testing"

func TestReverseCDefaultTransportExcludesPersonal(t *testing.T){
 for _,m:=range DefaultConfig.HTTPModules {if m=="personal"{t.Fatal("personal enabled over default HTTP")}}
 for _,m:=range DefaultConfig.WSModules {if m=="personal"{t.Fatal("personal enabled over default WS")}}
 t.Logf("REVERSE_C_DEFAULT_PERSONAL_EXCLUDED_PASS http=%v ws=%v",DefaultConfig.HTTPModules,DefaultConfig.WSModules)
}
