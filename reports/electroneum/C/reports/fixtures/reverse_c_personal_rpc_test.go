// Reverse Worker R: C-001 RPC result/error and personal API controls.
// Copy only into certified scratch internal/ethapi.
package ethapi

import (
 "context"
 "errors"
 "math/big"
 "testing"

 "github.com/electroneum/electroneum-sc"
 "github.com/electroneum/electroneum-sc/accounts"
 "github.com/electroneum/electroneum-sc/core/types"
 "github.com/electroneum/electroneum-sc/event"
)

type reverseCWallet struct{ url accounts.URL }
func (w *reverseCWallet) URL() accounts.URL { return w.url }
func (w *reverseCWallet) Status()(string,error){return "synthetic",nil}
func (w *reverseCWallet) Open(string) error{return nil}
func (w *reverseCWallet) Close() error{return nil}
func (w *reverseCWallet) Accounts() []accounts.Account{return nil}
func (w *reverseCWallet) Contains(accounts.Account) bool{return false}
func (w *reverseCWallet) Derive(accounts.DerivationPath,bool)(accounts.Account,error){return accounts.Account{},errors.New("unsupported")}
func (w *reverseCWallet) SelfDerive([]accounts.DerivationPath,electroneum.ChainStateReader){}
func (w *reverseCWallet) SignData(accounts.Account,string,[]byte)([]byte,error){return nil,errors.New("unsupported")}
func (w *reverseCWallet) SignDataWithPassphrase(accounts.Account,string,string,[]byte)([]byte,error){return nil,errors.New("unsupported")}
func (w *reverseCWallet) SignText(accounts.Account,[]byte)([]byte,error){return nil,errors.New("unsupported")}
func (w *reverseCWallet) SignTextWithPassphrase(accounts.Account,string,[]byte)([]byte,error){return nil,errors.New("unsupported")}
func (w *reverseCWallet) SignTx(accounts.Account,*types.Transaction,*big.Int)(*types.Transaction,error){return nil,errors.New("unsupported")}
func (w *reverseCWallet) SignTxWithPassphrase(accounts.Account,string,*types.Transaction,*big.Int)(*types.Transaction,error){return nil,errors.New("unsupported")}

type reverseCWalletBackend struct{ wallets []accounts.Wallet }
func (b *reverseCWalletBackend) Wallets() []accounts.Wallet{return b.wallets}
func (b *reverseCWalletBackend) Subscribe(chan<- accounts.WalletEvent) event.Subscription {
 return event.NewSubscription(func(quit <-chan struct{}) error {<-quit;return nil})
}
type reverseCEthBackend struct{ Backend; am *accounts.Manager }
func (b *reverseCEthBackend) AccountManager()*accounts.Manager{return b.am}

func TestReverseCInitializeWalletDefenseMatrix(t *testing.T){
 u:=accounts.URL{Scheme:"reverse",Path:"unsupported"}
 w:=&reverseCWallet{url:u}
 wb:=&reverseCWalletBackend{wallets:[]accounts.Wallet{w}}
 am:=accounts.NewManager(&accounts.Config{},wb)
 defer am.Close()
 api:=NewPrivateAccountAPI(&reverseCEthBackend{am:am},new(AddrLocker))

 t.Run("unknown_wallet_returns_no_secret",func(t *testing.T){
  result,err:=api.InitializeWallet(context.Background(),"reverse://missing")
  if err==nil||result!="" {t.Fatalf("unknown wallet leaked/returned data result=%q err=%v",result,err)}
  t.Log("REVERSE_C_INIT_UNKNOWN_WALLET_EMPTY_RESULT_PASS")
 })
 t.Run("unsupported_wallet_returns_no_secret",func(t *testing.T){
  result,err:=api.InitializeWallet(context.Background(),u.String())
  if err==nil||result!="" {t.Fatalf("unsupported wallet leaked mnemonic result=%q err=%v",result,err)}
  t.Log("REVERSE_C_INIT_UNSUPPORTED_WALLET_EMPTY_RESULT_PASS")
 })
}

func TestReverseCPersonalAPIRegistrationIsPrivate(t *testing.T){
 // GetAPIs requires a backend account manager; reuse a minimal manager.
 am:=accounts.NewManager(&accounts.Config{})
 defer am.Close()
 b:=&reverseCEthBackend{am:am}
 apis:=GetAPIs(b)
 found:=false
 for _,api:=range apis {
  if api.Namespace=="personal" {
   found=true
   if api.Public {t.Fatal("personal API unexpectedly marked public")}
  }
 }
 if !found {t.Fatal("personal namespace missing from API inventory")}
 t.Log("REVERSE_C_PERSONAL_API_PUBLIC_FALSE_PASS")
}
