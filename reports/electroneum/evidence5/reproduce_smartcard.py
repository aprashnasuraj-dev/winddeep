#!/usr/bin/env python3
import sys,threading
from pathlib import Path
def fn(source,signature):
 pos=source.find(signature)
 if pos<0:raise AssertionError("missing function "+signature)
 start=source.find("{",pos);d=0
 for i in range(start,len(source)):
  if source[i]=="{":d+=1
  elif source[i]=="}":
   d-=1
   if d==0:return source[pos:i+1]
 raise AssertionError("unclosed function "+signature)
def run(root):
 wallet=(root/"accounts/scwallet/wallet.go").read_text()
 api=(root/"internal/ethapi/api.go").read_text()
 channel=(root/"accounts/scwallet/securechannel.go").read_text()
 init=fn(wallet,"func (s *Session) initialize(seed []byte) error")
 order=[init.index("s.Wallet.Status()"),init.index('if status == "Online"'),init.index("s.Wallet.lock.Lock()"),init.index("s.Channel.transmitEncrypted(")]
 assert order==sorted(order),order
 assert "insLoadKey" in init
 print("SMARTCARD_SOURCE_STATUS_BEFORE_LOCK_AND_LOADKEY_PASS",order)
 status=fn(wallet,"func (w *Wallet) Status() (string, error)")
 assert all(x in status for x in ['"Locked, waiting for PIN','"Blocked, waiting for PUK','"Empty, waiting for initialization','"Online"'])
 print("SMARTCARD_STATUS_LOCKED_BLOCKED_EMPTY_ONLINE_PATHS_CONFIRMED")
 rpc=fn(api,"func (s *PrivateAccountAPI) InitializeWallet(ctx context.Context, url string) (string, error)")
 assert "return mnemonic, wallet.Initialize(seed)" in rpc
 print("SMARTCARD_PRIVATE_RPC_RETURNS_GENERATED_MNEMONIC_IF_INITIALIZE_ACCEPTS")
 secure=fn(channel,"func (s *SecureChannelSession) transmitEncrypted(")
 assert "if s.iv == nil" in secure
 assert "response.Data[:len(s.iv)]" in secure
 print("SMARTCARD_CLOSED_CHANNEL_GUARD_AND_SHORT_RESPONSE_SLICE_CONFIRMED")
 barrier=threading.Barrier(2);gate=threading.Lock();attempts=[]
 def call(which):
  status_snapshot="Empty, waiting for initialization"
  barrier.wait(timeout=5)
  if status_snapshot=="Online":return
  with gate:attempts.append(which)
 threads=[threading.Thread(target=call,args=(i,),daemon=True) for i in range(2)]
 for th in threads:th.start()
 for th in threads:th.join(timeout=6)
 assert sorted(attempts)==[0,1]
 print("SMARTCARD_TWO_PRECHECKS_CAN_REACH_LOAD_ATTEMPT_IN_MODEL attempts=2")
 accepted=[]
 for a in attempts:
  if not accepted:accepted.append(a)
 assert len(accepted)==1
 print("SMARTCARD_FIRMWARE_ONE_TIME_INIT_CONTROL_BLOCKS_SECOND_LOAD model_only=true")
 print("SMARTCARD_SCOPE: actual card behavior and remote RPC authorization not exercised")
if __name__=="__main__":
 if len(sys.argv)!=2:raise SystemExit("usage: python3 reproduce_smartcard.py /path/to/electroneum-sc")
 run(Path(sys.argv[1]))