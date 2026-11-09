#!/usr/bin/env python3
"""Apply a minimal temporary producer gas-pool rollback for verification only."""
from pathlib import Path
import sys
if len(sys.argv)!=3: raise SystemExit("usage: apply_synthetic_fix.py upstream/miner/worker.go upstream/miner/adversarial_c_miner_gaspool_test.go")
worker,test=map(Path,sys.argv[1:])
src=worker.read_text()
a=src.index("func (w *worker) commitTransaction(")
b=src.index("func (w *worker) commitTransactions(",a)
body=src[a:b]
fixes=[
 ("snap := env.state.Snapshot()","snap := env.state.Snapshot()\n\tbeforeGas := *env.gasPool"),
 ("env.state.RevertToSnapshot(snap)\n\t\treturn nil, err","env.state.RevertToSnapshot(snap)\n\t\t*env.gasPool = beforeGas\n\t\treturn nil, err")
]
for old,new in fixes:
 if body.count(old)!=1:raise SystemExit("source mismatch: "+old)
 body=body.replace(old,new,1)
worker.write_text(src[:a]+body+src[b:])
s=test.read_text()
for old,new in [
 ("env.gasPool.Gas()!=40000-20999","env.gasPool.Gas()!=40000"),
 ("C_MINER_GASPOOL_EXPECTED_LEAK","C_MINER_GASPOOL_RESTORATION_FAILED"),
 ("!errors.Is(e,core.ErrGasLimitReached)","e!=nil"),
 ("C_FOLLOWUP_UNEXPECTED","C_VALID_FOLLOWUP_FAILED"),
 ("C_MINER_GASPOOL_LEAK","C_MINER_GASPOOL_FIX_PASS"),
 ("followup_rejected=true","followup_accepted=true")
]:
 if s.count(old)!=1:raise SystemExit("test mismatch: "+old)
 s=s.replace(old,new,1)
test.write_text(s)
print("C_FIX_PATCH_PREPARED source guard and regression assertions verified")
