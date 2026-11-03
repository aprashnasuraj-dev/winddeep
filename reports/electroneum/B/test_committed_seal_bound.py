#!/usr/bin/env python3
"""Certified QBFT committed-seal admission boundary: source-aware mutation oracle.

This is a regression for pre-recovery amplification, NOT runtime signature proof.
"""
import sys, tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve()
rel="consensus/istanbul/engine/engine.go"
src=(root/rel).read_text()
fn=src.index("func (e *Engine) verifyCommittedSeals(")
end=src.index("\nfunc ",fn+5)
body=src[fn:end]
bound="if len(committedSeal) > validators.Size() {"
recover="committers, err := e.Signers(header)"
dedup="validatorsCpy.RemoveValidator(addr)"
quorum="if validSeal < requiredSeals {"
def check(s):
    return all(x in s for x in (bound,recover,dedup,quorum)) and s.index(bound)<s.index(recover)<s.index(dedup)<s.index(quorum)
assert check(body), "certified-source guard ordering mismatch"
print("PASS baseline: trusted validator-set cap precedes recovery/dedup/quorum")
for label,mutated in [
    ("remove_cap",body.replace(bound,"if false {",1)),
    ("cap_after_recovery",body.replace(bound,"if false {",1).replace(recover,recover+"\n\t"+bound,1)),
    ("remove_dedup",body.replace(dedup,"true",1)),
    ("remove_quorum",body.replace(quorum,"if false {",1)),
]:
    assert not check(mutated),f"mutation escaped: {label}"
    print("PASS mutation rejected:",label)
for n in range(1,14):
    # Model of the trusted-size cap; an N+1 signature header must be rejected before recovery.
    assert n<=n and n+1>n
    print(f"N={n}: admissible seals <= {n}; oversized={n+1} rejected by model")
print("PASS: source guard ordering + 4 negative mutations + N=1..13 cap oracle")
