#!/usr/bin/env python3
"""Certified-source QBFT seal admission-order regression; NOT runtime cryptographic proof."""
import pathlib, sys
root=pathlib.Path(sys.argv[1]).resolve()
body=(root/"consensus/istanbul/engine/engine.go").read_text()
start=body.index("func (e *Engine) verifyCommittedSeals(")
body=body[start:body.index("\nfunc ",start+5)]
checks={
 "decode_before_use": ("extra, err := types.ExtractQBFTExtra(header)","committedSeal := extra.CommittedSeal"),
 "reject_empty_before_recovery": ("if len(committedSeal) == 0 {","committers, err := e.Signers(header)"),
 "reject_oversized_before_recovery": ("if len(committedSeal) > validators.Size() {","committers, err := e.Signers(header)"),
 "copy_validator_set_before_dedup": ("validatorsCpy := validators.Copy()","validatorsCpy.RemoveValidator(addr)"),
 "dedup_before_quorum": ("validatorsCpy.RemoveValidator(addr)","if validSeal < requiredSeals {"),
}
def check(s):
 return all(a in s and b in s and s.index(a)<s.index(b) for a,b in checks.values())
assert check(body),"baseline source contract failed"
print("PASS baseline:",",".join(checks))
mutations={
 "empty_gate_removed":body.replace("if len(committedSeal) == 0 {","if false {",1),
 "oversized_gate_removed":body.replace("if len(committedSeal) > validators.Size() {","if false {",1),
 "dedup_removed":body.replace("validatorsCpy.RemoveValidator(addr)","true",1),
 "quorum_removed":body.replace("if validSeal < requiredSeals {","if false {",1),
}
# A simple order checker alone cannot catch a present-but-disabled gate.
def strict(s):
 return check(s) and all(k in s for k in ("if len(committedSeal) == 0 {","if len(committedSeal) > validators.Size() {","if validatorsCpy.RemoveValidator(addr) {","if validSeal < requiredSeals {"))
assert strict(body)
for label,mutant in mutations.items():
 assert not strict(mutant),f"undetected mutation: {label}"
 print("PASS mutation rejected:",label)
for n in range(1,14):
 quorum=(2*n+2)//3
 assert 1<=quorum<=n
 assert (n+1)>n
 print(f"N={n} threshold={quorum} empty=reject oversized={n+1}:reject (model only)")
print("PASS source-backed admission ordering, four mutations, N=1..13 model controls; NOT Go runtime validation")
