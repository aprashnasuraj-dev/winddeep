#!/usr/bin/env python3
"""Reverse-Audit R defensive control: patch ONLY disposable certified-source scratch.
Never use this script on vendor/electroneum-sc or upstream. The caller must
check the immutable source identity and copy it into a private scratch first.
"""
import pathlib
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: reverse_e_guard_patch.py /absolute/scratch/internal/ethapi/api.go")
target = pathlib.Path(sys.argv[1]).resolve(strict=True)
if "worker-r-scratch" not in target.parts or target.name != "api.go" or target.parent.name != "ethapi":
    raise SystemExit("Refusing non-R-scratch or wrong target path")
data = target.read_text()
before = """\t\theader, err := s.b.HeaderByHash(ctx, blockHash)
\t\tif err != nil {
\t\t\treturn nil, err
\t\t}
\t\tgasPrice := new(big.Int).Add(header.BaseFee, tx.EffectiveGasTipValue(header.BaseFee))"""
after = """\t\theader, err := s.b.HeaderByHash(ctx, blockHash)
\t\tif err != nil {
\t\t\treturn nil, err
\t\t}
\t\tif header == nil {
\t\t\treturn nil, fmt.Errorf("receipt header unavailable for %s", blockHash.Hex())
\t\t}
\t\tgasPrice := new(big.Int).Add(header.BaseFee, tx.EffectiveGasTipValue(header.BaseFee))"""
if data.count(before) != 1:
    raise SystemExit(f"Expected exactly one verified guard anchor, found {data.count(before)}")
target.write_text(data.replace(before, after, 1))
print("REVERSE_E_SCRATCH_GUARD_INJECTED", target)
