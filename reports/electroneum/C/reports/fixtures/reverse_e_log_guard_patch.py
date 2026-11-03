#!/usr/bin/env python3
"""Scratch-only reverse Worker R guard sensitivity for E-RPC-008."""
from pathlib import Path
import sys

if len(sys.argv)!=2:
    raise SystemExit("usage: reverse_e_log_guard_patch.py /absolute/worker-r-scratch/eth/filters/filter.go")
target=Path(sys.argv[1]).resolve(strict=True)
if "worker-r-scratch" not in target.parts or target.parts[-3:] != ("eth","filters","filter.go"):
    raise SystemExit("Refusing to edit anything outside reverse-R scratch eth/filters/filter.go")
data=target.read_text()
before="""\t\theader, err := f.backend.HeaderByNumber(ctx, rpc.BlockNumber(f.begin))
\t\tif header == nil || err != nil {
\t\t\treturn logs, err
\t\t}"""
after="""\t\theader, err := f.backend.HeaderByNumber(ctx, rpc.BlockNumber(f.begin))
\t\tif err != nil {
\t\t\treturn logs, err
\t\t}
\t\tif header == nil {
\t\t\treturn logs, fmt.Errorf("missing block header %d while scanning logs", f.begin)
\t\t}"""
if data.count(before)!=1:
    raise SystemExit(f"R guard anchor not unique: {data.count(before)}")
target.write_text(data.replace(before,after,1))
print("REVERSE_E_LOG_SCRATCH_GUARD_INJECTED",target)
