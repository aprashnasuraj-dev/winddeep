#!/usr/bin/env python3
"""Reverse-R scratch-only post-read canonicality check sensitivity oracle.
DO NOT run against certified source, upstream, or another worker's checkout.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: reverse_e_canonical_guard_patch.py /.../worker-r-scratch/internal/ethapi/api.go")
target=Path(sys.argv[1]).resolve(strict=True)
if "worker-r-scratch" not in target.parts or target.parts[-3:] != ("internal","ethapi","api.go"):
    raise SystemExit("refusing to modify anything outside R's disposable internal/ethapi/api.go")
source=target.read_text(encoding="utf-8")
anchor="\treceipt := receipts[index]\n\n\t// Derive the sender."
if source.count(anchor) != 1:
    raise SystemExit(f"missing/non-unique canonical check anchor: {source.count(anchor)}")
guard="""\treceipt := receipts[index]

\t// Reverse Worker R scratch-only defensive mutation, NOT upstream fix.
\t// If a reorganization occurs during the two indexed lookups, do not
\t// return a receipt from an orphan block as a confirmed canonical result.
\tcurrent, err := s.b.BlockByNumber(ctx, rpc.BlockNumber(blockNumber))
\tif err != nil {
\t\treturn nil, err
\t}
\tif current == nil || current.Hash() != blockHash {
\t\treturn nil, fmt.Errorf("canonical block changed during receipt query")
\t}

\t// Derive the sender."""
target.write_text(source.replace(anchor,guard,1),encoding="utf-8")
print("REVERSE_E_CANONICAL_SCRATCH_GUARD_INJECTED", target)
