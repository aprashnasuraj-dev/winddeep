#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: canonical_guard_residual_patch.py /scratch/internal/ethapi/api.go")
target = Path(sys.argv[1]).resolve(strict=True)
if target.parts[-3:] != ("internal","ethapi","api.go") or "r-prod-depth-11-guard-residual" not in target.parts:
    raise SystemExit(f"refusing unexpected target: {target}")
source = target.read_text(encoding="utf-8")
anchor = "\treceipt := receipts[index]\n\n\t// Derive the sender."
if source.count(anchor) != 1:
    raise SystemExit(f"missing/non-unique anchor: {source.count(anchor)}")
guard = """\treceipt := receipts[index]

\t// Worker R scratch-only candidate guard. This is intentionally tested for
\t// residual TOCTOU and is NOT a proposed upstream fix.
\tcurrent, err := s.b.BlockByNumber(ctx, rpc.BlockNumber(blockNumber))
\tif err != nil {
\t\treturn nil, err
\t}
\tif current == nil || current.Hash() != blockHash {
\t\treturn nil, fmt.Errorf("canonical block changed during receipt query")
\t}

\t// Derive the sender."""
target.write_text(source.replace(anchor, guard, 1), encoding="utf-8")
print("R_CANONICAL_GUARD_SCRATCH_PATCH_APPLIED", target)
