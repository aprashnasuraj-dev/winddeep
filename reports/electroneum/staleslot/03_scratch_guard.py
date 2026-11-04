#!/usr/bin/env python3
"""Scratch-only sensitivity guard for nil/stale downloader delivery slots.

Purpose: demonstrate that the exact panic is due to accepting (nil,nil,stale)
from GetDeliverySlot, not claim a production fix or proven production exploit.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: python3 03_scratch_guard.py /path/to/scratch/eth/downloader/queue.go")

path = Path(sys.argv[1]).resolve()
if path.name != "queue.go" or "scratch" not in str(path):
    raise SystemExit("refusing to change any file outside a scratch queue.go")
text = path.read_text(encoding="utf-8")
old_cond = "if res, stale, err := q.resultCache.GetDeliverySlot(header.Number.Uint64()); err == nil {"
new_cond = "if res, stale, err := q.resultCache.GetDeliverySlot(header.Number.Uint64()); err == nil && !stale && res != nil {"
old_end = "\t\t\tfailure = errStaleDelivery\n\t\t}\n\t\t// Clean up a successful fetch"
new_end = "\t\t\tfailure = errStaleDelivery\n\t\t\tbreak\n\t\t}\n\t\t// Clean up a successful fetch"
if text.count(old_cond) != 1 or text.count(old_end) != 1:
    raise SystemExit("source mismatch; refusing patch")
text = text.replace(old_cond, new_cond, 1).replace(old_end, new_end, 1)
path.write_text(text, encoding="utf-8")
print("STALE_SLOT_SCRATCH_FAIL_CLOSED_GUARD_APPLIED")
