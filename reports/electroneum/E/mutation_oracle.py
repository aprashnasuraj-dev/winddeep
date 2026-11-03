#!/usr/bin/env python3
"""Worker E negative oracle: change only a SCRATCH source copy and require Go tests to fail.
This is NOT a production patch. Does not modify the certified immutable WINDEEP_ETN_SOURCE.
"""
import pathlib, sys

root = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]
path = root / "core/rawdb/accessors_indexes.go"
text = path.read_text(encoding="utf-8")
original = 'blockHash := ReadCanonicalHash(db, *blockNumber)'
mutated = 'blockHash := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000ee")'
if mode == "inject":
    start = text.index('func ReadTransaction(')
    end = text.index('\n// ReadReceipt ', start)
    segment = text[start:end]
    if segment.count(original) != 1:
        raise SystemExit("MUTATION_FAILED: ReadTransaction canonical guard not uniquely located")
    path.write_text(text[:start]+segment.replace(original,mutated,1)+text[end:],encoding="utf-8")
    print("WORKER_E_MUTATION_INJECTED: canonical lookup deliberately corrupted in scratch")
elif mode == "restore":
    start = text.index('func ReadTransaction(')
    end = text.index('\n// ReadReceipt ', start)
    segment = text[start:end]
    if segment.count(mutated) != 1:
        raise SystemExit("RESTORE_FAILED: injected mutant not uniquely located")
    path.write_text(text[:start]+segment.replace(mutated,original,1)+text[end:],encoding="utf-8")
    print("WORKER_E_MUTATION_RESTORED")
else:
    raise SystemExit("usage: mutation_oracle.py SCRATCH_ROOT inject|restore")
