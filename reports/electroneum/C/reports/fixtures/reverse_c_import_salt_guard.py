#!/usr/bin/env python3
"""Scratch-only minimal negative-control guard for malformed keystore KDF salt.
Never edit immutable target, upstream or other workers' files.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: reverse_c_import_salt_guard.py /absolute/worker-r-scratch/accounts/keystore/passphrase.go")
target = Path(sys.argv[1]).resolve(strict=True)
if "worker-r-scratch" not in target.parts or target.parts[-3:] != ("accounts", "keystore", "passphrase.go"):
    raise SystemExit(f"Refusing patch outside R scratch: {target}")

source = target.read_text()
original = 'salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))'
guard = '''saltText, ok := cryptoJSON.KDFParams["salt"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid KDF salt")
	}
	salt, err := hex.DecodeString(saltText)'''
if source.count(original) != 1:
    raise SystemExit(f"Expected exactly one certified source anchor; found {source.count(original)}")
target.write_text(source.replace(original, guard, 1))
print("REVERSE_C_SCRATCH_KDF_SALT_GUARD_INJECTED", target)
