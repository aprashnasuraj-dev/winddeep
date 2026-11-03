#!/usr/bin/env python3
"""Certified Worker D source-contract guard oracle; no target-source modifications.
Tests presence/relative placement of root validations and detects three weakened mutations.
This is source-contract evidence, not a target-runtime import bypass proof.
"""
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
source = (root / "core/block_validator.go").read_text(encoding="utf-8")

def method(name, text):
    start = text.index("func (v *BlockValidator) " + name + "(")
    end = text.find("\nfunc ", start + 1)
    return text[start:] if end == -1 else text[start:end]

def check(text):
    body = method("ValidateBody", text)
    state = method("ValidateState", text)
    requirements = {
        "transaction_root_computed": "types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil))" in body,
        "transaction_root_checked": "hash != header.TxHash" in body,
        "receipt_root_computed": "types.DeriveSha(receipts, trie.NewStackTrie(nil))" in state,
        "receipt_root_checked": "receiptSha != header.ReceiptHash" in state,
        "state_root_computed": "statedb.IntermediateRoot(" in state,
        "state_root_checked": "header.Root != root" in state,
        "gas_used_checked": "block.GasUsed() != usedGas" in state,
        "bloom_checked": "rbloom != header.Bloom" in state,
    }
    return requirements

baseline = check(source)
if not all(baseline.values()):
    raise SystemExit("CERTIFIED_D_BASELINE_FAILED " + str(baseline))
print("WORKER_D_SOURCE_CONTRACT_PASS", len(baseline))
mutations = {
    "transaction_root_guard_removed": ("hash != header.TxHash", "false"),
    "receipt_root_guard_removed": ("receiptSha != header.ReceiptHash", "false"),
    "state_root_guard_removed": ("header.Root != root", "false"),
    "bloom_guard_removed": ("rbloom != header.Bloom", "false"),
}
for name, (needle, replacement) in mutations.items():
    if source.count(needle) != 1:
        raise SystemExit("MUTATION_ANCHOR_AMBIGUOUS " + name)
    changed = source.replace(needle, replacement, 1)
    if all(check(changed).values()):
        raise SystemExit("MUTATION_UNDETECTED " + name)
    print("WORKER_D_MUTATION_REJECTED", name)
print("WORKER_D_SOURCE_ORACLE_PASS")
