#!/usr/bin/env python3
"""Deterministic QBFT round-width and quorum source-contract checker (no AI API)."""
import argparse
import json
from pathlib import Path

FILES = {
    "engine": "consensus/istanbul/engine/engine.go",
    "core": "consensus/istanbul/core/core.go",
    "commit": "consensus/istanbul/core/commit.go",
    "roundchange": "consensus/istanbul/core/roundchange.go",
}

def analyze(root):
    source = {name: (root / path).read_text() for name, path in FILES.items()}
    patterns = {
        "header_round_u32": ("engine", "qbftExtra.Round = uint32(round.Uint64())"),
        "commit_round_u32": ("commit", "PrepareCommittedSeal(header, uint32(c.currentView().Round.Uint64()))"),
        "roundchange_round_u64": ("roundchange", "round := r.Uint64()"),
        "roundchange_gap_guard": ("roundchange", "MaxFutureRoundGap"),
        "header_seal_dedup": ("engine", "validatorsCpy.RemoveValidator(addr)"),
        "header_quorum": ("engine", "math.Ceil(float64(2*validators.Size()) / 3)"),
        "core_quorum": ("core", "math.Ceil(float64(2*c.valSet.Size()) / 3)"),
    }
    checks = {key: needle in source[part] for key, (part, needle) in patterns.items()}
    return {"checks": checks, "round_width_collision": {"a": 0, "b": 2**32, "encoded_a": 0, "encoded_b": (2**32) & 0xffffffff}, "status": "HYPOTHESIS: reachability not demonstrated"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("source_root", type=Path)
    args = p.parse_args()
    result = analyze(args.source_root)
    print(json.dumps(result, indent=2))
    return 0 if all(result["checks"].values()) else 1

if __name__ == "__main__":
    raise SystemExit(main())
