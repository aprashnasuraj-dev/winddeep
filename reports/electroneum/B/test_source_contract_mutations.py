#!/usr/bin/env python3
"""Worker B: deterministic mutation/negative controls for certified QBFT source contract."""
import importlib.util
import tempfile
from pathlib import Path
import sys

source_root=Path(sys.argv[1]).resolve()
spec=importlib.util.spec_from_file_location("qbft_round_contract",Path(__file__).resolve().parents[3]/"tools/qbft_round_contract.py")
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
baseline=mod.analyze(source_root)
assert all(baseline["checks"].values()), baseline
assert baseline["round_width_collision"]["encoded_a"]==baseline["round_width_collision"]["encoded_b"]
print("CERTIFIED_SOURCE_BASELINE_PASS",len(baseline["checks"]))
with tempfile.TemporaryDirectory() as td:
    scratch=Path(td)
    for key,rel in mod.FILES.items():
        dest=scratch/rel;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes((source_root/rel).read_bytes())
    # Mutation oracle: remove validator dedup, then independently weaken quorum.
    cases=[("dedup_removed","engine","validatorsCpy.RemoveValidator(addr)"),
           ("quorum_weakened","engine","math.Ceil(float64(2*validators.Size()) / 3)"),
           ("round_width_changed","commit","PrepareCommittedSeal(header, uint32(c.currentView().Round.Uint64()))")]
    for label,part,needle in cases:
        target=scratch/mod.FILES[part]
        original=target.read_text()
        assert original.count(needle)>=1,(label,"missing target")
        target.write_text(original.replace(needle,"/* MUTATION_ORACLE */",1))
        result=mod.analyze(scratch)
        assert not all(result["checks"].values()),(label,"mutation undetected")
        print("MUTATION_REJECTED",label,[k for k,v in result["checks"].items() if not v])
        target.write_text(original)
        assert all(mod.analyze(scratch)["checks"].values())
print("WORKER_B_MUTATION_CONTROLS_PASS")
