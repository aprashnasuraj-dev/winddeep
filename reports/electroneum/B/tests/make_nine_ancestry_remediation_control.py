#!/usr/bin/env python3
"""DISPOSABLE causal counterexample: move a premature ProgressEvent after
common-ancestor discovery, then change only the expected test assertions.

This intentionally modifies a temporary CI checkout of a pinned public
source tree. It must never be deployed to mainnet or represented as a tested
production fix. It is an experiment to isolate the cause of the finding.
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import sys

if len(sys.argv)!=3:
    sys.exit("usage: make_nine_ancestry_remediation_control.py <target/downloader.go> <target/nine_test.go>")

source=Path(sys.argv[1])
fixture=Path(sys.argv[2])
old_source=source.read_text()
old_test=fixture.read_text()
assert old_source.count("\td.mux.Post(ProgressEvent{})")==1
assert old_source.count("\td.syncStatsLock.Lock()")==1

# This is the exact trust-boundary correction under investigation: the
# untrusted remote head is insufficient until a common ancestor is found.
remove="\td.mux.Post(ProgressEvent{})\n\n\tvar origin uint64"
assert old_source.count(remove)==1
new_source=old_source.replace(remove,"\tvar origin uint64")
anchor="\t}\n\td.syncStatsLock.Lock()"
assert new_source.count(anchor)==1
new_source=new_source.replace(anchor,
    "\t}\n\t// Advance the miner gate only after a common ancestor was established.\n"
    "\td.mux.Post(ProgressEvent{})\n\td.syncStatsLock.Lock()")
assert new_source.count("\td.mux.Post(ProgressEvent{})")==1
assert new_source.index("\td.mux.Post(ProgressEvent{})") > new_source.index("origin, err = d.findAncestor")
source.write_text(new_source)

# The patched test deliberately expects that all nine miners remain active,
# even after the four actual ETH66 handshakes and ancestor stalls.
replacements=[
("if !isolatedWaitMiner(n.miner,false){return c,fmt.Errorf(\"actual QBFT miner still running\")}",
 "if isolatedWaitMiner(n.miner,false){return c,fmt.Errorf(\"patched QBFT miner unexpectedly stopped\")}"),
("QBFT_ETH66_WIRE_VALIDATOR_STOPPED address=%s real_eth66_handshake=true ancestor_verified=false miner_running=false canonical_height=%d",
 "PATCHED_ETH66_WIRE_VALIDATOR_ACTIVE address=%s real_eth66_handshake=true ancestor_verified=false miner_running=true canonical_height=%d"),
("FULL_MINERS_AUTO_ATTACK_TRIGGERED stopped=%d remaining=%d",
 "PATCHED_HEADONLY_WIRE_SESSIONS_VALIDATED count=%d remaining_miner_count_lower_bound=%d"),
("if delta!=0{t.Fatalf(\"FULL_MINERS_FOUR_PEER_OUTAGE_FALSIFIED paused=4 remaining=5 canonical_delta=%d\",delta)}",
 "if delta==0{t.Fatalf(\"PATCHED_CONTINUED_FINALITY_FAILED headonly_peers=4 canonical_delta=%d\",delta)}"),
("FULL_MINERS_FOUR_PEER_OUTAGE_30S signers=9 paused=4 remaining=5 canonical_delta=%d",
 "PATCHED_ETH66_FOUR_PEER_FINALITY_CONTINUES signers=9 untrusted_peers=4 canonical_delta=%d"),
("if n.miner.Mining(){t.Fatal(\"stopped validator miner resumed during observation\")}",
 "if !n.miner.Mining(){t.Fatal(\"patched validator miner stopped during unverified ancestor stall\")}"),
]
new_test=old_test
for before,after in replacements:
    assert new_test.count(before)==1, ("unexpected missing unique test assertion",before)
    new_test=new_test.replace(before,after)
assert "func TestIndependentNineFullMinersFourPeerLiveness" in new_test
fixture.write_text(new_test)

def sha(path:Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
result={
    "disposable_only":True,
    "boundary":"ProgressEvent emitted only after findAncestor (rather than fetchHead)",
    "source_sha256_before":hashlib.sha256(old_source.encode()).hexdigest(),
    "source_sha256_after":sha(source),
    "fixture_sha256_before":hashlib.sha256(old_test.encode()).hexdigest(),
    "fixture_sha256_after":sha(fixture),
    "assertion_changes":len(replacements),
    "test_target":"TestIndependentNineFullMinersFourPeerLiveness",
    "limitations":"Test-only change; successful result would prove causal mitigation in an isolated nine-validator simulation, not deployment readiness."
}
print("PATCHED_CAUSAL_CONTROL "+json.dumps(result,sort_keys=True))
