#!/usr/bin/env python3
"""Offline differential oracle for official Electroneum miner sync-progress fix.

1. REAL certified Go miner with an unverified downloader StartEvent:
   independently specified safe invariant is expected to FAIL with an exact
   invariant marker; compile failure or timeout is NOT counted as proof.
2. Apply the three-file *upstream semantics* to a disposable scratch tree,
   never to pinned source or public nodes.
3. Re-run secure no-pause invariant and positive verified-progress pause/resume
   controls three times. This establishes a component-level patch discriminator
   only; peer ingress, QBFT validator availability and P2/P3 remain unproven.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time


def edit_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise RuntimeError(f"patch anchor missing or ambiguous: {path.name}")
    path.chmod(path.stat().st_mode | 0o200)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def execute(scratch: Path, path: Path, regex: str, count: int) -> tuple[int, str]:
    command = ["go", "test", f"-count={count}", "-timeout=6m", "-run", regex, "-v", "./miner"]
    try:
        completed = subprocess.run(command, cwd=scratch, capture_output=True,
                                   text=True, timeout=450)
        content = completed.stdout + "\n" + completed.stderr
        exit_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        content = str(exc.stdout or "") + "\nTIMED_OUT"
        exit_code = 124
    path.write_text(content, encoding="utf-8")
    return exit_code, content


def verify(log: str, test: str, count: int) -> bool:
    return len(re.findall(r"(?m)^--- PASS: " + re.escape(test) + r"(?:\s|$)", log)) == count


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify_sync_patch.py <scratch-certified-go-source> <evidence-directory>")
        return 2
    scratch, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if not (scratch / "miner/miner.go").is_file():
        raise RuntimeError("missing certified scratch miner/miner.go")
    output.mkdir(parents=True, exist_ok=True)
    proof = {
        "hypothesis": "B-SYNC-PROGRESS-UPSTREAM-2026-11-05",
        "scope": "isolated in-process real miner and downloader event bus; no remote peer or QBFT finality proven",
        "upstream_fix": "electroneum/electroneum-sc@db0eb8792dd57304fbc66a60377c7663e1bd44d2",
        "certified_pre_fix_source": "3aeb14db0d6384243302f3a025bdff904dc28bf6",
        "finding_status": "E2 COMPONENT OBSERVATION ONLY",
    }
    try:
        original_path = output / "B-sync-prefixed-invariant.log"
        before_rc, before = execute(scratch, original_path,
                    r"^TestWorkerBUnverifiedSyncMustKeepMinerRunning$", 1)
        required = "B_UNVERIFIED_START_INVARIANT_BROKEN"
        if before_rc == 0 or required not in before or "build failed" in before.lower():
            raise RuntimeError("baseline did not fail specifically on expected secure invariant")
        proof["prefixed_secure_invariant"] = {
            "exit_code": before_rc,
            "expected_failure_marker": required,
            "log_sha256": hashlib.sha256(original_path.read_bytes()).hexdigest(),
            "classification": "certified component violates proposed no-pause invariant",
        }

        events = scratch / "eth/downloader/events.go"
        events.chmod(events.stat().st_mode | 0o200)
        events.write_text(events.read_text(encoding="utf-8") +
                          "\n// A sync proved it served a valid head. Scratch patch oracle only.\n"
                          "type ProgressEvent struct{}\n", encoding="utf-8")
        edit_once(scratch / "miner/miner.go",
                  "miner.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})",
                  "miner.mux.Subscribe(downloader.StartEvent{}, downloader.ProgressEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})")
        edit_once(scratch / "miner/miner.go",
                  "case downloader.StartEvent:\n\t\t\t\twasMining := miner.Mining()",
                  "case downloader.StartEvent:\n\t\t\t\t// Do not pause before verified head progress.\n\t\t\tcase downloader.ProgressEvent:\n\t\t\t\twasMining := miner.Mining()")
        edit_once(scratch / "eth/downloader/downloader.go",
                  "height := latest.Number.Uint64()",
                  "height := latest.Number.Uint64()\n\t// Verified peer head is now available; notify consensus clients.\n\td.mux.Post(ProgressEvent{})")

        controls = '''package miner
import (
 "testing"
 "time"
 "github.com/electroneum/electroneum-sc/common"
 "github.com/electroneum/electroneum-sc/eth/downloader"
)
func TestWorkerBVerifiedProgressStopsAndResumes(t *testing.T) {
 m,mux,cleanup:=createMiner(t)
 defer cleanup(false)
 m.Start(common.HexToAddress("0x12345"))
 waitForMiningState(t,m,true)
 mux.Post(downloader.StartEvent{})
 time.Sleep(100*time.Millisecond)
 if !m.Mining() {t.Fatal("patched miner prematurely stopped on unverified StartEvent")}
 mux.Post(downloader.ProgressEvent{})
 waitForMiningState(t,m,false)
 mux.Post(downloader.DoneEvent{})
 waitForMiningState(t,m,true)
 t.Log("B_VERIFIED_PROGRESS_CONTROLS_PASS")
}
'''
        patched_test = scratch / "miner/adversarial_worker_b_verified_progress_test.go"
        patched_test.parent.chmod(patched_test.parent.stat().st_mode | 0o200)
        patched_test.write_text(controls, encoding="utf-8")
        after_path = output / "B-sync-patched-controls.log"
        after_rc, after = execute(scratch, after_path,
            r"^TestWorkerB(UnverifiedSyncMustKeepMinerRunning|VerifiedProgressStopsAndResumes)$", 3)
        if after_rc != 0 or not all(verify(after, name, 3) for name in
            ["TestWorkerBUnverifiedSyncMustKeepMinerRunning", "TestWorkerBVerifiedProgressStopsAndResumes"]):
            raise RuntimeError("patched controls did not pass 3x on disposable target")
        if after.count("B_BARE_START_NO_PAUSE_PATCHED_PASS") < 3 or after.count("B_VERIFIED_PROGRESS_CONTROLS_PASS") < 3:
            raise RuntimeError("patched positive/negative control evidence is incomplete")
        proof["patched_semantic_controls"] = {
            "exit_code": after_rc,
            "repetitions": 3,
            "log_sha256": hashlib.sha256(after_path.read_bytes()).hexdigest(),
            "classification": "synthetic scratch oracle; published upstream fix, not a production exploit",
        }
        proof["status"] = "COMPONENT_PATCH_GAP_REPRODUCED_NOT_E4"
        print("B_UPSTREAM_SYNC_PROGRESS_DIFFERENTIAL_PASS baseline_invariant_fail=expected patched_controls=3x")
    except Exception as exc:
        proof["status"] = "FAILED"
        proof["error"] = str(exc)
        print(f"B_UPSTREAM_SYNC_PROGRESS_DIFFERENTIAL_ERROR: {exc}", file=sys.stderr)
    finally:
        (output / "B-sync-patch-differential.json").write_text(json.dumps(proof,indent=2)+"\n",encoding="utf-8")
    return 0 if proof["status"] == "COMPONENT_PATCH_GAP_REPRODUCED_NOT_E4" else 1

if __name__ == "__main__":
    raise SystemExit(main())
