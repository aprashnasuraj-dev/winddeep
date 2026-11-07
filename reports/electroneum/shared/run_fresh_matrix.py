#!/usr/bin/env python3
"""Three fresh-process, independently logged certified Go regression attempts.

Passing these regressions does not establish an E3 breach or an E4 vulnerability.
All native tests run against disposable source trees, never live networks.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

COMMIT="7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
TREE="de7f3c75a2db7e87a89918f1257820703d5b731e"
PASS="PASSED_INDEPENDENT_REGRESSIONS_NOT_FINDINGS"

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1048576),b""): h.update(block)
    return h.hexdigest()

def safe(root,relative):
    if not isinstance(relative,str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("unsafe relative evidence path")
    p=(root/relative).resolve()
    if not p.is_relative_to(root.resolve()): raise ValueError("evidence escapes run directory")
    return p

def verify(result,folder,owner):
    if result.get("class")!=owner or result.get("status")!="PASSED_REGRESSIONS_NOT_FINDINGS":
        raise ValueError("class or matrix status invalid")
    if result.get("certified_source_commit")!=COMMIT or result.get("certified_source_tree")!=TREE:
        raise ValueError("certified identity mismatch")
    if os.getenv("GITHUB_RUN_ID") and result.get("github_run_id")!=os.getenv("GITHUB_RUN_ID"):
        raise ValueError("mismatched GitHub run identity")
    probes=result.get("probes")
    if not isinstance(probes,list) or not probes: raise ValueError("no executed Go probes")
    identities={}
    for item in probes:
        pid=item.get("id")
        if not isinstance(pid,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",pid) or pid in identities:
            raise ValueError("unsafe or duplicate probe identity")
        if item.get("owner")!=owner or item.get("outcome")!="PASS_REGRESSION_ONLY":
            raise ValueError(f"{pid}: nonpassing native regression")
        if (item.get("exit_code")!=0 or item.get("expected_repetitions")!=1
            or item.get("successful_top_level_repetitions")!=1):
            raise ValueError(f"{pid}: not exactly one successful native execution")
        fixture=item.get("fixture_sha256")
        if not isinstance(fixture,str) or not re.fullmatch(r"[a-f0-9]{64}",fixture):
            raise ValueError(f"{pid}: invalid fixture hash")
        test=item.get("test")
        if not isinstance(test,str) or not re.fullmatch(r"Test[A-Za-z0-9_]+",test):
            raise ValueError(f"{pid}: invalid Go test identity")
        log=safe(folder,item.get("log"))
        if not log.is_file() or sha(log)!=item.get("log_sha256"):
            raise ValueError(f"{pid}: missing or tampered native log")
        content=log.read_text(encoding="utf8",errors="replace")
        if len(re.findall(r"(?m)^--- PASS: "+re.escape(test)+r"(?:\s|$)",content))!=1:
            raise ValueError(f"{pid}: missing actual Go PASS line")
        markers=item.get("positive_negative_controls_seen")
        if not isinstance(markers,dict) or not markers:
            raise ValueError(f"{pid}: no evidence markers")
        for marker,count in markers.items():
            if not isinstance(marker,str) or not marker or type(count)!=int or count<1:
                raise ValueError(f"{pid}: missing required control")
            if content.count(marker)!=count:
                raise ValueError(f"{pid}: marker count contradicts log")
        identities[pid]={k:item.get(k) for k in ("owner","test","package","source_fixture","fixture_sha256","classification")}
    return identities

def spawn(command,root,timeout):
    p=subprocess.Popen(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                       text=True,start_new_session=True)
    try:
        out,_=p.communicate(timeout=timeout)
        return p.returncode,out,p.pid
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL)
        out,_=p.communicate()
        return 124,out+"\nFRESH_ATTEMPT_TIMEOUT\n",p.pid

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--class",dest="owner",required=True,choices=list("ABCDE"))
    p.add_argument("--matrix",default="reports/electroneum/shared/adversarial_matrix.json")
    p.add_argument("--runner",default="reports/electroneum/shared/run_adversarial_matrix.py")
    p.add_argument("--output",required=True)
    p.add_argument("--fresh-count",type=int,default=3)
    p.add_argument("--timeout-sec",type=int,default=1200)
    a=p.parse_args()
    if a.fresh_count!=3 or not 30<=a.timeout_sec<=1200:
        p.error("requires three fresh processes with a 30..1200-second timeout")
    root=Path.cwd().resolve()
    output=Path(a.output).resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        p.error("refusing to reuse nonempty evidence directory")
    output.mkdir(parents=True,exist_ok=True)
    report={"schema":2,"class":a.owner,"timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
            "trigger_sha":os.getenv("GITHUB_SHA"),"github_run_id":os.getenv("GITHUB_RUN_ID"),
            "certificate_commit":COMMIT,"certificate_tree":TREE,
            "scope":"three independent Python/Go processes and new certified scratch copies",
            "limits":"no independent blockchain state, production reachability, E3 or E4 claim from regression pass",
            "status":"FAILED_OR_INCOMPLETE","attempts":[],"probe_ids":[]}
    baseline=None
    try:
        native=safe(root,a.runner)
        if not native.is_file(): raise ValueError("missing native certified Go runner")
        for name,expected in (("WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT",COMMIT),
                              ("WINDEEP_ETN_SOURCE_TREE_SHA",TREE)):
            if os.getenv(name)!=expected: raise ValueError("missing or wrong source environment: "+name)
        if os.getenv("GITHUB_SHA"):
            actual=subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()
            if actual!=os.getenv("GITHUB_SHA"): raise ValueError("checkout SHA differs from triggering SHA")
        for n in (1,2,3):
            folder=output/f"fresh-{n}"
            folder.mkdir()
            cmd=[sys.executable,str(native),"--class",a.owner,"--matrix",a.matrix,
                 "--repeat","1","--output",str(folder)]
            t0=time.monotonic()
            rc,stdout,pid=spawn(cmd,root,a.timeout_sec)
            logfile=folder/"runner.log"
            logfile.write_text(stdout,encoding="utf8")
            entry={"attempt":n,"process_id":pid,"exit_code":rc,
                   "duration_seconds":round(time.monotonic()-t0,2),
                   "runner_log":f"fresh-{n}/runner.log","runner_log_sha256":sha(logfile)}
            report["attempts"].append(entry)
            data=folder/"result.json"
            if rc!=0 or not data.is_file():
                raise RuntimeError(f"attempt {n} failed exit={rc}; inspect fresh-{n}/runner.log")
            entry["result"]=f"fresh-{n}/result.json"
            entry["result_sha256"]=sha(data)
            current=verify(json.loads(data.read_text(encoding="utf8")),folder,a.owner)
            if baseline is not None and current!=baseline:
                raise RuntimeError("fixture hashes or exact Go probe identities drifted")
            baseline=current
            print(f"FRESH_MATRIX_ATTEMPT {n}/3 class={a.owner} probes={len(current)} PASS_REGRESSION_ONLY",flush=True)
        report["probe_ids"]=sorted(baseline or {})
        report["status"]=PASS
    except Exception as exc:
        report["error"]=str(exc)
        print(f"FRESH_MATRIX_ERROR class={a.owner} {exc}",file=sys.stderr,flush=True)
    finally:
        (output/"fresh-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print(f"FRESH_MATRIX_FINAL class={a.owner} status={report['status']}",flush=True)
    return 0 if report["status"]==PASS else 1

if __name__=="__main__":
    raise SystemExit(main())
