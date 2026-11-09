#!/usr/bin/env python3
"""Offline readiness and reproducible proof-bundle packaging (never executes PoCs)."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
LANES = "ABCDE"
REQUIRED = ("REPORT.md", "REPRODUCE.md", "SCOPE.md", "IMPACT.md",
            "DUPLICATE_REVIEW.md", "ENVIRONMENT.md", "MANIFEST.json")
MAX_BYTES = 30 * 1024 * 1024
MAX_SINGLE = 10 * 1024 * 1024

class Invalid(ValueError):
    pass

def check(ok, message):
    if not ok:
        raise Invalid(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def safe_path(name):
    parts = PurePosixPath(name).parts
    return bool(name) and not name.startswith("/") and "\\" not in name and \
        all(p not in (".", "..", "__pycache__") and not p.startswith(".") for p in parts) and \
        not name.endswith((".pem", ".key", ".p12", ".pfx"))

def validate(meta, files):
    check(meta.get("lane") in LANES, "invalid lane")
    repo = meta.get("target_repo", "")
    check(isinstance(repo, str) and re.fullmatch(r"transferwise/[A-Za-z0-9_.-]+", repo)
          and repo != "transferwise/pipelinewise", "out-of-scope target_repo")
    commit = meta.get("target_commit")
    check(isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}", commit), "target_commit must be full SHA")
    severity = meta.get("severity")
    check(severity in ("P0", "P1", "P2", "P3"), "invalid severity")
    check(severity != "P3" or meta.get("exceptional_p3_justified") is True, "unjustified P3")
    check(meta.get("status") == "CONFIRMED", "only confirmed results may be packaged")
    gates = meta.get("gates", {})
    check(isinstance(gates, dict) and all(gates.get("G"+str(i)) is True for i in range(5)),
          "G0-G4 evidence gates incomplete")
    check(meta.get("independent_reproduction_executed") is True and
          meta.get("negative_control_executed") is True, "execution/control attestation missing")
    check(all(f in files and files[f].strip() for f in REQUIRED), "missing required report/manifest file")
    check(any(f.startswith("POC/") for f in files), "runnable PoC file missing")
    check(any(f.startswith("EVIDENCE/CONTROL/") for f in files), "negative-control evidence missing")
    check(any(f.startswith("EVIDENCE/") and not f.startswith("EVIDENCE/CONTROL/")
              for f in files), "raw execution evidence missing")

def collect(source):
    check(source.is_dir(), "source directory does not exist")
    found = {}
    size = 0
    for path in sorted(source.rglob("*")):
        check(not path.is_symlink(), "symlink forbidden: "+str(path))
        if path.is_dir():
            continue
        name = path.relative_to(source).as_posix()
        check(safe_path(name), "unsafe filename: "+name)
        raw = path.read_bytes()
        check(len(raw) <= MAX_SINGLE, "oversized file: "+name)
        check(b"-----BEGIN PRIVATE KEY-----" not in raw and b"github_pat_" not in raw,
              "potential secret: "+name)
        size += len(raw)
        check(size <= MAX_BYTES, "bundle too large")
        if name != "SHA256SUMS":
            found[name] = raw
    check("MANIFEST.json" in found, "missing manifest")
    validate(json.loads(found["MANIFEST.json"]), found)
    return found

def package(source, dest):
    check(not dest.resolve().is_relative_to(source.resolve()), "ZIP must be outside source folder")
    found = collect(source)
    meta = json.loads(found["MANIFEST.json"])
    meta["files"] = [{"path": name, "sha256": digest(raw), "bytes": len(raw)}
                     for name, raw in sorted(found.items()) if name != "MANIFEST.json"]
    found["MANIFEST.json"] = (json.dumps(meta, sort_keys=True, indent=2)+"\n").encode()
    found["SHA256SUMS"] = ("\n".join(digest(raw)+"  "+name
                                      for name, raw in sorted(found.items()))+"\n").encode()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w") as z:
        for name, raw in sorted(found.items()):
            item = zipfile.ZipInfo(name, date_time=(1980,1,1,0,0,0))
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(item, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
    verify(dest)
    print("BUNDLE_OK", dest, "sha256="+digest(dest.read_bytes()))

def verify(dest):
    check(dest.is_file() and dest.stat().st_size <= MAX_BYTES, "missing/oversized ZIP")
    with zipfile.ZipFile(dest) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        check(len(names) == len(set(names)), "duplicate ZIP entries")
        check(all(safe_path(i.filename) and i.file_size <= MAX_SINGLE and
                  ((i.external_attr >> 16) & 0o170000) != 0o120000 for i in infos),
              "unsafe ZIP entries")
        check(sum(i.file_size for i in infos) <= MAX_BYTES, "ZIP expansion too large")
        found = {name: z.read(name) for name in names}
    check("SHA256SUMS" in found and "MANIFEST.json" in found, "missing checksum/manifest")
    sums = {}
    for line in found["SHA256SUMS"].decode().splitlines():
        parts = line.split("  ", 1)
        check(len(parts)==2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]), "bad checksum line")
        check(parts[1] not in sums, "duplicate checksum entry")
        sums[parts[1]] = parts[0]
    check(set(sums)==set(found)-{"SHA256SUMS"}, "incomplete checksum coverage")
    check(all(digest(found[n])==sha for n,sha in sums.items()), "ZIP checksum mismatch")
    meta = json.loads(found["MANIFEST.json"])
    validate(meta, found)
    entries = meta.get("files", [])
    check(isinstance(entries, list) and all(isinstance(e, dict) for e in entries),
          "bad manifest inventory")
    expected = {n:(digest(v),len(v)) for n,v in found.items()
                if n not in ("MANIFEST.json","SHA256SUMS")}
    actual = {e["path"]:(e["sha256"],e["bytes"]) for e in entries}
    check(len(actual)==len(entries) and actual==expected, "manifest inventory mismatch")
    print("VERIFY_OK", dest, "files="+str(len(found)))

def doctor(strict):
    check(sys.version_info >= (3,11), "Python >=3.11 required")
    print("Python", sys.version.split()[0])
    for tool in ("git", "gh", "docker", "rg", "node", "java", "terraform"):
        available = shutil.which(tool) is not None
        print(tool, "available" if available else "optional/missing")
        if tool == "git":
            check(available, "git required")
    if strict:
        cfg = json.loads((ROOT/"config/programs/transferwise_github.json").read_text())
        check(cfg["github"]["organization"]=="transferwise" and
              "transferwise/pipelinewise" in cfg["github"]["excluded_repositories"] and
              cfg["automation"]["branch"]=="transferwise", "scope/branch drift")
        for lane in LANES:
            root = ROOT/"transferwise"/lane
            probes = json.loads((root/"PROBES.json").read_text())
            check(probes.get("lane")==lane and probes.get("max_active_hypotheses")==3,
                  lane+": lane ownership mismatch")
            check(isinstance(probes.get("active"),list) and len(probes["active"])<=3,
                  lane+": too many active hypotheses")
            check((root/"latest.md").is_file(), lane+": missing status")
            for archive in (root/"submissions").glob("*.zip"):
                verify(archive)
        print("WORKSPACE_READY A,B,C,D,E")

def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command",required=True)
    d = commands.add_parser("doctor")
    d.add_argument("--check", action="store_true")
    p = commands.add_parser("pack")
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    v = commands.add_parser("verify")
    v.add_argument("--zip",type=Path,required=True)
    args = parser.parse_args()
    try:
        if args.command=="doctor":
            doctor(args.check)
        elif args.command=="pack":
            package(args.source,args.output)
        else:
            verify(args.zip)
    except (Invalid, OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print("CHECK_FAILED",str(exc),file=sys.stderr)
        sys.exit(1)

if __name__=="__main__":
    main()
