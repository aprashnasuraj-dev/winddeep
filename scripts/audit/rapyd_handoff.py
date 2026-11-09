#!/usr/bin/env python3
"""Offline readiness and structural evidence ZIP verification; never certifies a finding."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
LANES = "ABCDE"
REQUIRED = {"REPORT.md", "REPRODUCE.md", "SCOPE.md", "IMPACT.md", "DUPLICATE_REVIEW.md", "ENVIRONMENT.md"}
MAX_BYTES = 25 * 1024 * 1024
REPO_RE = re.compile(r"^rapyd/[A-Za-z0-9_.-]+$", re.I)


def legal_name(name: str) -> bool:
    return bool(name and not name.endswith("/") and not name.startswith("/") and
                "\\" not in name and "\x00" not in name and
                all(p not in ("", ".", "..") for p in name.split("/")) and
                PurePosixPath(name).as_posix() == name)


def private_git_path(path: str) -> bool:
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "rapyd" or parts[1] not in LANES:
        return False
    return (parts[2] in {"evidence", "submissions", "private", "POC", "EVIDENCE", "CONTROL"}
            or path.lower().endswith((".zip", ".tar", ".tgz", ".7z"))
            or parts[-1] in {"REPORT.md", "REPRODUCE.md", "IMPACT.md"})


def repo_check(root: Path = ROOT) -> list[str]:
    errors = []
    try:
        cfg = json.loads((root / "config/programs/rapyd_bugcrowd.json").read_text())
        if cfg["platform"] != "bugcrowd":
            errors.append("Unexpected audit program")
        if set(cfg["lane_map"]) != set(LANES):
            errors.append("Five-lane mapping incomplete")
        required_denies = {"docs.rapyd.net", "support.rapyd.net", "sandbox.rapyd.net", "community.rapyd.net"}
        if not required_denies.issubset(set(cfg["out_of_scope"])):
            errors.append("Rapyd explicit scope denials missing")
        if cfg["authorization"]["live_target_requests_enabled"]:
            errors.append("Live target testing must remain disabled in this baseline")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Invalid Rapyd program config: {exc}")
    for lane in LANES:
        folder = root / "rapyd" / lane
        if not (folder / "latest.md").is_file():
            errors.append(f"{lane}: missing latest.md")
        try:
            probes = json.loads((folder / "PROBES.json").read_text())
            if probes["lane"] != lane or not isinstance(probes["active"], list):
                errors.append(f"{lane}: invalid lane/active schema")
            elif len(probes["active"]) > 3 or probes["max_active_hypotheses"] != 3:
                errors.append(f"{lane}: active hypotheses exceed cap 3")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{lane}: invalid PROBES.json: {exc}")
    try:
        tracked = subprocess.check_output(
            ["git", "-C", str(root), "ls-files", "-z"], stderr=subprocess.PIPE
        ).decode("utf-8").split("\x00")
        leaks = [name for name in tracked if private_git_path(name)]
        if leaks:
            errors.append("Private evidence tracked in PUBLIC Git: " + ", ".join(leaks))
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        errors.append(f"Cannot verify tracked files (fail-closed): {exc}")
    return errors


def source_files(folder: Path) -> dict[str, bytes]:
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Source must be a normal local directory")
    found = {}
    total = 0
    for path in sorted(folder.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Symlink not allowed: {path}")
        if not path.is_file():
            continue
        name = path.relative_to(folder).as_posix()
        if not legal_name(name) or name in {"SHA256SUMS", "MANIFEST.json"}:
            raise ValueError(f"Illegal/reserved artifact path: {name}")
        data = path.read_bytes()
        total += len(data)
        if total > MAX_BYTES:
            raise ValueError("Source exceeds 25 MiB")
        found[name] = data
    return found


def check_layout(files: dict[str, bytes]) -> None:
    missing = sorted(REQUIRED - files.keys())
    if missing:
        raise ValueError("Missing required files: " + ", ".join(missing))
    if any(not files[n].strip() for n in REQUIRED):
        raise ValueError("Blank required report document")
    if not any(n.startswith("POC/") for n in files):
        raise ValueError("Missing independently runnable POC/ file")
    if not any(n.startswith("EVIDENCE/") and not n.startswith("EVIDENCE/CONTROL/") for n in files):
        raise ValueError("Missing observed EVIDENCE/ artifact")
    if not any(n.startswith(("EVIDENCE/CONTROL/", "CONTROL/")) for n in files):
        raise ValueError("Missing negative CONTROL artifact")


def check_metadata(meta: dict) -> None:
    if meta.get("lane") not in LANES:
        raise ValueError("Invalid lane")
    asset = str(meta.get("asset", ""))
    if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z0-9-]+", asset):
        raise ValueError("Out-of-scope asset hostname")
    cfg = json.loads((ROOT / "config/programs/rapyd_bugcrowd.json").read_text())
    def match(pattern):
        return (asset.endswith(pattern[1:]) and asset != pattern[2:]) if pattern.startswith("*.") else asset == pattern
    if (any(match(p) for p in cfg["out_of_scope"] if p != "3rd party services")
            or not any(match(p) for p in cfg["in_scope"])):
        raise ValueError("Out-of-scope asset")
    if not re.fullmatch(r"[0-9a-f]{64}", str(meta.get("snapshot_sha256", ""))):
        raise ValueError("64-char SHA256 snapshot required")
    if meta.get("policy_reviewed") is not True:
        raise ValueError("Manual authenticated Bugcrowd policy review required")
    if meta.get("priority") not in {"P0", "P1", "P2", "P3"}:
        raise ValueError("Unsupported priority")
    if meta.get("verification_state") != "STRUCTURE_ONLY_NOT_CONFIRMED":
        raise ValueError("Structural helper cannot certify CONFIRMED")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        if len(names) != len(set(names)) or not all(legal_name(n) for n in names):
            raise ValueError("Duplicate or unsafe ZIP path")
        if any(stat.S_ISLNK(i.external_attr >> 16) for i in infos):
            raise ValueError("ZIP symlink forbidden")
        if len(infos) > 500:
            raise ValueError("Too many ZIP entries")
        if sum(i.file_size for i in infos) > MAX_BYTES:
            raise ValueError("Uncompressed ZIP exceeds 25 MiB")
        files = {name: z.read(name) for name in names}
    if "SHA256SUMS" not in files or "MANIFEST.json" not in files:
        raise ValueError("Missing checksum/manifest")
    sums = {}
    for line in files["SHA256SUMS"].decode().splitlines():
        if "  " not in line:
            raise ValueError("Malformed checksum line")
        digest, name = line.split("  ", 1)
        if name in sums or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid/duplicate checksum")
        sums[name] = digest
    actual = set(files) - {"SHA256SUMS"}
    if actual != set(sums) or any(sha(files[n]) != sums[n] for n in actual):
        raise ValueError("ZIP checksum mismatch")
    manifest = json.loads(files["MANIFEST.json"])
    check_metadata(manifest)
    source = {k: v for k, v in files.items() if k not in {"MANIFEST.json", "SHA256SUMS"}}
    check_layout(source)
    expected = [{"path": n, "sha256": sha(v), "size": len(v)} for n, v in sorted(source.items())]
    if manifest.get("files") != expected:
        raise ValueError("Manifest inventory mismatch")
    return manifest


def pack(folder: Path, output: Path, metadata: dict) -> None:
    check_metadata(metadata)
    files = source_files(folder)
    check_layout(files)
    if output.exists():
        raise ValueError("Output exists; no overwrite")
    manifest = dict(metadata)
    manifest["files"] = [{"path": n, "sha256": sha(v), "size": len(v)} for n, v in sorted(files.items())]
    files["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    files["SHA256SUMS"] = "".join(f"{sha(v)}  {n}\n" for n, v in sorted(files.items())).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(info, data)
    verify(output)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("repo-check")
    make = sub.add_parser("pack")
    make.add_argument("--source", required=True, type=Path)
    make.add_argument("--output", required=True, type=Path)
    make.add_argument("--lane", required=True, choices=list(LANES))
    make.add_argument("--asset", required=True)
    make.add_argument("--snapshot-sha256", required=True)
    make.add_argument("--priority", required=True, choices=["P0", "P1", "P2", "P3"])
    make.add_argument("--policy-reviewed", action="store_true")
    check = sub.add_parser("verify")
    check.add_argument("zip", type=Path)
    a = p.parse_args()
    try:
        if a.command == "repo-check":
            errors = repo_check()
            if errors:
                raise ValueError("; ".join(errors))
            print("PUBLIC REPOSITORY READY: five lanes and private-evidence guard passed")
        elif a.command == "pack":
            pack(a.source, a.output, {"lane": a.lane, "asset": a.asset, "snapshot_sha256": a.snapshot_sha256,
                 "priority": a.priority, "policy_reviewed": a.policy_reviewed,
                 "verification_state": "STRUCTURE_ONLY_NOT_CONFIRMED"})
            print(f"STRUCTURE_OK {a.output} SHA256={sha(a.output.read_bytes())}")
        else:
            meta = verify(a.zip)
            print(f"STRUCTURE_OK {meta['asset']} snapshot={meta['snapshot_sha256']} SHA256={sha(a.zip.read_bytes())}")
        return 0
    except (OSError, ValueError, KeyError, UnicodeError, zipfile.BadZipFile) as exc:
        print(f"NOT READY: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
