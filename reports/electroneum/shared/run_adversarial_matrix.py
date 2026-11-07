#!/usr/bin/env python3
"""Bounded certified-source adversarial regression executor.

Copies the immutable certified source into disposable scratch, injects only
synthetic audit test files, and runs actual Go package tests three times.
Never treats a passing regression as a confirmed vulnerability.
No local Git, network peers, production keys or public-chain transactions.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def contained(root: Path, path: str) -> Path:
    if not path or path.startswith("/") or ".." in Path(path).parts:
        raise ValueError(f"unsafe relative path: {path}")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"path escaped workspace: {path}")
    return resolved


def validate_identity(matrix: dict) -> None:
    source = matrix["source"]
    expectations = {
        "WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT": source["certified_commit"],
        "WINDEEP_ETN_SOURCE_TREE_SHA": source["tree"],
        "WINDEEP_ETN_PINNED_SOURCE_COMMIT": source["public_commit"],
    }
    for key, required in expectations.items():
        actual = os.environ.get(key)
        if actual != required:
            raise RuntimeError(f"certification mismatch {key}: {actual!r} != {required!r}")
    if not os.environ.get("WINDEEP_ETN_SOURCE"):
        raise RuntimeError("certified runner bootstrap did not export WINDEEP_ETN_SOURCE")


def validate_matrix(matrix: dict, repo: Path) -> None:
    if matrix.get("schema") != 1:
        raise ValueError("expected adversarial matrix schema 1")
    seen: set[str] = set()
    for probe in matrix["probes"]:
        if probe["id"] in seen:
            raise ValueError("duplicate probe id")
        seen.add(probe["id"])
        if probe["owner"] not in "ABCDE":
            raise ValueError(f"unknown owner {probe['owner']}")
        if not re.fullmatch(r"Test[A-Za-z0-9_]+", probe["test"]):
            raise ValueError("test name is not an explicit Go Test identifier")
        if not re.fullmatch(r"\./[a-zA-Z0-9_/-]+", probe["package"]):
            raise ValueError("unsafe Go package path")
        source_path = contained(repo, probe["source"])
        if not source_path.is_file() or source_path.suffix != ".go":
            raise ValueError(f"missing Go fixture {probe['source']}")
        if not probe["source"].startswith("reports/electroneum/"):
            raise ValueError("fixture outside audit directory")
        if not probe["target"].endswith("_test.go"):
            raise ValueError("target must be a Go test")
        if not probe["markers"]:
            raise ValueError("every probe must have measurable stdout controls")


def run_probe(probe: dict, repeat: int, repo: Path, scratch: Path, output: Path) -> dict:
    fixture = contained(repo, probe["source"])
    target = contained(scratch, probe["target"])
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, target.parent.stat().st_mode | stat.S_IWUSR)
    shutil.copyfile(fixture, target)
    os.chmod(target, target.stat().st_mode | stat.S_IWUSR)

    cmd = ["go", "test", f"-count={repeat}", "-timeout=8m",
           "-run", f"^{probe['test']}$", "-v", probe["package"]]
    started = time.monotonic()
    env = os.environ.copy()
    env["GOTOOLCHAIN"] = "local"
    try:
        result = subprocess.run(cmd, cwd=scratch, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=840, check=False)
        log = result.stdout
        exit_code = result.returncode
    except subprocess.TimeoutExpired as exc:
        captured = exc.stdout or b""
        log = captured.decode("utf-8", "replace") if isinstance(captured, bytes) else captured
        log += "\nMATRIX_TIMEOUT after 840s\n"
        exit_code = 124

    log_path = output / f"{probe['id']}.log"
    log_path.write_text(log, encoding="utf-8")
    top_pass = len(re.findall(r"(?m)^--- PASS: " + re.escape(probe["test"]) + r"(?:\s|$)", log))
    marker_counts = {marker: log.count(marker) for marker in probe["markers"]}
    ok = exit_code == 0 and top_pass == repeat and all(n >= repeat for n in marker_counts.values())
    return {
        "id": probe["id"],
        "owner": probe["owner"],
        "test": probe["test"],
        "package": probe["package"],
        "source_fixture": probe["source"],
        "fixture_sha256": sha256(fixture),
        "classification": probe["classification"],
        "command": cmd,
        "exit_code": exit_code,
        "expected_repetitions": repeat,
        "successful_top_level_repetitions": top_pass,
        "positive_negative_controls_seen": marker_counts,
        "duration_seconds": round(time.monotonic() - started, 2),
        "log": log_path.name,
        "log_sha256": sha256(log_path),
        "outcome": "PASS_REGRESSION_ONLY" if ok else "FAIL_OR_INCOMPLETE",
        "claim_limit": "Passing regression is not evidence of attacker-reachable E3/E4 vulnerability",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="owner", required=True, choices=list("ABCDE"))
    ap.add_argument("--matrix", default="reports/electroneum/shared/adversarial_matrix.json")
    ap.add_argument("--output", required=True)
    ap.add_argument("--repeat", type=int, default=3)
    args = ap.parse_args()
    if not 1 <= args.repeat <= 3:
        ap.error("repeat must be 1..3")
    repo = Path.cwd().resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    run = {
        "schema": 1, "class": args.owner,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "status": "FAILED", "probes": [],
        "verified_scope": "certified in-process test regression, synthetic fixtures only",
        "not_proven": ["public network reachability", "production exploit",
                       "independent public-code reproducer", "E3/E4 impact"],
    }
    try:
        matrix = json.loads(contained(repo, args.matrix).read_text(encoding="utf-8"))
        # Each scheduled worker may register up to three ACTIVE new probes
        # in its own class-owned manifest; no concurrent shared-file writes.
        extension_path = contained(repo, f"reports/electroneum/{args.owner}/PROBES.json")
        if extension_path.exists():
            extension = json.loads(extension_path.read_text(encoding="utf-8"))
            if extension.get("schema") != 1 or extension.get("owner") != args.owner:
                raise ValueError(f"invalid owner/schema in {extension_path}")
            extra = extension.get("probes", [])
            if not isinstance(extra, list) or len(extra) > 3:
                raise ValueError("class probe extension requires 0..3 bounded active probes")
            for probe in extra:
                if probe.get("owner") != args.owner or not probe.get("source", "").startswith(
                    f"reports/electroneum/{args.owner}/"
                ):
                    raise ValueError("class-owned probe cannot read or overwrite peer fixtures")
            matrix["probes"].extend(extra)
        validate_matrix(matrix, repo)
        validate_identity(matrix)
        run["certified_source_commit"] = matrix["source"]["certified_commit"]
        run["certified_source_tree"] = matrix["source"]["tree"]
        selected = [x for x in matrix["probes"] if x["owner"] == args.owner]
        if not selected:
            raise RuntimeError(f"no probes for class {args.owner}")
        source = Path(os.environ["WINDEEP_ETN_SOURCE"]).resolve()
        if not (source / "go.mod").is_file():
            raise RuntimeError("certified materialization lacks go.mod")
        scratch = output / "scratch"
        if scratch.exists():
            raise RuntimeError("refusing to reuse non-clean scratch")
        print(f"CERTIFIED_MATRIX_START class={args.owner} probes={len(selected)}")
        shutil.copytree(source, scratch, symlinks=False)
        for probe in selected:
            record = run_probe(probe, args.repeat, repo, scratch, output)
            run["probes"].append(record)
            print(f"MATRIX_PROBE {record['id']} {record['outcome']} "
                  f"repeated={record['successful_top_level_repetitions']} "
                  f"exit={record['exit_code']} log_sha256={record['log_sha256']}", flush=True)
            if record["outcome"] != "PASS_REGRESSION_ONLY":
                raise RuntimeError(f"probe {probe['id']} failed or lacked controls")
        run["status"] = "PASSED_REGRESSIONS_NOT_FINDINGS"
    except Exception as exc:
        run["error"] = str(exc)
        print(f"MATRIX_ERROR class={args.owner}: {exc}", file=sys.stderr)
        traceback.print_exc()
    finally:
        (output / "result.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
        if summary:
            with summary.open("a", encoding="utf-8") as handle:
                handle.write(f"### Electroneum certified class {args.owner} adversarial regressions\n"
                             f"Status: **{run['status']}**; no P1–P3 claim from pass alone.\n\n"
                             "| Probe | Result | Repetitions |\n|---|---|---:|\n")
                for record in run["probes"]:
                    handle.write(f"| {record['id']} | {record['outcome']} | "
                                 f"{record['successful_top_level_repetitions']} |\n")
        print(f"CERTIFIED_MATRIX_END class={args.owner} status={run['status']}", flush=True)
    return 0 if run["status"] == "PASSED_REGRESSIONS_NOT_FINDINGS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
