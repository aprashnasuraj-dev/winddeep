#!/usr/bin/env python3
"""Read-only GitHub organization audit flow for the Wise/transferwise bug-bounty scope.

This module intentionally produces *candidates*, not vulnerability claims.
Nothing becomes reportable without scoped reproduction, specific proof, impact,
Wise-specific ownership where relevant, and duplicate review.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable

ORG = "transferwise"
EXCLUDED = {"transferwise/pipelinewise"}
TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts", ".go", ".rb",
    ".php", ".cs", ".scala", ".groovy", ".sh", ".bash", ".zsh", ".ps1", ".yml",
    ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties",
    ".gradle", ".tf", ".hcl", ".md", ".txt", ".env", ".example",
}
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".terraform", ".gradle", ".idea", ".next",
}
SAMPLE_PATH_PARTS = {
    "test", "tests", "testing", "fixture", "fixtures", "example", "examples",
    "sample", "samples", "demo", "docs", "doc", ".github",
}
PLACEHOLDER_VALUES = {
    "password", "passwd", "changeit", "secret", "changeme", "example", "dummy",
    "test", "testing", "token", "apikey", "api_key", "your-token", "your_token",
    "replace-me", "replace_me", "xxx", "xxxx", "foobar",
}
SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)
    \b\s*[:=]\s*["']([^"'\r\n]{4,200})["']
    """
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
DANGEROUS_WORKFLOW_EXPR = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)[^}]*\}\}"
)
PR_HEAD_CHECKOUT = re.compile(
    r"(?is)uses:\s*actions/checkout@[^\n]+.*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)"
)
WRITE_ALL = re.compile(r"(?im)^\s*permissions:\s*write-all\s*$")
PULL_REQUEST_TARGET = re.compile(r"(?im)^\s*pull_request_target\s*:")
SHELL_TRUE = re.compile(r"(?im)\bshell\s*=\s*True\b|\bshell:\s*true\b")
YAML_LOAD = re.compile(r"\byaml\.load\s*\((?![^\n)]*(?:SafeLoader|safe_load))")


@dataclass(frozen=True)
class Candidate:
    repo: str
    commit: str
    path: str
    line: int
    detector: str
    severity_hint: str
    excerpt: str
    rationale: str
    reportable: bool
    required_proof: tuple[str, ...]
    duplicate_review_required: bool = True
    wise_specific_review_required: bool = False


def load_config(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def normalize_repo(value: str) -> str:
    value = value.strip()
    value = re.sub(r"^https?://github\.com/", "", value, flags=re.I)
    value = value[:-4] if value.endswith(".git") else value
    return value.strip("/")


def assert_repo_in_scope(value: str, config: dict | None = None) -> str:
    repo = normalize_repo(value)
    parts = repo.split("/")
    if len(parts) != 2 or parts[0].casefold() != ORG:
        raise ValueError(f"out of scope GitHub repository: {value}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", parts[1]):
        raise ValueError(f"invalid GitHub repository name: {value}")
    excluded = set(EXCLUDED)
    if config:
        excluded.update(str(x).casefold() for x in config["github"].get("excluded_repositories", []))
    if repo.casefold() in {x.casefold() for x in excluded}:
        raise ValueError(f"explicitly excluded repository: {repo}")
    return f"{ORG}/{parts[1]}"


def github_json(url: str, token: str = "") -> object:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "windeep-transferwise-readonly-audit",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def repo_priority(repo: dict) -> int:
    score = 0
    if not repo.get("archived"):
        score += 40
    if not repo.get("fork"):
        score += 25
    name = str(repo.get("name", "")).casefold()
    description = str(repo.get("description") or "").casefold()
    high_signal = (
        "api", "auth", "oauth", "webhook", "sign", "kms", "security", "terraform",
        "github", "action", "operator", "payment", "bank", "identity", "token",
    )
    score += min(30, 6 * sum(term in name or term in description for term in high_signal))
    size = int(repo.get("size") or 0)
    if 1 <= size <= 25_000:
        score += 10
    if size > 150_000:
        score -= 15
    return score


def inventory(config: dict, *, limit: int, token: str = "") -> tuple[list[dict], list[dict]]:
    org = config["github"]["organization"]
    if org.casefold() != ORG:
        raise ValueError("policy organization mismatch")
    repos: list[dict] = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{org}/repos?type=public&per_page=100&page={page}"
        batch = github_json(url, token)
        if not isinstance(batch, list):
            raise RuntimeError("unexpected GitHub repository inventory response")
        if not batch:
            break
        for raw in batch:
            full_name = str(raw.get("full_name", ""))
            try:
                scoped = assert_repo_in_scope(full_name, config)
            except ValueError:
                continue
            repos.append({
                "repo": scoped,
                "archived": bool(raw.get("archived")),
                "fork": bool(raw.get("fork")),
                "default_branch": str(raw.get("default_branch") or ""),
                "size_kb": int(raw.get("size") or 0),
                "pushed_at": raw.get("pushed_at"),
                "description": raw.get("description"),
                "priority": repo_priority(raw),
                "third_party_review_required": bool(raw.get("fork")),
            })
        if len(batch) < 100:
            break
        page += 1
    repos.sort(key=lambda x: (-int(x["priority"]), bool(x["archived"]), x["repo"].casefold()))
    selected = repos if limit <= 0 else repos[:limit]
    matrix = [{"repo": r["repo"], "fork": r["fork"], "archived": r["archived"], "priority": r["priority"]} for r in selected]
    return repos, matrix


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.stat().st_size > 2_000_000:
            continue
        if path.suffix.casefold() in TEXT_SUFFIXES or path.name in {
            "Dockerfile", "Makefile", "Gemfile", "Rakefile", "Jenkinsfile",
        }:
            yield path


def is_sample_path(path: Path) -> bool:
    lowered = {part.casefold() for part in path.parts}
    return bool(lowered & SAMPLE_PATH_PARTS)


def placeholder_secret(value: str, path: Path, line_text: str) -> bool:
    cleaned = value.strip().strip("'\"").casefold()
    if cleaned in PLACEHOLDER_VALUES:
        return True
    if any(token in cleaned for token in ("example", "dummy", "sample", "changeme", "changeit", "your_")):
        return True
    context = line_text.casefold()
    if is_sample_path(path) and any(k in context for k in ("example", "sample", "test", "fixture", "ci")):
        return True
    return False


def excerpt(line: str) -> str:
    line = line.strip().replace("\t", " ")
    return line[:280]


def add_candidate(
    out: list[Candidate], *, repo: str, commit: str, path: Path, line: int,
    detector: str, severity: str, text: str, rationale: str,
    required: tuple[str, ...], wise_specific: bool = False,
) -> None:
    out.append(Candidate(
        repo=repo,
        commit=commit,
        path=path.as_posix(),
        line=line,
        detector=detector,
        severity_hint=severity,
        excerpt=excerpt(text),
        rationale=rationale,
        reportable=False,
        required_proof=required,
        duplicate_review_required=True,
        wise_specific_review_required=wise_specific,
    ))


def scan_repo(repo: str, root: Path, commit: str, config: dict, *, fork: bool = False) -> list[Candidate]:
    repo = assert_repo_in_scope(repo, config)
    candidates: list[Candidate] = []
    wise_specific = bool(fork)
    for path in iter_text_files(root):
        rel = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()

        # Secrets are leads only. Suppress obvious placeholders/examples/tests/CI.
        for idx, line in enumerate(lines, 1):
            for match in SECRET_ASSIGNMENT.finditer(line):
                value = match.group(2)
                if placeholder_secret(value, rel, line):
                    continue
                add_candidate(
                    candidates, repo=repo, commit=commit, path=rel, line=idx,
                    detector="hardcoded-secret-candidate", severity="review",
                    text=line,
                    rationale="Non-placeholder secret-like assignment requires provenance and production-use review.",
                    required=(
                        "prove value is real and Wise-owned",
                        "prove production/internal impact without automated credential login",
                        "specific reproduction and impact",
                        "manual duplicate review",
                    ),
                    wise_specific=wise_specific,
                )
            if PRIVATE_KEY.search(line) and not is_sample_path(rel):
                add_candidate(
                    candidates, repo=repo, commit=commit, path=rel, line=idx,
                    detector="private-key-candidate", severity="high-review",
                    text=line,
                    rationale="Private-key material outside obvious sample/test paths needs ownership and usage verification.",
                    required=(
                        "prove key is Wise-owned and active/relevant",
                        "do not perform automated login or unauthorized use",
                        "specific impact evidence",
                        "manual duplicate review",
                    ),
                    wise_specific=wise_specific,
                )

        suffix = rel.suffix.casefold()
        if suffix in {".yml", ".yaml"} and ".github" in rel.parts and "workflows" in rel.parts:
            if PULL_REQUEST_TARGET.search(text) and PR_HEAD_CHECKOUT.search(text):
                line_no = next((i for i, line in enumerate(lines, 1) if "pull_request_target" in line), 1)
                add_candidate(
                    candidates, repo=repo, commit=commit, path=rel, line=line_no,
                    detector="pr-target-untrusted-checkout", severity="high",
                    text=lines[line_no - 1] if lines else "",
                    rationale="pull_request_target combined with PR-head checkout can expose privileged workflow context to untrusted code.",
                    required=(
                        "prove attacker-controlled fork/PR code reaches a privileged step",
                        "prove secrets/token permissions or write capability are exposed",
                        "minimal non-destructive PoC",
                        "manual duplicate review",
                    ),
                    wise_specific=wise_specific,
                )
            if WRITE_ALL.search(text):
                line_no = next((i for i, line in enumerate(lines, 1) if "write-all" in line), 1)
                add_candidate(
                    candidates, repo=repo, commit=commit, path=rel, line=line_no,
                    detector="workflow-write-all", severity="review",
                    text=lines[line_no - 1] if lines else "",
                    rationale="Broad workflow permissions increase blast radius but are not a finding without an attacker-controlled execution path.",
                    required=(
                        "identify attacker-controlled execution path",
                        "demonstrate concrete privileged effect",
                        "manual duplicate review",
                    ),
                    wise_specific=wise_specific,
                )
            for idx, line in enumerate(lines, 1):
                if DANGEROUS_WORKFLOW_EXPR.search(line) and re.search(r"^\s*(run:|-\s*run:)", line):
                    add_candidate(
                        candidates, repo=repo, commit=commit, path=rel, line=idx,
                        detector="workflow-expression-command-injection", severity="high",
                        text=line,
                        rationale="Event-derived expression is interpolated directly into a shell run block and may permit command injection.",
                        required=(
                            "show the event field is attacker-controlled for this trigger",
                            "show shell parsing reaches injected syntax",
                            "minimal non-destructive PoC",
                            "manual duplicate review",
                        ),
                        wise_specific=wise_specific,
                    )

        for idx, line in enumerate(lines, 1):
            if SHELL_TRUE.search(line):
                add_candidate(
                    candidates, repo=repo, commit=commit, path=rel, line=idx,
                    detector="shell-true-review", severity="review",
                    text=line,
                    rationale="shell=True is only actionable if untrusted input reaches the command string.",
                    required=(
                        "trace attacker-controlled input to command construction",
                        "prove executable command injection",
                        "minimal non-destructive PoC",
                        "manual duplicate review",
                    ),
                    wise_specific=wise_specific,
                )
            if YAML_LOAD.search(line):
                add_candidate(
                    candidates, repo=repo, commit=commit, path=rel, line=idx,
                    detector="unsafe-yaml-load-review", severity="review",
                    text=line,
                    rationale="Potential unsafe YAML deserialization; exploitability depends on loader and attacker control.",
                    required=(
                        "prove attacker controls parsed YAML",
                        "prove unsafe loader/object construction in the shipped path",
                        "specific impact",
                        "manual duplicate review",
                    ),
                    wise_specific=wise_specific,
                )
    return candidates


def validate_candidate(candidate: dict, proof: dict, config: dict) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    try:
        assert_repo_in_scope(str(candidate.get("repo", "")), config)
    except ValueError as exc:
        reasons.append(str(exc))

    required_true = ("reproduced", "impact_demonstrated", "specific_poc", "duplicate_reviewed")
    for key in required_true:
        if proof.get(key) is not True:
            reasons.append(f"{key}=true is required")

    if candidate.get("wise_specific_review_required") and proof.get("wise_specific") is not True:
        reasons.append("wise_specific=true is required for third-party/fork-derived code")

    if str(candidate.get("detector", "")).endswith("secret-candidate") or candidate.get("detector") == "private-key-candidate":
        if proof.get("wise_owned_credential_or_key") is not True:
            reasons.append("Wise ownership must be established")
        if proof.get("manual_program_evidence") is not True:
            reasons.append("manual program-compliant evidence is required; automation must not validate credentials")

    if not str(proof.get("poc_steps", "")).strip():
        reasons.append("poc_steps are required")
    if not str(proof.get("impact", "")).strip():
        reasons.append("impact description is required")

    return (not reasons), reasons


def git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def cmd_inventory(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    repos, matrix = inventory(config, limit=args.limit, token=os.environ.get("GITHUB_TOKEN", ""))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps({
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "github.com/transferwise/*",
        "excluded": sorted(EXCLUDED),
        "known_reported_issue_count": config["github"].get("known_reported_issue_count", 0),
        "repository_count": len(repos),
        "repositories": repos,
    }, indent=2), encoding="utf-8")
    Path(args.matrix).write_text(json.dumps({"include": matrix}, separators=(",", ":")), encoding="utf-8")
    print(f"inventory: {len(repos)} in-scope repositories; selected {len(matrix)} for this run")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    repo = assert_repo_in_scope(args.repo, config)
    root = Path(args.root).resolve()
    commit = args.commit or git_head(root)
    candidates = scan_repo(repo, root, commit, config, fork=args.fork)
    payload = {
        "repo": repo,
        "commit": commit,
        "candidate_count": len(candidates),
        "reportable_count": 0,
        "policy": {
            "scanner_output_is_not_a_finding": True,
            "credential_login_validation_performed": False,
            "duplicate_review_required": True,
            "known_reported_issue_count": config["github"].get("known_reported_issue_count", 0),
        },
        "candidates": [asdict(c) for c in candidates],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"{repo}@{commit}: {len(candidates)} candidates, 0 automatically reportable findings")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
    proof = json.loads(Path(args.proof).read_text(encoding="utf-8"))
    ok, reasons = validate_candidate(candidate, proof, config)
    print(json.dumps({"reportable": ok, "reasons": reasons}, indent=2))
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("inventory")
    inv.add_argument("--config", required=True)
    inv.add_argument("--out", required=True)
    inv.add_argument("--matrix", required=True)
    inv.add_argument("--limit", type=int, default=30)
    inv.set_defaults(func=cmd_inventory)

    scan = sub.add_parser("scan")
    scan.add_argument("--config", required=True)
    scan.add_argument("--repo", required=True)
    scan.add_argument("--root", required=True)
    scan.add_argument("--commit", default="")
    scan.add_argument("--fork", action="store_true")
    scan.add_argument("--out", required=True)
    scan.set_defaults(func=cmd_scan)

    val = sub.add_parser("validate")
    val.add_argument("--config", required=True)
    val.add_argument("--candidate", required=True)
    val.add_argument("--proof", required=True)
    val.set_defaults(func=cmd_validate)
    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
