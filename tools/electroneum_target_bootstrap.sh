#!/usr/bin/env bash
# Shared Electroneum audit target bootstrap for Workers A-E.
# Routine audits trust only the certified Git source commit/tree. The historical
# ZIP remains provenance evidence and is never extracted by this bootstrap.
set -euo pipefail

readonly WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT="7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
readonly WINDEEP_ETN_SOURCE_TREE_SHA="de7f3c75a2db7e87a89918f1257820703d5b731e"
readonly WINDEEP_ETN_SOURCE_REL="vendor/electroneum-sc"
readonly WINDEEP_ETN_CERTIFICATE_REL="reports/electroneum/TARGET_CERTIFICATE.json"
readonly WINDEEP_ETN_PINNED_SOURCE_COMMIT="3aeb14db0d6384243302f3a025bdff904dc28bf6"
readonly WINDEEP_ETN_UPSTREAM_ROOT_TREE_SHA="bc45332f06c9e4db462951d80243b462982b3f04"
readonly WINDEEP_ETN_ARCHIVE_SHA256="3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
readonly WINDEEP_ETN_EXPECTED_FILE_COUNT="1921"
WINDEEP_ETN_TARGET_BASE=""

fail() {
  local code="$1"; shift
  echo "target-bootstrap: $*" >&2
  return "$code" 2>/dev/null || exit "$code"
}

for cmd in git tar mktemp find chmod python3 awk wc; do
  command -v "$cmd" >/dev/null 2>&1 || fail 20 "missing required command: $cmd"
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail 21 "must run from inside a Windeep Git checkout"
certificate="$repo_root/$WINDEEP_ETN_CERTIFICATE_REL"
[[ -f "$certificate" ]] || fail 22 "target certificate is missing: $WINDEEP_ETN_CERTIFICATE_REL"

python3 - "$certificate" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    cert = json.load(fh)
expected = {
    "schema": 2,
    "archive_git_blob_sha1": "581c984e3e0d6451bc6273c19edf1bdb78dfed0a",
    "archive_sha256": "3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b",
    "upstream_repository": "electroneum/electroneum-sc",
    "upstream_source_commit": "3aeb14db0d6384243302f3a025bdff904dc28bf6",
    "upstream_root_tree_sha": "bc45332f06c9e4db462951d80243b462982b3f04",
    "windeep_source_commit": "7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0",
    "source_path": "vendor/electroneum-sc",
    "git_tree_sha": "de7f3c75a2db7e87a89918f1257820703d5b731e",
    "tracked_blob_count": 1921,
    "file_count": 1921,
    "gitlinks_materialized": False,
    "symlinks_allowed": False,
}
for key, value in expected.items():
    if cert.get(key) != value:
        raise SystemExit(f"target-bootstrap: certificate mismatch for {key}: expected {value!r} got {cert.get(key)!r}")
expected_gitlinks = {
    "tests/evm-benchmarks": "849b3e239a28f236dc99574b2e10e0c720895105",
    "tests/testdata": "a380655e5ffab1a5ea0f4d860224bdb19013f06a",
}
if cert.get("upstream_gitlinks") != expected_gitlinks:
    raise SystemExit("target-bootstrap: certificate upstream_gitlinks mismatch")
PY

git -C "$repo_root" cat-file -e "$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT^{commit}" 2>/dev/null ||   fail 23 "certified source commit object is unavailable: $WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT"

commit_tree="$(git -C "$repo_root" rev-parse "$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT:$WINDEEP_ETN_SOURCE_REL" 2>/dev/null)" ||   fail 23 "certified source tree object is unavailable from source commit"
[[ "$commit_tree" == "$WINDEEP_ETN_SOURCE_TREE_SHA" ]] ||   fail 24 "source-commit tree mismatch: expected $WINDEEP_ETN_SOURCE_TREE_SHA got $commit_tree"

head_tree="$(git -C "$repo_root" rev-parse "HEAD:$WINDEEP_ETN_SOURCE_REL" 2>/dev/null)" ||   fail 22 "certified source path is absent from current audit branch: $WINDEEP_ETN_SOURCE_REL"
[[ "$head_tree" == "$WINDEEP_ETN_SOURCE_TREE_SHA" ]] ||   fail 24 "current branch source tree mismatch: expected $WINDEEP_ETN_SOURCE_TREE_SHA got $head_tree"

if ! git -C "$repo_root" diff --quiet -- "$WINDEEP_ETN_SOURCE_REL" ||    ! git -C "$repo_root" diff --cached --quiet -- "$WINDEEP_ETN_SOURCE_REL" ||    [[ -n "$(git -C "$repo_root" ls-files --others -- "$WINDEEP_ETN_SOURCE_REL")" ]]; then
  fail 25 "checkout contains staged, unstaged, or untracked changes under $WINDEEP_ETN_SOURCE_REL"
fi

tree_type="$(git -C "$repo_root" cat-file -t "$WINDEEP_ETN_SOURCE_TREE_SHA" 2>/dev/null)" ||   fail 23 "certified tree object is unavailable: $WINDEEP_ETN_SOURCE_TREE_SHA"
[[ "$tree_type" == "tree" ]] || fail 23 "certified object is not a Git tree: $WINDEEP_ETN_SOURCE_TREE_SHA"

if git -C "$repo_root" ls-tree -r "$WINDEEP_ETN_SOURCE_TREE_SHA" | awk '$1 == "120000" {found=1} END {exit found ? 0 : 1}'; then
  fail 28 "certified tree contains a symlink; refusing materialization"
fi
if git -C "$repo_root" ls-tree -r "$WINDEEP_ETN_SOURCE_TREE_SHA" | awk '$1 == "160000" {found=1} END {exit found ? 0 : 1}'; then
  fail 32 "certified materialized tree contains an unexpected gitlink"
fi

WINDEEP_ETN_TARGET_BASE="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-electroneum-tree.XXXXXXXX")" ||   fail 27 "unable to create scratch directory"
source_dir="$WINDEEP_ETN_TARGET_BASE/source"
mkdir -p "$source_dir"

git -C "$repo_root" archive --format=tar "$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT:$WINDEEP_ETN_SOURCE_REL" | tar -xf - -C "$source_dir" || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 29 "failed to materialize certified Git tree"
}

# Git does not store empty directories. The historical GitHub ZIP represented
# the two upstream gitlinks as empty directories. Recreate only those empty
# structural placeholders so legacy/new audit inputs are path-equivalent; do
# not initialize or fetch submodule content.
mkdir -p "$source_dir/tests/evm-benchmarks" "$source_dir/tests/testdata"

[[ -f "$source_dir/go.mod" ]] || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 30 "certified materialization is missing go.mod"
}

file_count="$(find "$source_dir" -type f | wc -l | tr -d ' ')"
[[ "$file_count" == "$WINDEEP_ETN_EXPECTED_FILE_COUNT" ]] || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 31 "materialized file-count sanity check failed: expected $WINDEEP_ETN_EXPECTED_FILE_COUNT got $file_count"
}

find "$source_dir" -type f -exec chmod a-w {} +
find "$source_dir" -type d -exec chmod a-w {} +

export WINDEEP_ETN_SOURCE="$source_dir"
export WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT
export WINDEEP_ETN_SOURCE_TREE_SHA
export WINDEEP_ETN_PINNED_SOURCE_COMMIT
export WINDEEP_ETN_UPSTREAM_ROOT_TREE_SHA
export WINDEEP_ETN_ARCHIVE_SHA256

cat > "$WINDEEP_ETN_TARGET_BASE/target.env" <<EOF
WINDEEP_ETN_SOURCE=$WINDEEP_ETN_SOURCE
WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT=$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT
WINDEEP_ETN_SOURCE_TREE_SHA=$WINDEEP_ETN_SOURCE_TREE_SHA
WINDEEP_ETN_PINNED_SOURCE_COMMIT=$WINDEEP_ETN_PINNED_SOURCE_COMMIT
WINDEEP_ETN_UPSTREAM_ROOT_TREE_SHA=$WINDEEP_ETN_UPSTREAM_ROOT_TREE_SHA
WINDEEP_ETN_ARCHIVE_SHA256=$WINDEEP_ETN_ARCHIVE_SHA256
EOF

if [[ -n "${GITHUB_ENV:-}" ]]; then
  cat "$WINDEEP_ETN_TARGET_BASE/target.env" >> "$GITHUB_ENV"
fi

echo "target-bootstrap: certified_source_commit=$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT"
echo "target-bootstrap: tree_sha=$WINDEEP_ETN_SOURCE_TREE_SHA"
echo "target-bootstrap: upstream_source_commit=$WINDEEP_ETN_PINNED_SOURCE_COMMIT"
echo "target-bootstrap: archive_sha256_provenance=$WINDEEP_ETN_ARCHIVE_SHA256"
echo "target-bootstrap: source=$WINDEEP_ETN_SOURCE"
echo "target-bootstrap: files=$file_count"
