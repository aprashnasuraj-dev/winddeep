#!/usr/bin/env bash
# Shared Electroneum audit target bootstrap.
# Source from A-E workers. The ZIP is provenance evidence only; continuous
# runs trust the certified Git subtree and materialize fresh read-only bytes.
set -euo pipefail

WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT="21162f549d95e4117bb954426cba436262ef4b2f"
WINDEEP_ETN_SOURCE_TREE_SHA="3571f9f8e31ca3f2e85c2a32acbc002bc3a177cc"
WINDEEP_ETN_SOURCE_REL="vendor/electroneum-sc"
WINDEEP_ETN_PINNED_SOURCE_COMMIT="3aeb14db0d6384243302f3a025bdff904dc28bf6"
WINDEEP_ETN_ARCHIVE_SHA256="3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
WINDEEP_ETN_EXPECTED_FILE_COUNT="1921"
WINDEEP_ETN_TARGET_BASE=""

fail() {
  local code="$1"; shift
  echo "target-bootstrap: $*" >&2
  return "$code" 2>/dev/null || exit "$code"
}

for cmd in git tar mktemp find chmod; do
  command -v "$cmd" >/dev/null 2>&1 || fail 20 "missing required command: $cmd"
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail 21 "must run from inside a Windeep Git checkout"

actual_tree="$(git -C "$repo_root" rev-parse "HEAD:$WINDEEP_ETN_SOURCE_REL" 2>/dev/null)" || \
  fail 22 "certified source path is absent from current audit branch: $WINDEEP_ETN_SOURCE_REL"

[[ "$actual_tree" == "$WINDEEP_ETN_SOURCE_TREE_SHA" ]] || \
  fail 24 "source tree mismatch: expected $WINDEEP_ETN_SOURCE_TREE_SHA got $actual_tree"

tree_type="$(git -C "$repo_root" cat-file -t "$actual_tree" 2>/dev/null)" || \
  fail 23 "certified tree object is unavailable: $actual_tree"
[[ "$tree_type" == "tree" ]] || fail 23 "certified object is not a Git tree: $actual_tree"

if git -C "$repo_root" ls-tree -r "$actual_tree" | awk '$1 == "120000" {found=1} END {exit found ? 0 : 1}'; then
  fail 28 "certified tree contains a symlink; refusing materialization"
fi

WINDEEP_ETN_TARGET_BASE="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-electroneum-tree.XXXXXXXX")" || \
  fail 27 "unable to create scratch directory"
source_dir="$WINDEEP_ETN_TARGET_BASE/source"
mkdir -p "$source_dir"

git -C "$repo_root" archive --format=tar "HEAD:$WINDEEP_ETN_SOURCE_REL" | tar -xf - -C "$source_dir" || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 29 "failed to materialize certified Git tree"
}

[[ -f "$source_dir/go.mod" ]] || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 30 "certified materialization is missing go.mod"
}

file_count="$(find "$source_dir" -type f | wc -l | tr -d ' ')"
[[ "$file_count" == "$WINDEEP_ETN_EXPECTED_FILE_COUNT" ]] || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 31 "materialized file-count sanity check failed: expected $WINDEEP_ETN_EXPECTED_FILE_COUNT got $file_count"
}

# Defense in depth. The trust check is the Git tree SHA above; this prevents
# ordinary worker code from accidentally mutating its audit input afterward.
find "$source_dir" -type f -exec chmod a-w {} +
find "$source_dir" -type d -exec chmod a-w {} +

export WINDEEP_ETN_SOURCE="$source_dir"
export WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT
export WINDEEP_ETN_SOURCE_TREE_SHA
export WINDEEP_ETN_PINNED_SOURCE_COMMIT
export WINDEEP_ETN_ARCHIVE_SHA256

cat > "$WINDEEP_ETN_TARGET_BASE/target.env" <<EOF
WINDEEP_ETN_SOURCE=$WINDEEP_ETN_SOURCE
WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT=$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT
WINDEEP_ETN_SOURCE_TREE_SHA=$WINDEEP_ETN_SOURCE_TREE_SHA
WINDEEP_ETN_PINNED_SOURCE_COMMIT=$WINDEEP_ETN_PINNED_SOURCE_COMMIT
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
