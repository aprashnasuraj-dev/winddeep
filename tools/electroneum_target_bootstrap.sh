#!/usr/bin/env bash
# Shared Electroneum audit target bootstrap for Workers A-E.
# Routine runs trust the certified Git subtree. The historical ZIP is
# provenance evidence only and is never extracted or re-hashed here.
set -euo pipefail

WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT="7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
WINDEEP_ETN_SOURCE_TREE_SHA="de7f3c75a2db7e87a89918f1257820703d5b731e"
WINDEEP_ETN_SOURCE_REL="vendor/electroneum-sc"
WINDEEP_ETN_PINNED_SOURCE_COMMIT="3aeb14db0d6384243302f3a025bdff904dc28bf6"
WINDEEP_ETN_ARCHIVE_SHA256="3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
WINDEEP_ETN_TRACKED_BLOB_COUNT="1921"
WINDEEP_ETN_TARGET_BASE=""

fail() {
  local code="$1"; shift
  echo "target-bootstrap: $*" >&2
  return "$code" 2>/dev/null || exit "$code"
}

for cmd in git tar mktemp mkdir chmod; do
  command -v "$cmd" >/dev/null 2>&1 || fail 20 "missing required command: $cmd"
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail 21 "must run from inside a Windeep Git checkout"

# HEAD must still carry the exact certified subtree. This is an object-identity
# check; it does not hash every file in the mutable checkout.
actual_tree="$(git -C "$repo_root" rev-parse "HEAD:$WINDEEP_ETN_SOURCE_REL" 2>/dev/null)" || \
  fail 22 "certified source path is absent from current audit branch: $WINDEEP_ETN_SOURCE_REL"
[[ "$actual_tree" == "$WINDEEP_ETN_SOURCE_TREE_SHA" ]] || \
  fail 24 "source tree mismatch: expected $WINDEEP_ETN_SOURCE_TREE_SHA got $actual_tree"

tree_type="$(git -C "$repo_root" cat-file -t "$WINDEEP_ETN_SOURCE_TREE_SHA" 2>/dev/null)" || \
  fail 23 "certified tree object is unavailable: $WINDEEP_ETN_SOURCE_TREE_SHA"
[[ "$tree_type" == "tree" ]] || fail 23 "certified object is not a Git tree: $WINDEEP_ETN_SOURCE_TREE_SHA"

WINDEEP_ETN_TARGET_BASE="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-electroneum-tree.XXXXXXXX")" || \
  fail 27 "unable to create scratch directory"
source_dir="$WINDEEP_ETN_TARGET_BASE/source"
mkdir -p "$source_dir"

# Materialize from the certified tree object itself, never from mutable
# worktree bytes. Dirty files or symlinks in vendor/electroneum-sc therefore
# cannot contaminate the audit input.
git -C "$repo_root" archive --format=tar "$WINDEEP_ETN_SOURCE_TREE_SHA" | tar -xf - -C "$source_dir" || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 29 "failed to materialize certified Git tree"
}

[[ -f "$source_dir/go.mod" && ! -L "$source_dir/go.mod" ]] || {
  rm -rf "$WINDEEP_ETN_TARGET_BASE"
  fail 30 "certified materialization is missing a regular go.mod"
}

# Defense in depth: prevent ordinary worker code from mutating audit input.
chmod -R a-w "$source_dir"

export WINDEEP_ETN_SOURCE="$source_dir"
export WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT
export WINDEEP_ETN_SOURCE_TREE_SHA
export WINDEEP_ETN_PINNED_SOURCE_COMMIT
export WINDEEP_ETN_ARCHIVE_SHA256
export WINDEEP_ETN_TRACKED_BLOB_COUNT
export WINDEEP_ETN_TARGET_BASE

cat > "$WINDEEP_ETN_TARGET_BASE/target.env" <<EOF
WINDEEP_ETN_SOURCE=$WINDEEP_ETN_SOURCE
WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT=$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT
WINDEEP_ETN_SOURCE_TREE_SHA=$WINDEEP_ETN_SOURCE_TREE_SHA
WINDEEP_ETN_PINNED_SOURCE_COMMIT=$WINDEEP_ETN_PINNED_SOURCE_COMMIT
WINDEEP_ETN_ARCHIVE_SHA256=$WINDEEP_ETN_ARCHIVE_SHA256
WINDEEP_ETN_TRACKED_BLOB_COUNT=$WINDEEP_ETN_TRACKED_BLOB_COUNT
EOF

if [[ -n "${GITHUB_ENV:-}" ]]; then
  cat "$WINDEEP_ETN_TARGET_BASE/target.env" >> "$GITHUB_ENV"
fi

echo "target-bootstrap: certified_source_commit=$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT"
echo "target-bootstrap: tree_sha=$WINDEEP_ETN_SOURCE_TREE_SHA"
echo "target-bootstrap: upstream_source_commit=$WINDEEP_ETN_PINNED_SOURCE_COMMIT"
echo "target-bootstrap: archive_sha256_provenance=$WINDEEP_ETN_ARCHIVE_SHA256"
echo "target-bootstrap: tracked_blobs=$WINDEEP_ETN_TRACKED_BLOB_COUNT"
echo "target-bootstrap: source=$WINDEEP_ETN_SOURCE"
