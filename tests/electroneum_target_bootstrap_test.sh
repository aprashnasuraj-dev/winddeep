#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
BOOT="$ROOT/tools/electroneum_target_bootstrap.sh"
EXPECTED_TREE="de7f3c75a2db7e87a89918f1257820703d5b731e"
EXPECTED_SOURCE_COMMIT="7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
EXPECTED_UPSTREAM="3aeb14db0d6384243302f3a025bdff904dc28bf6"
EXPECTED_ARCHIVE_SHA256="3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
TMP="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-etn-bootstrap-test.XXXXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

pass() { printf 'PASS: %s\n' "$1"; }
fail_test() { printf 'FAIL: %s\n' "$1" >&2; exit 90; }

run_expect_rc() {
  local label="$1" expected="$2" repo="$3" script="$4"
  local log="$TMP/${label// /_}.log"
  set +e
  (cd "$repo" && source "$script") >"$log" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" != "$expected" ]]; then
    cat "$log" >&2
    fail_test "$label expected rc=$expected got rc=$rc"
  fi
  pass "$label (rc=$rc)"
}

# Certificate and immutable commit/tree relationship.
python - "$ROOT/reports/electroneum/TARGET_CERTIFICATE.json" <<'PY'
import json, sys
c=json.load(open(sys.argv[1], encoding="utf-8"))
assert c["schema"] == 2
assert c["windeep_source_commit"] == "7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
assert c["git_tree_sha"] == "de7f3c75a2db7e87a89918f1257820703d5b731e"
assert c["tracked_blob_count"] == 1921
assert c["upstream_source_commit"] == "3aeb14db0d6384243302f3a025bdff904dc28bf6"
assert c["archive_sha256"] == "3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
assert c["symlinks_allowed"] is False
PY
[[ "$(git -C "$ROOT" rev-parse "$EXPECTED_SOURCE_COMMIT:vendor/electroneum-sc")" == "$EXPECTED_TREE" ]] || fail_test "immutable source commit/tree relation"
[[ "$(git -C "$ROOT" rev-parse "HEAD:vendor/electroneum-sc")" == "$EXPECTED_TREE" ]] || fail_test "HEAD certified tree relation"
pass "certificate and immutable source identity"

# Positive: valid tree materializes and is read-only.
source "$BOOT"
CLEAN_SOURCE="$WINDEEP_ETN_SOURCE"
[[ "$WINDEEP_ETN_SOURCE_TREE_SHA" == "$EXPECTED_TREE" ]] || fail_test "positive tree env"
[[ "$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT" == "$EXPECTED_SOURCE_COMMIT" ]] || fail_test "positive source commit env"
[[ "$WINDEEP_ETN_PINNED_SOURCE_COMMIT" == "$EXPECTED_UPSTREAM" ]] || fail_test "positive upstream env"
[[ "$WINDEEP_ETN_ARCHIVE_SHA256" == "$EXPECTED_ARCHIVE_SHA256" ]] || fail_test "positive archive env"
[[ -f "$CLEAN_SOURCE/go.mod" && ! -L "$CLEAN_SOURCE/go.mod" ]] || fail_test "positive go.mod"
if find "$CLEAN_SOURCE" -perm /222 -print -quit | grep -q .; then
  fail_test "materialized source contains writable paths"
fi
pass "valid certified source"

# Negative: wrong pinned tree SHA must fail closed with rc 24.
WRONG_BOOT="$TMP/wrong-tree.sh"
sed "s/$EXPECTED_TREE/0000000000000000000000000000000000000000/g" "$BOOT" > "$WRONG_BOOT"
chmod +x "$WRONG_BOOT"
run_expect_rc "wrong tree SHA" 24 "$ROOT" "$WRONG_BOOT"

# Modified checkout: dirty worktree bytes must never contaminate materialization.
git clone -q --no-hardlinks "$ROOT" "$TMP/dirty"
DIRTY_FILE="$TMP/dirty/vendor/electroneum-sc/core/state/statedb.go"
printf '\n// WINDEEP_DIRTY_CHECKOUT_SENTINEL\n' >> "$DIRTY_FILE"
(
  cd "$TMP/dirty"
  source tools/electroneum_target_bootstrap.sh
  printf '%s\n' "$WINDEEP_ETN_SOURCE" > "$TMP/dirty-source-path"
)
DIRTY_SOURCE="$(cat "$TMP/dirty-source-path")"
if grep -q 'WINDEEP_DIRTY_CHECKOUT_SENTINEL' "$DIRTY_SOURCE/core/state/statedb.go"; then
  fail_test "modified checkout contaminated certified source"
fi
pass "modified checkout cannot contaminate certified materialization"

# Negative: expected tree entry exists in commit metadata but object is absent.
git init -q "$TMP/missing-object"
git -C "$TMP/missing-object" config user.name test
git -C "$TMP/missing-object" config user.email test@example.invalid
vendor_tree="$(printf '040000 tree %s\telectroneum-sc\n' "$EXPECTED_TREE" | git -C "$TMP/missing-object" mktree --missing)"
root_tree="$(printf '040000 tree %s\tvendor\n' "$vendor_tree" | git -C "$TMP/missing-object" mktree)"
missing_commit="$(printf 'missing-object\n' | git -C "$TMP/missing-object" commit-tree "$root_tree")"
git -C "$TMP/missing-object" update-ref refs/heads/master "$missing_commit"
run_expect_rc "missing Git tree object" 23 "$TMP/missing-object" "$BOOT"

# Malicious symlink in mutable checkout is ignored; once committed it changes
# the subtree identity and the bootstrap must reject it with rc 24.
git clone -q --no-hardlinks "$ROOT" "$TMP/symlink"
rm "$TMP/symlink/vendor/electroneum-sc/go.mod"
ln -s /etc/passwd "$TMP/symlink/vendor/electroneum-sc/go.mod"
(
  cd "$TMP/symlink"
  source tools/electroneum_target_bootstrap.sh
  printf '%s\n' "$WINDEEP_ETN_SOURCE" > "$TMP/symlink-source-path"
)
SYMLINK_SOURCE="$(cat "$TMP/symlink-source-path")"
[[ -f "$SYMLINK_SOURCE/go.mod" && ! -L "$SYMLINK_SOURCE/go.mod" ]] || fail_test "worktree symlink contaminated materialization"
git -C "$TMP/symlink" config user.name test
git -C "$TMP/symlink" config user.email test@example.invalid
git -C "$TMP/symlink" add -f vendor/electroneum-sc/go.mod
git -C "$TMP/symlink" commit -qm "malicious symlink fixture"
run_expect_rc "committed malicious symlink" 24 "$TMP/symlink" "$TMP/symlink/tools/electroneum_target_bootstrap.sh"

# Migration gate: old ZIP extraction and new Git-tree materialization must have
# exactly the same 1,921 file paths and bytes (excluding .git metadata).
archive="$ROOT/electroneum-sc-master.zip"
actual_archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
[[ "$actual_archive_sha" == "$EXPECTED_ARCHIVE_SHA256" ]] || fail_test "archive provenance SHA-256"
mkdir -p "$TMP/legacy"
unzip -q "$archive" -d "$TMP/legacy"
mapfile -t roots < <(find "$TMP/legacy" -mindepth 2 -maxdepth 3 -type f -name go.mod -printf '%h\n' | sort -u)
[[ "${#roots[@]}" -eq 1 ]] || fail_test "legacy extraction root count"
LEGACY_SOURCE="${roots[0]}"
python - "$LEGACY_SOURCE" "$CLEAN_SOURCE" <<'PY'
import hashlib, os, sys

def file_map(root):
    out={}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            p=os.path.join(base,name)
            if os.path.islink(p):
                raise AssertionError(f"symlink in source: {p}")
            rel=os.path.relpath(p,root).replace(os.sep,"/")
            h=hashlib.sha256()
            with open(p,"rb") as f:
                for chunk in iter(lambda:f.read(1024*1024), b""):
                    h.update(chunk)
            out[rel]=h.hexdigest()
    return out

legacy=file_map(sys.argv[1])
cert=file_map(sys.argv[2])
assert len(legacy)==1921, len(legacy)
assert len(cert)==1921, len(cert)
assert legacy==cert, (
    sorted(set(legacy)-set(cert))[:10],
    sorted(set(cert)-set(legacy))[:10],
    [p for p in legacy.keys() & cert.keys() if legacy[p]!=cert[p]][:10],
)
print("equivalence: 1921/1921 paths and SHA-256 file contents match")
PY
pass "legacy ZIP extraction equals certified Git-tree source"

printf 'ALL ELECTRONEUM TARGET BOOTSTRAP TESTS PASSED\n'
