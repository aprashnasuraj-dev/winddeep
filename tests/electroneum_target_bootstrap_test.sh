#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
bootstrap="$repo_root/tools/electroneum_target_bootstrap.sh"
archive="$repo_root/electroneum-sc-master.zip"
source_commit="7eb84ee39bd01eaaf1f64afbd871b06c85ff3bb0"
source_tree="de7f3c75a2db7e87a89918f1257820703d5b731e"

for cmd in git unzip diff python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "bootstrap-test: missing command: $cmd" >&2; exit 90; }
done
[[ -f "$archive" ]] || { echo "bootstrap-test: missing provenance archive" >&2; exit 91; }

tmp="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-etn-bootstrap-test.XXXXXXXX")"
trap 'chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "$tmp"' EXIT

expect_fail() {
  local expected="$1" name="$2"; shift 2
  set +e
  "$@" >"$tmp/$name.out" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne "$expected" ]]; then
    echo "bootstrap-test: $name expected rc=$expected got rc=$rc" >&2
    cat "$tmp/$name.out" >&2 || true
    exit 92
  fi
  echo "bootstrap-test: $name PASS (rc=$rc)"
}

clone_full() {
  local dst="$1"
  git clone -q --no-hardlinks "$repo_root" "$dst"
  git -C "$dst" checkout -q --detach "$(git -C "$repo_root" rev-parse HEAD)"
  git -C "$dst" config user.name "bootstrap-test"
  git -C "$dst" config user.email "bootstrap-test@example.invalid"
}

(
  cd "$repo_root"
  source "$bootstrap"
  test "$WINDEEP_ETN_CERTIFIED_SOURCE_COMMIT" = "$source_commit"
  test "$WINDEEP_ETN_SOURCE_TREE_SHA" = "$source_tree"
  test -f "$WINDEEP_ETN_SOURCE/go.mod"

  mkdir -p "$tmp/legacy"
  unzip -q "$archive" -d "$tmp/legacy"
  mapfile -t roots < <(find "$tmp/legacy" -mindepth 2 -maxdepth 3 -type f -name go.mod -printf '%h\n' | sort -u)
  test "${#roots[@]}" -eq 1
  legacy_root="${roots[0]}"

  diff -qr "$legacy_root" "$WINDEEP_ETN_SOURCE"
  test "$(find "$legacy_root" -type f | wc -l | tr -d ' ')" = "1921"
  test "$(find "$WINDEEP_ETN_SOURCE" -type f | wc -l | tr -d ' ')" = "1921"
  echo "bootstrap-test: valid-source PASS"
  echo "bootstrap-test: legacy-vs-pinned equivalence PASS (1921/1921 files)"
)

clone_full "$tmp/dirty"
printf '\n# bootstrap negative control\n' >> "$tmp/dirty/vendor/electroneum-sc/go.mod"
expect_fail 25 modified-checkout bash -c "cd '$tmp/dirty' && bash tools/electroneum_target_bootstrap.sh"

clone_full "$tmp/wrong-tree"
printf '\n# committed negative control\n' >> "$tmp/wrong-tree/vendor/electroneum-sc/go.mod"
git -C "$tmp/wrong-tree" add vendor/electroneum-sc/go.mod
git -C "$tmp/wrong-tree" commit -q -m "test: wrong target tree"
expect_fail 24 wrong-tree-sha bash -c "cd '$tmp/wrong-tree' && bash tools/electroneum_target_bootstrap.sh"

git clone -q --depth=1 "file://$repo_root" "$tmp/missing-object"
if git -C "$tmp/missing-object" cat-file -e "$source_commit^{commit}" 2>/dev/null; then
  echo "bootstrap-test: shallow fixture unexpectedly contains certified source commit" >&2
  exit 93
fi
expect_fail 23 missing-git-object bash -c "cd '$tmp/missing-object' && bash tools/electroneum_target_bootstrap.sh"

clone_full "$tmp/symlink"
rm "$tmp/symlink/vendor/electroneum-sc/go.mod"
ln -s README.md "$tmp/symlink/vendor/electroneum-sc/go.mod"
git -C "$tmp/symlink" add -A vendor/electroneum-sc/go.mod
git -C "$tmp/symlink" commit -q -m "test: malicious symlink source"
mal_commit="$(git -C "$tmp/symlink" rev-parse HEAD)"
mal_tree="$(git -C "$tmp/symlink" rev-parse HEAD:vendor/electroneum-sc)"
python3 - "$tmp/symlink/reports/electroneum/TARGET_CERTIFICATE.json" "$mal_commit" "$mal_tree" <<'PY'
import json, sys
p, commit, tree = sys.argv[1:]
with open(p, encoding="utf-8") as fh:
    d = json.load(fh)
d["windeep_source_commit"] = commit
d["git_tree_sha"] = tree
with open(p, "w", encoding="utf-8") as fh:
    json.dump(d, fh, indent=2)
    fh.write("\n")
PY
git -C "$tmp/symlink" add reports/electroneum/TARGET_CERTIFICATE.json
git -C "$tmp/symlink" commit -q -m "test: align malicious fixture certificate"
python3 - "$tmp/symlink/tools/electroneum_target_bootstrap.sh" "$tmp/symlink/tools/bootstrap-malicious.sh" "$source_commit" "$source_tree" "$mal_commit" "$mal_tree" <<'PY'
import sys
src, dst, old_commit, old_tree, new_commit, new_tree = sys.argv[1:]
data = open(src, encoding="utf-8").read()
data = data.replace(old_commit, new_commit).replace(old_tree, new_tree)
open(dst, "w", encoding="utf-8").write(data)
PY
expect_fail 28 malicious-symlink bash -c "cd '$tmp/symlink' && bash tools/bootstrap-malicious.sh"

echo "bootstrap-test: ALL PASS"
