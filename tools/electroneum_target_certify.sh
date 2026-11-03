#!/usr/bin/env bash
# One-time certification helper for the canonical Electroneum audit source.
# Continuous workers MUST use the lightweight bootstrap after certification.
set -euo pipefail

WINDEEP_ETN_ARCHIVE_PATH="electroneum-sc-master.zip"
WINDEEP_ETN_ARCHIVE_BLOB_SHA1="581c984e3e0d6451bc6273c19edf1bdb78dfed0a"
WINDEEP_ETN_ARCHIVE_SHA256="3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
WINDEEP_ETN_UPSTREAM_COMMIT="3aeb14db0d6384243302f3a025bdff904dc28bf6"
WINDEEP_ETN_EXPECTED_FILE_COUNT="1921"
WINDEEP_ETN_VENDOR_PATH="vendor/electroneum-sc"

for cmd in git unzip sha256sum find diff cp; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "target-certify: missing required command: $cmd" >&2; exit 40; }
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "target-certify: must run inside the Windeep checkout" >&2
  exit 41
}
cd "$repo_root"

archive="$repo_root/$WINDEEP_ETN_ARCHIVE_PATH"
[[ -f "$archive" ]] || { echo "target-certify: canonical archive missing: $WINDEEP_ETN_ARCHIVE_PATH" >&2; exit 42; }

index_blob="$(git ls-files -s -- "$WINDEEP_ETN_ARCHIVE_PATH" | awk 'NR==1 {print $2}')"
[[ "$index_blob" == "$WINDEEP_ETN_ARCHIVE_BLOB_SHA1" ]] || {
  echo "target-certify: archive Git blob mismatch: expected $WINDEEP_ETN_ARCHIVE_BLOB_SHA1 got ${index_blob:-<none>}" >&2
  exit 43
}
worktree_blob="$(git hash-object "$archive")"
[[ "$worktree_blob" == "$WINDEEP_ETN_ARCHIVE_BLOB_SHA1" ]] || {
  echo "target-certify: archive worktree differs from certified Git blob" >&2
  exit 44
}
actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
[[ "$actual_sha256" == "$WINDEEP_ETN_ARCHIVE_SHA256" ]] || {
  echo "target-certify: archive SHA-256 mismatch: expected $WINDEEP_ETN_ARCHIVE_SHA256 got $actual_sha256" >&2
  exit 45
}

scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-etn-certify.XXXXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/extract"
unzip -q "$archive" -d "$scratch/extract"

mapfile -t roots < <(find "$scratch/extract" -mindepth 2 -maxdepth 3 -type f -name go.mod -printf '%h\n' | sort -u)
[[ "${#roots[@]}" -eq 1 ]] || {
  echo "target-certify: expected exactly one source root with go.mod, found ${#roots[@]}" >&2
  exit 46
}
source_root="${roots[0]}"

bad_link="$(find "$source_root" -type l -print -quit)"
[[ -z "$bad_link" ]] || { echo "target-certify: symlink rejected: $bad_link" >&2; exit 47; }
bad_type="$(find "$source_root" ! -type f ! -type d -print -quit)"
[[ -z "$bad_type" ]] || { echo "target-certify: unsupported filesystem object rejected: $bad_type" >&2; exit 48; }
file_count="$(find "$source_root" -type f | wc -l | tr -d ' ')"
[[ "$file_count" == "$WINDEEP_ETN_EXPECTED_FILE_COUNT" ]] || {
  echo "target-certify: file count mismatch: expected $WINDEEP_ETN_EXPECTED_FILE_COUNT got $file_count" >&2
  exit 49
}

git init -q "$scratch/upstream"
git -C "$scratch/upstream" remote add origin https://github.com/electroneum/electroneum-sc.git
git -C "$scratch/upstream" -c advice.detachedHead=false fetch -q --depth=1 origin "$WINDEEP_ETN_UPSTREAM_COMMIT"
git -C "$scratch/upstream" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
upstream_link="$(find "$scratch/upstream" -path "$scratch/upstream/.git" -prune -o -type l -print -quit)"
[[ -z "$upstream_link" ]] || { echo "target-certify: upstream symlink rejected: $upstream_link" >&2; exit 50; }
if ! diff -qr --exclude=.git "$source_root" "$scratch/upstream" >"$scratch/diff.txt"; then
  echo "target-certify: archive content does not match pinned upstream commit $WINDEEP_ETN_UPSTREAM_COMMIT" >&2
  head -100 "$scratch/diff.txt" >&2
  exit 51
fi

rm -rf "$repo_root/$WINDEEP_ETN_VENDOR_PATH"
mkdir -p "$(dirname "$repo_root/$WINDEEP_ETN_VENDOR_PATH")"
cp -a "$source_root" "$repo_root/$WINDEEP_ETN_VENDOR_PATH"
rm -rf "$repo_root/$WINDEEP_ETN_VENDOR_PATH/.git"
[[ -z "$(find "$repo_root/$WINDEEP_ETN_VENDOR_PATH" -type l -print -quit)" ]] || {
  echo "target-certify: vendor copy unexpectedly contains a symlink" >&2
  exit 52
}

printf 'target-certify: archive_sha256=%s\n' "$actual_sha256"
printf 'target-certify: upstream_commit=%s\n' "$WINDEEP_ETN_UPSTREAM_COMMIT"
printf 'target-certify: files=%s\n' "$file_count"
printf 'target-certify: vendor_path=%s\n' "$WINDEEP_ETN_VENDOR_PATH"
