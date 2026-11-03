#!/usr/bin/env bash
# Shared Electroneum audit target bootstrap.
# Source this file from A-E workers so WINDEEP_ETN_SOURCE remains in the shell.
set -euo pipefail

WINDEEP_ETN_ARCHIVE_COMMIT="7d93d2435750ef258445f4a57142bb7b43a644f4"
WINDEEP_ETN_ARCHIVE_PATH="electroneum-sc-master.zip"
WINDEEP_ETN_ARCHIVE_BLOB_SHA1="581c984e3e0d6451bc6273c19edf1bdb78dfed0a"
WINDEEP_ETN_EXPECTED_SHA256="3ca62ab9c6951ea26cb13615d67255940e176522126f2ca7a157bf4035329d7b"
WINDEEP_ETN_PINNED_SOURCE_COMMIT="3aeb14db0d6384243302f3a025bdff904dc28bf6"
WINDEEP_ETN_TARGET_BASE=""

command -v git >/dev/null 2>&1 || { echo "target-bootstrap: git is required" >&2; return 20 2>/dev/null || exit 20; }
command -v unzip >/dev/null 2>&1 || { echo "target-bootstrap: unzip is required" >&2; return 21 2>/dev/null || exit 21; }
command -v mktemp >/dev/null 2>&1 || { echo "target-bootstrap: mktemp is required" >&2; return 26 2>/dev/null || exit 26; }

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "target-bootstrap: must run from inside a Windeep Git checkout" >&2
  return 27 2>/dev/null || exit 27
}

WINDEEP_ETN_TARGET_BASE="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/windeep-electroneum-target.XXXXXXXX")"
archive="${WINDEEP_ETN_TARGET_BASE}/electroneum-sc-master.zip"
extract_dir="${WINDEEP_ETN_TARGET_BASE}/extract"
stable_source="${WINDEEP_ETN_TARGET_BASE}/current"
branch_archive="${repo_root}/${WINDEEP_ETN_ARCHIVE_PATH}"
archive_origin=""

# Fast path: the canonical archive is intentionally retained at audit-branch HEAD.
# This avoids requiring the historical archive commit to be present in shallow
# checkouts while still pinning both the Git blob identity and the stronger
# SHA-256 certificate.
if [[ -f "${branch_archive}" ]]; then
  index_blob="$(git -C "${repo_root}" ls-files -s -- "${WINDEEP_ETN_ARCHIVE_PATH}" | awk 'NR==1 {print $2}')"
  if [[ -z "${index_blob}" ]]; then
    echo "target-bootstrap: branch-local archive exists but is not tracked: ${WINDEEP_ETN_ARCHIVE_PATH}" >&2
    return 28 2>/dev/null || exit 28
  fi
  if [[ "${index_blob}" != "${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}" ]]; then
    echo "target-bootstrap: branch-local archive Git blob mismatch: expected ${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}, got ${index_blob}" >&2
    return 28 2>/dev/null || exit 28
  fi
  worktree_blob="$(git -C "${repo_root}" hash-object "${branch_archive}")"
  if [[ "${worktree_blob}" != "${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}" ]]; then
    echo "target-bootstrap: branch-local archive worktree content differs from certified Git blob: expected ${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}, got ${worktree_blob}" >&2
    return 28 2>/dev/null || exit 28
  fi
  cp "${branch_archive}" "${archive}"
  archive_origin="branch-head"
else
  # Compatibility fallback for older/full checkouts that still contain the
  # historical archive object but not the archive at branch HEAD.
  git -C "${repo_root}" cat-file -e "${WINDEEP_ETN_ARCHIVE_COMMIT}:${WINDEEP_ETN_ARCHIVE_PATH}" 2>/dev/null || {
    echo "target-bootstrap: canonical archive unavailable at branch HEAD and historical object ${WINDEEP_ETN_ARCHIVE_COMMIT}:${WINDEEP_ETN_ARCHIVE_PATH} is absent" >&2
    return 22 2>/dev/null || exit 22
  }
  historical_blob="$(git -C "${repo_root}" rev-parse "${WINDEEP_ETN_ARCHIVE_COMMIT}:${WINDEEP_ETN_ARCHIVE_PATH}")"
  if [[ "${historical_blob}" != "${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}" ]]; then
    echo "target-bootstrap: historical archive Git blob mismatch: expected ${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}, got ${historical_blob}" >&2
    return 29 2>/dev/null || exit 29
  fi
  git -C "${repo_root}" show "${WINDEEP_ETN_ARCHIVE_COMMIT}:${WINDEEP_ETN_ARCHIVE_PATH}" > "${archive}"
  archive_origin="historical-object"
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha="$(sha256sum "${archive}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_sha="$(shasum -a 256 "${archive}" | awk '{print $1}')"
else
  echo "target-bootstrap: sha256sum or shasum is required" >&2
  return 23 2>/dev/null || exit 23
fi

if [[ "${actual_sha}" != "${WINDEEP_ETN_EXPECTED_SHA256}" ]]; then
  echo "target-bootstrap: SHA-256 mismatch: expected ${WINDEEP_ETN_EXPECTED_SHA256}, got ${actual_sha}" >&2
  return 24 2>/dev/null || exit 24
fi

mkdir -p "${extract_dir}"
unzip -q "${archive}" -d "${extract_dir}"

go_mod="$(find "${extract_dir}" -mindepth 1 -maxdepth 4 -type f -name go.mod -print -quit)"
if [[ -z "${go_mod}" ]]; then
  echo "target-bootstrap: extracted archive contains no go.mod within expected depth" >&2
  return 25 2>/dev/null || exit 25
fi
source_root="$(dirname "${go_mod}")"
ln -s "${source_root}" "${stable_source}"

export WINDEEP_ETN_SOURCE="${stable_source}"
export WINDEEP_ETN_ARCHIVE="${archive}"
export WINDEEP_ETN_ARCHIVE_SHA256="${actual_sha}"
export WINDEEP_ETN_ARCHIVE_GIT_BLOB_SHA1="${WINDEEP_ETN_ARCHIVE_BLOB_SHA1}"
export WINDEEP_ETN_ARCHIVE_ORIGIN="${archive_origin}"
export WINDEEP_ETN_PINNED_SOURCE_COMMIT

cat > "${WINDEEP_ETN_TARGET_BASE}/target.env" <<EOF
WINDEEP_ETN_SOURCE=${WINDEEP_ETN_SOURCE}
WINDEEP_ETN_ARCHIVE=${WINDEEP_ETN_ARCHIVE}
WINDEEP_ETN_ARCHIVE_SHA256=${WINDEEP_ETN_ARCHIVE_SHA256}
WINDEEP_ETN_ARCHIVE_GIT_BLOB_SHA1=${WINDEEP_ETN_ARCHIVE_GIT_BLOB_SHA1}
WINDEEP_ETN_ARCHIVE_ORIGIN=${WINDEEP_ETN_ARCHIVE_ORIGIN}
WINDEEP_ETN_PINNED_SOURCE_COMMIT=${WINDEEP_ETN_PINNED_SOURCE_COMMIT}
EOF

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "WINDEEP_ETN_SOURCE=${WINDEEP_ETN_SOURCE}"
    echo "WINDEEP_ETN_ARCHIVE=${WINDEEP_ETN_ARCHIVE}"
    echo "WINDEEP_ETN_ARCHIVE_SHA256=${WINDEEP_ETN_ARCHIVE_SHA256}"
    echo "WINDEEP_ETN_ARCHIVE_GIT_BLOB_SHA1=${WINDEEP_ETN_ARCHIVE_GIT_BLOB_SHA1}"
    echo "WINDEEP_ETN_ARCHIVE_ORIGIN=${WINDEEP_ETN_ARCHIVE_ORIGIN}"
    echo "WINDEEP_ETN_PINNED_SOURCE_COMMIT=${WINDEEP_ETN_PINNED_SOURCE_COMMIT}"
  } >> "${GITHUB_ENV}"
fi

file_count="$(find -L "${WINDEEP_ETN_SOURCE}" -type f | wc -l | tr -d ' ')"
echo "target-bootstrap: archive_origin=${WINDEEP_ETN_ARCHIVE_ORIGIN}"
echo "target-bootstrap: archive_git_blob_sha1=${WINDEEP_ETN_ARCHIVE_GIT_BLOB_SHA1}"
echo "target-bootstrap: verified_sha256=${WINDEEP_ETN_ARCHIVE_SHA256}"
echo "target-bootstrap: pinned_source_commit=${WINDEEP_ETN_PINNED_SOURCE_COMMIT}"
echo "target-bootstrap: source=${WINDEEP_ETN_SOURCE}"
echo "target-bootstrap: files=${file_count}"
