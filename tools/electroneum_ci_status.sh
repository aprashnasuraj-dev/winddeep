#!/usr/bin/env bash
# GitHub Actions -> connected GitHub commit-status lookup for hourly auditors.
# Minimal scoped credential, no repository writes, no artifact quota usage.
set -euo pipefail
class="${1:?class A..E required}"
phase="${2:?start or finish required}"
case "$class" in A|B|C|D|E) ;; *) echo "invalid audit class" >&2; exit 64;; esac
: "${GITHUB_API_URL:?}"
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_SHA:?}"
: "${GITHUB_RUN_ID:?}"
: "${GH_TOKEN:?}"
url="https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
context="security-audit/$class"
case "$phase" in
  start)
    state="pending"
    description="Class $class certified CI running (run $GITHUB_RUN_ID)"
    ;;
  finish)
    case "${JOB_RESULT:-unknown}" in
      success) state="success" ;;
      failure) state="failure" ;;
      cancelled) state="error" ;;
      *) state="error" ;;
    esac
    description="Class $class CI finished: ${JOB_RESULT:-unknown} (run $GITHUB_RUN_ID)"
    ;;
  *) echo "invalid phase" >&2; exit 64 ;;
esac
payload="$(python3 - "$state" "$context" "$url" "$description" <<'PY'
import json, sys
print(json.dumps(dict(state=sys.argv[1], context=sys.argv[2], target_url=sys.argv[3], description=sys.argv[4])))
PY
)"
status="$(curl -sS -L -o /dev/null -w '%{http_code}' --retry 2 \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  -X POST "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/statuses/$GITHUB_SHA" \
  -d "$payload")"
if [[ "$status" != "201" ]]; then
  echo "audit status publication HTTP $status, class=$class phase=$phase" >&2
  exit 1
fi
echo "AUDIT_STATUS_PUBLISHED class=$class phase=$phase state=$state sha=$GITHUB_SHA run=$GITHUB_RUN_ID"
