#!/usr/bin/env bash
# One-command, isolated reproducer for the conditional downloader stale-slot bug.
# Usage: bash 04_REPRODUCE_EXACT.sh /path/to/electroneum-sc [/path/to/log-output]
# Requirements: Bash, Go 1.24, Python 3, local dependencies/network for Go modules.
# This script does NOT alter the input Electroneum source checkout.
set -euo pipefail

here="$(cd -- "$(dirname -- "$0")" && pwd)"
src=""
if [[ "$#" -ge 1 ]]; then src="$1"; fi
if [[ -z "$src" || ! -f "$src/go.mod" || ! -f "$src/eth/downloader/queue.go" ]]; then
  echo "Usage: bash 04_REPRODUCE_EXACT.sh /absolute/path/to/electroneum-sc [output-logs-dir]" >&2
  exit 64
fi
for file in 01_downloader_stale_slot_test.go 02_base_receipt_fixture_test.go 03_scratch_guard.py; do
  if [[ ! -f "$here/$file" ]]; then echo "Missing bundled file: $file" >&2; exit 65; fi
done
for tool in go python3 sha256sum; do
  if ! command -v "$tool" >/dev/null; then echo "Missing tool: $tool" >&2; exit 66; fi
done
src="$(cd "$src" && pwd)"
out="$PWD/Downloader_StaleSlot_Reproduction_Logs"
if [[ "$#" -ge 2 ]]; then out="$2"; fi
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
scratch="$tmp/staleslot-scratch"
mkdir -p "$scratch"
cp -a "$src"/. "$scratch"/
chmod u+w "$scratch/eth/downloader" "$scratch/eth/downloader/queue.go"
cp "$here/01_downloader_stale_slot_test.go" "$scratch/eth/downloader/worker_d_staleslot_test.go"
cp "$here/02_base_receipt_fixture_test.go" "$scratch/eth/downloader/worker_d_receipt_fixture_test.go"
original_sha="$(sha256sum "$src/eth/downloader/queue.go" | awk '{print $1}')"
printf 'Target source: %s\n' "$src"
printf 'Go toolchain: %s\n' "$(go version)"
printf 'Evidence logs: %s\n' "$out"
cd "$scratch"

go test -count=1 -timeout=10m -run '^TestDStaleSlotSafeControls$' -v ./eth/downloader 2>&1 | tee "$out/01_safe_controls.log"
grep -Fq 'STALE_SLOT_BASELINE_VALID_DELIVERY_PASS accepted=3' "$out/01_safe_controls.log"
grep -Fq 'STALE_SLOT_RESYNC_RESET_BLOCKS_STALE_RESPONSE_PASS accepted=0' "$out/01_safe_controls.log"
grep -Fq 'STALE_SLOT_BAD_RECEIPT_ROOT_REJECTED_PASS' "$out/01_safe_controls.log"

go test -count=1 -timeout=10m -run '^TestDStaleSlotConditionalPanic$' -v ./eth/downloader 2>&1 | tee "$out/02_target_panic.log"
grep -Fq 'STALE_SLOT_PRECONDITION_VERIFIED' "$out/02_target_panic.log"
grep -Fq 'STALE_SLOT_TARGET_PANIC_OBSERVED' "$out/02_target_panic.log"

set +e
go test -count=1 -timeout=10m -run '^TestDStaleSlotFailClosedOracle$' -v ./eth/downloader > "$out/03_original_failing_oracle.log" 2>&1
original_rc=$?
set -e
cat "$out/03_original_failing_oracle.log"
if [[ "$original_rc" -eq 0 ]]; then echo 'ERROR: original strict oracle unexpectedly passed' >&2; exit 67; fi
grep -Fq 'STALE_SLOT_FAIL_CLOSED_ORACLE_PANIC' "$out/03_original_failing_oracle.log"

python3 "$here/03_scratch_guard.py" "$scratch/eth/downloader/queue.go"
go test -count=1 -timeout=10m -run '^(TestDStaleSlotFailClosedOracle|TestDStaleSlotSafeControls)$' -v ./eth/downloader 2>&1 | tee "$out/04_guard_oracle.log"
grep -Fq 'STALE_SLOT_FAIL_CLOSED_ORACLE_PASS accepted=0 structured_error=true' "$out/04_guard_oracle.log"
final_sha="$(sha256sum "$src/eth/downloader/queue.go" | awk '{print $1}')"
if [[ "$final_sha" != "$original_sha" ]]; then echo 'ERROR: original queue.go changed' >&2; exit 68; fi

printf '%s\n' 'PASS: valid receipt, same-offset, reset-before-prepare, and invalid-root controls.'
printf '%s\n' 'PASS: nil-pointer panic on original source under forced pending/Prepare overlap.'
printf '%s\n' 'PASS: original strict oracle fails as expected; scratch-only guard succeeds.'
printf '%s\n' 'IMPORTANT: no external peer-triggered Prepare overlap or network outage has been established.'
