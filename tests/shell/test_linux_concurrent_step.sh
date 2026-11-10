#!/usr/bin/env bash
# test_linux_concurrent_step.sh — contract net for ci.yml's Linux step
# "Test (non-pg + pg halves, concurrent)".
#
# WHY THIS EXISTS. That step runs the non-pg and the pg test halves as two
# background process groups and decides the job's verdict from both. Its
# failure paths (a half's exit code reaching the step, the final exit, the
# cancel trap) are exactly the lines a refactor can drop silently: the job then
# goes green on a red half, or a cancelled job leaves test processes holding the
# box-wide test slot. scripts/ci/test_runner_health_check.py pins the step's
# strings; this test RUNS the step.
#
# WHAT IT PINS.
#   both halves green                -> rc 0, both halves' wall seconds printed
#   non-pg half fails                -> rc 1; its ::error:: line is printed while
#                                       the (slower) pg half is still running
#   pg half fails / both fail        -> rc 1
#   unknown pg_mode                  -> rc 1 before any half starts
#   YUZU_CI_SEQUENTIAL_HALVES=1      -> non-pg runs first, then pg; pg skipped
#                                       after a non-pg failure (rc 1)
#   stale logbase files              -> removed before the halves start
#   SIGTERM to the step shell        -> rc non-zero, and no process of either
#                                       half survives (checked by the PIDs the
#                                       stubs record, never by pattern)
#
# The step body is extracted from ci.yml (tests/shell/extract_run_block.py), not
# copied. python3 (flake-retry.py / test-durations-summary.py), ninja and
# scripts/ci/with-test-slot.sh are hermetic stubs: the step runs from a scratch
# work dir whose scripts/ci/ holds the slot stub, with the stub bin dir first on
# PATH. It runs under the shell GitHub uses for `run:` (bash -eo pipefail).
#
# Run:  bash tests/shell/test_linux_concurrent_step.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="${CI_YML:-$ROOT/.github/workflows/ci.yml}"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-linux-step.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}
yes_no() { if "$@"; then echo yes; else echo no; fi; }

python3 "$ROOT/tests/shell/extract_run_block.py" "$CI_YML" "$TMP/step.sh" \
  --name "Test (non-pg + pg halves, concurrent)" || exit 2
grep -q 'nonpg_half' "$TMP/step.sh" || { echo "extracted body does not look like the Linux test step" >&2; exit 2; }

# ── Stubs ────────────────────────────────────────────────────────────────────
mkdir -p "$TMP/bin"
cat > "$TMP/bin/ninja" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
# python3: flake-retry.py sleeps STUB_SLEEP_<base> seconds then exits 3 if its
# --logbase is in STUB_FAIL. It records its own PID and its sleep's PID, and an
# ordered start/end line per base. The pg base also records whether the step
# had already printed the non-pg failure by the time pg finished.
cat > "$TMP/bin/python3" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  scripts/ci/test-durations-summary.py) echo "durations stub: $*"; exit 0 ;;
  scripts/ci/flake-retry.py) ;;
  *) echo "python3 stub: unexpected invocation: $*" >&2; exit 99 ;;
esac
base=""; prev=""
for a in "$@"; do [ "$prev" = "--logbase" ] && base="$a"; prev="$a"; done
[ -n "$base" ] || { echo "python3 stub: no --logbase" >&2; exit 98; }
var="STUB_SLEEP_${base//-/_}"
echo "$$" >> "$STUB_DIR/pids"
echo "start $base" >> "$STUB_DIR/order"
echo "flake-retry stub running $base"
sleep "${!var:-0}" &
echo "$!" >> "$STUB_DIR/pids"
wait "$!"
if [ "$base" = testlog-pg ]; then
  if grep -q '::error::non-pg half failed' "$STUB_DIR/stdout" 2>/dev/null; then
    echo seen > "$STUB_DIR/pg-saw-nonpg-error"
  fi
fi
echo "end $base" >> "$STUB_DIR/order"
case " ${STUB_FAIL:-} " in *" $base "*) echo "flake-retry stub FAILING $base"; exit 3 ;; esac
exit 0
STUB
chmod +x "$TMP/bin/ninja" "$TMP/bin/python3"
mkdir -p "$TMP/work/scripts/ci"
cat > "$TMP/work/scripts/ci/with-test-slot.sh" <<'STUB'
#!/usr/bin/env bash
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
exec "$@"
STUB

# run_step [ENV=VAL ...] — runs the step synchronously; sets $rc.
run_step() {
  rm -rf "$TMP/work/build" "$TMP/stub"; mkdir -p "$TMP/stub"; : > "$TMP/stub/order"
  : > "$TMP/summary.md"
  ( cd "$TMP/work" || exit 97
    env PATH="$TMP/bin:$PATH" BUILDDIR=build PG_MODE=full GITHUB_WORKSPACE="$TMP/work" \
        GITHUB_STEP_SUMMARY="$TMP/summary.md" STUB_DIR="$TMP/stub" "$@" \
        bash --noprofile --norc -eo pipefail "$TMP/step.sh" >"$TMP/stub/stdout" 2>&1 )
  rc=$?
}
out_has() { grep -qF -- "$1" "$TMP/stub/stdout"; }

echo "-- both halves green --"
run_step
check "rc 0" 0 "$rc"
check "all three invocations ran" "3" "$(grep -c '^end ' "$TMP/stub/order")"
check "non-pg wall seconds printed" yes "$(yes_no grep -qE 'non-pg half: exit 0 in [0-9]+s' "$TMP/stub/stdout")"
check "pg wall seconds printed" yes "$(yes_no grep -qE 'pg half \(pg_mode=full\): exit 0 in [0-9]+s' "$TMP/stub/stdout")"
check "job summary has the timing table" yes "$(yes_no grep -qF '| Linux test half | result | wall s |' "$TMP/summary.md")"

echo "-- non-pg half fails while the pg half is still running --"
run_step STUB_FAIL=testlog-nonpg-cheap STUB_SLEEP_testlog_pg=7
check "rc 1" 1 "$rc"
check "non-pg failure printed before the pg half finished" yes "$(yes_no test -e "$TMP/stub/pg-saw-nonpg-error")"
check "fail-fast inside the non-pg half (server shards not run)" no "$(yes_no grep -q 'start testlog-nonpg-server' "$TMP/stub/order")"
check "pg half still ran to completion" yes "$(yes_no grep -q 'end testlog-pg' "$TMP/stub/order")"

echo "-- pg half fails --"
run_step STUB_FAIL=testlog-pg
check "rc 1" 1 "$rc"
check "names the pg half" yes "$(yes_no out_has '::error::pg half (pg_mode=full) failed (exit 3')"

echo "-- both halves fail --"
run_step STUB_FAIL="testlog-nonpg-server testlog-pg"
check "rc 1" 1 "$rc"
check "both exit codes printed" yes "$(yes_no grep -qE 'non-pg half: exit 3 in [0-9]+s; pg half \(pg_mode=full\): exit 3' "$TMP/stub/stdout")"

echo "-- smoke mode --"
run_step PG_MODE=smoke
check "rc 0" 0 "$rc"

echo "-- unknown pg_mode --"
run_step PG_MODE=bogus
check "rc 1" 1 "$rc"
check "no half started" "0" "$(grep -c '^start ' "$TMP/stub/order")"

echo "-- stale logbase files are removed before the halves start --"
mkdir -p "$TMP/work/build/meson-logs"
run_step_with_stale() {
  rm -rf "$TMP/stub"; mkdir -p "$TMP/stub"; : > "$TMP/stub/order"
  mkdir -p "$TMP/work/build/meson-logs"
  touch "$TMP/work/build/meson-logs/testlog-nonpg-server.junit.xml" \
        "$TMP/work/build/meson-logs/testlog-pg-flake-retry.json" \
        "$TMP/work/build/meson-logs/testlog-pg-flake-retry-enum-x.junit.xml"
  ( cd "$TMP/work" || exit 97
    env PATH="$TMP/bin:$PATH" BUILDDIR=build PG_MODE=full GITHUB_WORKSPACE="$TMP/work" \
        STUB_DIR="$TMP/stub" STUB_FAIL=testlog-nonpg-cheap \
        bash --noprofile --norc -eo pipefail "$TMP/step.sh" >"$TMP/stub/stdout" 2>&1 )
  rc=$?
}
run_step_with_stale
check "rc 1" 1 "$rc"
check "never-run invocation's stale junit removed" no "$(yes_no test -e "$TMP/work/build/meson-logs/testlog-nonpg-server.junit.xml")"
check "stale flake-retry files removed" "0" "$(ls "$TMP/work/build/meson-logs" | grep -c '^testlog-pg-flake-retry')"

echo "-- kill switch: YUZU_CI_SEQUENTIAL_HALVES=1 --"
run_step YUZU_CI_SEQUENTIAL_HALVES=1 STUB_SLEEP_testlog_nonpg_server=1
check "rc 0" 0 "$rc"
check "non-pg finished before pg started" \
  "start testlog-nonpg-cheap,end testlog-nonpg-cheap,start testlog-nonpg-server,end testlog-nonpg-server,start testlog-pg,end testlog-pg" \
  "$(paste -sd, "$TMP/stub/order")"
run_step YUZU_CI_SEQUENTIAL_HALVES=1 STUB_FAIL=testlog-nonpg-cheap
check "rc 1 after a non-pg failure" 1 "$rc"
check "pg half skipped" no "$(yes_no grep -q 'start testlog-pg' "$TMP/stub/order")"
check "skip reported" yes "$(yes_no out_has 'pg half (pg_mode=full): skipped')"

echo "-- clone-strategy leak is warned --"
run_step YUZU_TEST_PG_CLONE_STRATEGY=file_copy
check "rc 0" 0 "$rc"
check "warning names the value" yes "$(yes_no out_has "::warning::YUZU_TEST_PG_CLONE_STRATEGY='file_copy'")"

echo "-- SIGTERM to the step shell stops both halves --"
rm -rf "$TMP/work/build" "$TMP/stub"; mkdir -p "$TMP/stub"; : > "$TMP/stub/order"
( cd "$TMP/work" || exit 97
  exec env PATH="$TMP/bin:$PATH" BUILDDIR=build PG_MODE=full GITHUB_WORKSPACE="$TMP/work" \
      STUB_DIR="$TMP/stub" STUB_SLEEP_testlog_nonpg_cheap=60 STUB_SLEEP_testlog_pg=60 \
      bash --noprofile --norc -eo pipefail "$TMP/step.sh" >"$TMP/stub/stdout" 2>&1 ) &
step_pid=$!
for _ in $(seq 1 100); do
  [ "$(grep -c . "$TMP/stub/pids" 2>/dev/null || echo 0)" -ge 4 ] && break
  sleep 0.1
done
check "both halves were running (4 stub PIDs recorded)" 4 "$(grep -c . "$TMP/stub/pids" 2>/dev/null || echo 0)"
kill -TERM "$step_pid"
wait "$step_pid"; rc=$?
check "step exits non-zero" yes "$( [ "$rc" -ne 0 ] && echo yes || echo no)"
survivors=""
for _ in $(seq 1 50); do
  survivors=""
  while read -r p; do kill -0 "$p" 2>/dev/null && survivors="$survivors $p"; done < "$TMP/stub/pids"
  [ -z "$survivors" ] && break
  sleep 0.1
done
check "no stub process survives" "" "$survivors"
# Never leave our own stubs behind, even when the check failed (PIDs we started only).
for p in $survivors; do kill -KILL "$p" 2>/dev/null; done

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
