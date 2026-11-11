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
#   YUZU_CI_SEQUENTIAL_HALVES=true   -> ::warning:: (only 1 enables it); the
#                                       halves still run concurrently
#   stale logbase files              -> removed even when the step fails before
#                                       any half starts (legacy testlog.* too)
#   a half's own shell SIGKILLed     -> that half's stub children are stopped
#                                       when the step reaps it
#   SIGTERM to the step shell        -> rc non-zero; the step waits (bounded) for
#                                       the halves to exit, so none survives the
#                                       step's exit, and it exits within ~6 s even
#                                       when a half ignores SIGTERM for longer
#   the step shell exits non-zero    -> the EXIT trap stops the running halves
#   any other way (injected `false`)
#   (PIDs are always the ones the stubs record, never matched by pattern)
#
# The step body is extracted from ci.yml (tests/shell/extract_run_block.py), not
# copied. python3 (flake-retry.py / test-durations-summary.py), ninja and
# scripts/ci/with-test-slot.sh are hermetic stubs: the step runs from a scratch
# work dir whose scripts/ci/ holds the slot stub, with the stub bin dir first on
# PATH. It runs under the shell GitHub uses for a `run:` with no `shell:` key
# (`bash -e {0}`: no pipefail; ci.yml's linux job sets no defaults.run.shell),
# with the two knob variables unset unless a scenario sets them.
#
# Run:  bash tests/shell/test_linux_concurrent_step.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="${CI_YML:-$ROOT/.github/workflows/ci.yml}"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }

REAL_PYTHON3="$(command -v python3)"
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
# STUB_TERM_DELAY: on SIGTERM, become a sleep of that many seconds (same PID)
# before exiting — a test runner that takes a while to write its logs.
if [ -n "${STUB_TERM_DELAY:-}" ]; then trap 'exec sleep "$STUB_TERM_DELAY"' TERM; fi
echo "$$" | tee -a "$STUB_DIR/pids" >> "$STUB_DIR/pids-$base"
echo "start $base" >> "$STUB_DIR/order"
echo "flake-retry stub running $base"
sleep "${!var:-0}" &
echo "$!" | tee -a "$STUB_DIR/pids" >> "$STUB_DIR/pids-$base"
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

# step_cmd [ENV=VAL ...] — the step, as the runner launches it. SIGINT is reset
# to its default first: a background job of this non-interactive script inherits
# SIGINT ignored, and bash cannot trap a signal ignored at entry.
step_cmd() { # always called in a subshell, which it replaces (so $! is the step)
  exec "$REAL_PYTHON3" -I -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execvp(sys.argv[1], sys.argv[1:])' \
    env -u YUZU_CI_SEQUENTIAL_HALVES -u YUZU_TEST_PG_CLONE_STRATEGY \
        PATH="$TMP/bin:$PATH" BUILDDIR=build PG_MODE=full GITHUB_WORKSPACE="$TMP/work" \
        STUB_DIR="$TMP/stub" "$@" \
        bash --noprofile --norc -e "${STEP_SH:-$TMP/step.sh}"
}
fresh() { rm -rf "$TMP/work/build" "$TMP/stub"; mkdir -p "$TMP/stub"; : > "$TMP/stub/order"; }
# run_step [ENV=VAL ...] — runs the step synchronously; sets $rc.
run_step() {
  fresh
  : > "$TMP/summary.md"
  ( cd "$TMP/work" || exit 97
    step_cmd GITHUB_STEP_SUMMARY="$TMP/summary.md" "$@" >"$TMP/stub/stdout" 2>&1 )
  rc=$?
}
# start_step [ENV=VAL ...] — runs the step in the background; sets $step_pid.
start_step() {
  fresh
  ( cd "$TMP/work" || exit 97; step_cmd "$@" >"$TMP/stub/stdout" 2>&1 ) &
  step_pid=$!
}
# survivors <pid-file> — the recorded PIDs still alive.
survivors() { local p s=""; while read -r p; do kill -0 "$p" 2>/dev/null && s="$s $p"; done < "$1"; echo "$s"; }
# reap_ours <pid-file> — never leave our own stubs behind (recorded PIDs only).
reap_ours() { local p; for p in $(survivors "$1"); do kill -KILL "$p" 2>/dev/null; done; }
wait_lines() { # wait_lines <file> <n>: up to 10 s for <file> to reach <n> lines
  for _ in $(seq 1 100); do
    [ "$(grep -c . "$1" 2>/dev/null || echo 0)" -ge "$2" ] && return 0
    sleep 0.1
  done
  return 1
}
now_ms() { date +%s%3N; }
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
run_step_with_stale() { # run_step_with_stale [ENV=VAL ...]
  rm -rf "$TMP/stub"; mkdir -p "$TMP/stub"; : > "$TMP/stub/order"
  rm -rf "$TMP/work/build"; mkdir -p "$TMP/work/build/meson-logs"
  touch "$TMP/work/build/meson-logs/testlog-nonpg-server.junit.xml" \
        "$TMP/work/build/meson-logs/testlog-pg-flake-retry.json" \
        "$TMP/work/build/meson-logs/testlog-pg-flake-retry-enum-x.junit.xml" \
        "$TMP/work/build/meson-logs/testlog.junit.xml" \
        "$TMP/work/build/meson-logs/testlog.txt"
  ( cd "$TMP/work" || exit 97
    step_cmd "$@" >"$TMP/stub/stdout" 2>&1 )
  rc=$?
}
run_step_with_stale STUB_FAIL=testlog-nonpg-cheap
check "rc 1" 1 "$rc"
check "never-run invocation's stale junit removed" no "$(yes_no test -e "$TMP/work/build/meson-logs/testlog-nonpg-server.junit.xml")"
check "stale flake-retry files removed" "0" "$(ls "$TMP/work/build/meson-logs" | grep -c '^testlog-pg-flake-retry')"
check "legacy default testlog.* removed" "0" "$(ls "$TMP/work/build/meson-logs" | grep -c '^testlog\.')"
run_step_with_stale PG_MODE=bogus
check "rc 1 (bad pg_mode)" 1 "$rc"
check "stale files removed even when the step fails before any half" "0" "$(ls "$TMP/work/build/meson-logs" | grep -c '^testlog')"

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

echo "-- kill switch set to something other than 1 --"
run_step YUZU_CI_SEQUENTIAL_HALVES=true STUB_SLEEP_testlog_nonpg_cheap=2
check "rc 0" 0 "$rc"
check "warning says only 1 enables it" yes "$(yes_no out_has "::warning::YUZU_CI_SEQUENTIAL_HALVES='true' is not '1'")"
check "halves still concurrent (pg started before non-pg ended)" yes \
  "$(yes_no awk '/^start testlog-pg$/{s=NR} /^end testlog-nonpg-cheap$/{e=NR} END{exit !(s && e && s < e)}' "$TMP/stub/order")"
run_step
check "no kill-switch warning when unset" no "$(yes_no out_has "::warning::YUZU_CI_SEQUENTIAL_HALVES")"

echo "-- clone-strategy leak is warned --"
run_step YUZU_TEST_PG_CLONE_STRATEGY=file_copy
check "rc 0" 0 "$rc"
check "warning names the value" yes "$(yes_no out_has "::warning::YUZU_TEST_PG_CLONE_STRATEGY='file_copy'")"

echo "-- a half's own shell is SIGKILLed: its children are stopped --"
start_step STUB_SLEEP_testlog_nonpg_cheap=60 STUB_SLEEP_testlog_pg=4
wait_lines "$TMP/stub/pids-testlog-nonpg-cheap" 2
half_pid="$(sed -n 's/^started non-pg half (pid \([0-9][0-9]*\))$/\1/p' "$TMP/stub/stdout")"
check "non-pg half shell PID read from the step output" yes "$( [ -n "$half_pid" ] && echo yes || echo no)"
[ -n "$half_pid" ] && kill -KILL "$half_pid"
wait "$step_pid"; rc=$?
check "rc 1" 1 "$rc"
check "killed half reported" yes "$(yes_no out_has '::error::non-pg half failed (exit 137')"
left=""
for _ in $(seq 1 30); do left="$(survivors "$TMP/stub/pids-testlog-nonpg-cheap")"; [ -z "$left" ] && break; sleep 0.1; done
check "the killed half's stub children are gone" "" "$left"
reap_ours "$TMP/stub/pids"

echo "-- SIGTERM to the step shell stops both halves --"
start_step STUB_SLEEP_testlog_nonpg_cheap=60 STUB_SLEEP_testlog_pg=60 STUB_TERM_DELAY=1
wait_lines "$TMP/stub/pids" 4
check "both halves were running (4 stub PIDs recorded)" 4 "$(grep -c . "$TMP/stub/pids" 2>/dev/null || echo 0)"
t0=$(now_ms); kill -TERM "$step_pid"; wait "$step_pid"; rc=$?; dt=$(( $(now_ms) - t0 ))
left="$(survivors "$TMP/stub/pids")"
check "step exits non-zero" yes "$( [ "$rc" -ne 0 ] && echo yes || echo no)"
check "no stub process survives the step's exit (it waited for them)" "" "$left"
check "step exited within 6 s (took ${dt} ms)" yes "$( [ "$dt" -le 6000 ] && echo yes || echo no)"
reap_ours "$TMP/stub/pids"

echo "-- SIGTERM: the wait is bounded when a half outlives it --"
start_step STUB_SLEEP_testlog_nonpg_cheap=60 STUB_SLEEP_testlog_pg=60 STUB_TERM_DELAY=20
wait_lines "$TMP/stub/pids" 4
t0=$(now_ms); kill -TERM "$step_pid"; wait "$step_pid"; rc=$?; dt=$(( $(now_ms) - t0 ))
check "step exits non-zero" yes "$( [ "$rc" -ne 0 ] && echo yes || echo no)"
check "step exited within 6 s although the halves had not (took ${dt} ms)" yes "$( [ "$dt" -le 6000 ] && echo yes || echo no)"
check "and it did wait for them first (>= 4 s)" yes "$( [ "$dt" -ge 4000 ] && echo yes || echo no)"
reap_ours "$TMP/stub/pids"

echo "-- abnormal exit of the step shell (injected failure) stops both halves --"
# The only edit to the extracted step: a failing command right after the launches.
awk '{print} /^ *if \[\[ "\$sequential" -eq 0 \]\]; then launch pg; fi$/{print "sleep 1; false"; n++} END{exit n != 1}' \
  "$TMP/step.sh" > "$TMP/step-false.sh" || { echo "injection point not found" >&2; exit 2; }
STEP_SH="$TMP/step-false.sh" start_step STUB_SLEEP_testlog_nonpg_cheap=60 STUB_SLEEP_testlog_pg=60
wait "$step_pid"; rc=$?
check "rc 1" 1 "$rc"
left=""
for _ in $(seq 1 30); do left="$(survivors "$TMP/stub/pids")"; [ -z "$left" ] && break; sleep 0.1; done
check "no stub process survives" "" "$left"
reap_ours "$TMP/stub/pids"

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
