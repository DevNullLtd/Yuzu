#!/usr/bin/env bash
# coverage-gate.sh — Phase 7 coverage gate for /test (PR2).
#
# Sets up a dedicated build-linux-coverage/ dir (separate from the main
# build-linux/ to avoid cross-contamination), runs meson test, runs gcovr
# with the same filter set as the nightly.yml coverage job, parses the branch
# coverage percentage, compares against tests/coverage-baseline.json, and
# writes a Phase 7 gate row + branch_coverage_overall metric to the DB.
#
# Two modes:
#   default           — fail if branch coverage drops > 0.5 pp below baseline
#   --capture-baselines — run full pipeline, then REWRITE tests/coverage-baseline.json
#                         with the current numbers. Operator must commit the
#                         updated JSON in the same change that earned the new
#                         baseline. Exits PASS after capture.
#
# Required arguments:
#   --run-id ID       — /test run ID (DB foreign key)
#
# Optional arguments:
#   --build-dir DIR   — coverage build directory (default: build-linux-coverage)
#   --baseline PATH   — baseline JSON (default: tests/coverage-baseline.json)
#   --slack-pp F      : pp tolerance for regression (default 0.5; used only when the
#                       baseline file has no slack_pp)
#   --capture-baselines — rewrite baseline from current run
#   --report-only     — parse + record metric, don't enforce baseline
#
# Environment:
#   YUZU_COVERAGE_TIMEOUT_MULT: number >= 1 passed to
#                       `meson test --timeout-multiplier` (default: 3)
#   YUZU_COVERAGE_KILL_GRACE_SECS: seconds the EXIT handler waits for a
#                       terminated `meson test` and its test processes before
#                       killing what is left: meson only while it is still this
#                       gate's own child (its parent pid is the gate, or ps cannot
#                       report a parent at all, as on busybox), any other
#                       process only when its start time proves it is the same
#                       process, otherwise it is left running and a WARNING is
#                       logged (whole number, at most 4 digits, default: 30)
#   YUZU_COVERAGE_MIN_FREE_KB: free KB the build filesystem must still have
#                       after the run, else the run is inconclusive (default:
#                       262144)
#   YUZU_COVERAGE_HOST_OS: TEST HARNESS ONLY, do not set. Names the host for the Linux-only
#                       check below. Setting it to Linux on another host defeats that check
#                       and reproduces #6187; the gate warns when it differs from `uname -s`.
#
# Linux only: on any other host the gate refuses up front, before the tool check, the lock and
# the build (#6187): a WARN row (exit 2; exit 0 under --report-only), no metric, no baseline
# comparison; --capture-baselines is a FAIL row and exit 1. The baseline is Linux/gcc data and
# another host's coverage data is not comparable with it.
#
# One run per build directory: a second concurrent run is refused (WARN row)
# while the first holds the `<build-dir>.lock` symlink. A run whose tests failed
# or timed out, whose test processes reported libgcov counter-write errors, or
# that left the build filesystem almost full is INCONCLUSIVE: it is recorded as
# a WARN gate row, writes no coverage metric, is never compared with the
# baseline, and cannot capture one. The libgcov and free-space checks are
# best-effort: they see only the output of processes meson itself ran and a
# disk reading taken after the run.
#
# Exit codes:
#   0  coverage measured and within tolerance (or --report-only); also, under
#      --report-only, a tool/lock/orphan/non-Linux-host refusal, an inconclusive run or an
#      unreadable baseline (the WARN row is the record)
#   1  coverage regressed beyond slack, or --capture-baselines was refused or
#      could not write the baseline
#   2  environmental refusal (missing tool, bad configuration, a non-Linux host,
#      another run holds the build dir), an inconclusive run, a missing or seed baseline, a
#      build/gcovr/parse failure, or a gate/metric DB write that failed (WARN
#      row; the DB case also turns an exit 0 into 2). These stay 2 under
#      --report-only except where listed under 0.
# 129/130/143  interrupted (SIGHUP / SIGINT / SIGTERM): meson and its test
#      processes were terminated (see YUZU_COVERAGE_KILL_GRACE_SECS for the
#      limit) and the lock released before exit
#
# Implementation notes:
#
# - We use gcovr's JSON summary mode (`--json-summary`) to get structured
#   per-file + overall coverage without having to text-parse the XML or HTML.
#   The same --filter / --exclude set as the nightly.yml coverage job so
#   operator runs match CI.
#
# - The baseline JSON schema is documented in tests/coverage-baseline.json
#   itself (inline comments not allowed in JSON, so read the file header).
#
# - build-linux-coverage/ is separate from build-linux/ on purpose: -Db_coverage
#   embeds profiling artifacts into every object file, which invalidates the
#   non-coverage build's ccache entries. Keeping it separate preserves
#   cross-run ccache hit rate.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
BUILD_DIR=""
BASELINE=""
SLACK_PP="0.5"
CAPTURE=0
REPORT_ONLY=0
# meson test --timeout-multiplier; see the Run tests section.
TIMEOUT_MULT="${YUZU_COVERAGE_TIMEOUT_MULT:-3}"
# Free space (KB) the build filesystem must still have after the test run;
# below it the run is treated as inconclusive (gcov silently truncates counters
# when the disk fills).
MIN_FREE_KB="${YUZU_COVERAGE_MIN_FREE_KB:-262144}"

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --build-dir DIR        (default: build-linux-coverage)
  --baseline PATH        (default: tests/coverage-baseline.json)
  --slack-pp F           (default: 0.5; used only when the baseline file has no slack_pp)
  --capture-baselines    rewrite baseline from current run (then PASS)
  --report-only          parse + record metric, don't enforce baseline
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id|--build-dir|--baseline|--slack-pp)
            # A value is required, non-empty and not another option (`--run-id --report-only`).
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "coverage-gate: $1 needs a value" >&2; usage >&2; exit 2
            fi ;;
    esac
    case "$1" in
        --run-id)             RUN_ID="$2"; shift 2 ;;
        --build-dir)          BUILD_DIR="$2"; shift 2 ;;
        --baseline)           BASELINE="$2"; shift 2 ;;
        --slack-pp)           SLACK_PP="$2"; shift 2 ;;
        --capture-baselines)  CAPTURE=1; shift ;;
        --report-only)        REPORT_ONLY=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        *)                    echo "coverage-gate: unknown arg: ${1//[^[:print:]]/?}" >&2; usage >&2; exit 2 ;;
    esac
done

# --slack-pp is a fallback for a baseline file without its own slack_pp; refuse a value the
# comparison could not parse here, not after a 20 minute run.
[[ "$SLACK_PP" =~ ^[0-9]{1,6}([.][0-9]{1,6})?$ ]] && awk -v s="$SLACK_PP" 'BEGIN { exit !(s <= 50) }' || { echo "coverage-gate: --slack-pp must be a plain number from 0 to 50, got '${SLACK_PP//[^[:print:]]/?}'" >&2; exit 2; }

if [[ -z "$RUN_ID" ]]; then
    echo "coverage-gate: --run-id required" >&2
    exit 2
fi

# Validate RUN_ID before it's interpolated into filesystem paths (UP-9).
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ || "$RUN_ID" == "." || "$RUN_ID" == ".." ]]; then
    echo "coverage-gate: invalid --run-id (allowed: A-Z a-z 0-9 . _ -)" >&2
    exit 2
fi

BUILD_DIR="${BUILD_DIR:-$YUZU_ROOT/build-linux-coverage}"
BASELINE="${BASELINE:-$YUZU_ROOT/tests/coverage-baseline.json}"

# Validate BUILD_DIR — the reconfigure-failure path does `rm -rf "$BUILD_DIR"`,
# so an operator passing `--build-dir /` or `--build-dir $HOME` would be
# catastrophic (sec-M1). Require BUILD_DIR to resolve to a `build-*` segment
# under YUZU_ROOT, or an explicit absolute path clearly scoped to build work
# (e.g. /tmp/build-*).
# Resolve symlinks and `..`. `readlink -f` is not available everywhere (older
# macOS); fall back to python's realpath. A raw spelling must never reach the
# guard below: `build-x/../../elsewhere` matches the `build-*` glob lexically.
BUILD_DIR_ABS=$(readlink -f "$BUILD_DIR" 2>/dev/null) \
    || BUILD_DIR_ABS=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$BUILD_DIR" 2>/dev/null) \
    || BUILD_DIR_ABS=""
if [[ -z "$BUILD_DIR_ABS" || "$BUILD_DIR_ABS" != /* ]]; then
    echo "coverage-gate: refusing --build-dir '$BUILD_DIR': could not resolve it to an absolute path" >&2
    exit 2
fi
case "$BUILD_DIR_ABS" in
    "$YUZU_ROOT"/build-*|/tmp/build-*|/tmp/yuzu-test-*)
        ;;
    *)
        echo "coverage-gate: refusing --build-dir '$BUILD_DIR' (resolved '$BUILD_DIR_ABS') — must be under \$YUZU_ROOT/build-* or /tmp/build-*" >&2
        exit 2
        ;;
esac
# From here on use the RESOLVED path everywhere (lock, orphan check, meson -C,
# gcovr outputs, df/find): two spellings of one directory (relative, trailing
# slash, symlink) must be one lock and one orphan match, and a cwd-relative
# spelling must not make gcovr write its summary outside the build dir.
BUILD_DIR="${BUILD_DIR_ABS%/}"
BUILD_DIR_ABS="$BUILD_DIR"

LOG_DIR="$HOME/.local/share/yuzu/test-runs/$RUN_ID"
mkdir -p "$LOG_DIR"

GATE_LOG="$LOG_DIR/coverage.log"
: > "$GATE_LOG"

echo ""
echo "Phase 7 — Coverage (run $RUN_ID)"
echo "================================"
echo "  build-dir: $BUILD_DIR"
echo "  baseline:  $BASELINE"
echo "  slack-pp:  $SLACK_PP"
echo "  capture:   $CAPTURE  report-only: $REPORT_ONLY"
echo ""

GATE_START=$(date +%s)

# Exit code for a run that cannot produce a measurement for an environmental
# reason (missing tool, bad configuration, a non-Linux host, another run holding
# the build dir, an inconclusive result). In --report-only (the default-mode caller wraps the
# gate in `|| true`) the WARN gate row is the authoritative record and the exit
# is 0 so a fallback does not double-write; in enforce and --capture-baselines
# it is 2 so the caller sees a hard failure.
REFUSE_EXIT=2
if (( REPORT_ONLY )) && ! (( CAPTURE )); then
    REFUSE_EXIT=0
fi

# A failed gate or metric DB write must not be silent: the DB row IS the gate's
# result. Remember the failure and turn an otherwise-successful exit into 2 in
# the EXIT handler below.
DB_WRITE_FAILED=0

GATE_ROW_WRITTEN=0
OVERRIDE_MARK=""   # set when YUZU_COVERAGE_HOST_OS names a host other than the real one
write_gate() {
    local status="$1" duration="$2" notes="$3${OVERRIDE_MARK:-}"
    GATE_ROW_WRITTEN=1
    # A run whose earlier DB write failed (a metric, say) must not leave a PASS row: Phase 8 derives
    # the run's result from the gate rows alone, so the durable summary would read PASS with data missing.
    if [[ "$status" == "PASS" ]] && (( DB_WRITE_FAILED )); then
        status="WARN"
        notes="$notes [an earlier DB write in this run failed: its data is missing]"
    fi
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" \
        --phase 7 \
        --gate "Coverage" \
        --status "$status" \
        --duration "$duration" \
        --log "coverage.log" \
        --notes "$notes" || {
            DB_WRITE_FAILED=1
            echo "coverage-gate: ERROR could not record the Coverage gate row ($status) in the test-runs DB" | tee -a "$GATE_LOG" >&2
        }
}

write_metric() {
    local name="$1" value="$2" unit="$3"
    bash "$HERE/test-db-write.sh" metric \
        --run-id "$RUN_ID" \
        --name "$name" \
        --value "$value" \
        --unit "$unit" || {
            DB_WRITE_FAILED=1
            echo "coverage-gate: ERROR could not record metric $name in the test-runs DB" | tee -a "$GATE_LOG" >&2
        }
}

# One EXIT handler: terminate `meson test` and its whole process tree if it is still running
# (TERM, a bounded grace, then KILL of what is left), release the build-dir lock (if this run
# holds it) and turn an exit-0 whose DB write failed into exit 2.
LOCK_HELD=0   # raised just before this process tries to create the lock (see acquire_build_lock)
LOCK_PATH=""
LOCK_GUARD=""
TEST_PID=""
INTERRUPTED=0
# Print "pid@start" for PID and every descendant, found by parent-pid links in one `ps -A` call
# (a second, start-time-less call is the fallback when ps rejects lstart). meson starts every
# test in its OWN session and process group (setsid), so a group kill cannot reach them; the
# parent links still can. `start` is the process start time with spaces turned into '_' ("?"
# when ps cannot give it): it later proves a pid is still the same process and not a reused
# one. The walk stops at 5000 entries (bounding depth and fan-out), so an absurdly large tree
# is truncated rather than walked without bound; on_exit logs a WARNING when that happens.
descendants() {
    local out
    out=$(ps -A -o pid= -o ppid= -o lstart= 2>/dev/null)
    [[ -n "$out" ]] || out=$(ps -A -o pid= -o ppid= 2>/dev/null)
    printf '%s\n' "$out" | awk -v root="$1" '
        NF >= 2 {
            s = "?"
            if (NF >= 3) { s = $3; for (k = 4; k <= NF; k++) s = s "_" $k }
            kids[$2] = kids[$2] " " $1; start[$1] = s
        }
        END {
            n = 1; q[1] = root; seen[root] = 1
            for (i = 1; i <= n && n < 5000; i++) {
                m = split(kids[q[i]], a, " ")
                for (j = 1; j <= m && n < 5000; j++) if (!(a[j] in seen)) { seen[a[j]] = 1; n++; q[n] = a[j] }
            }
            for (i = 1; i <= n; i++) print q[i] "@" ((q[i] in start) ? start[q[i]] : "?")
        }'
}

# The start time of one process, in the same form descendants() records.
proc_start() {
    ps -o lstart= -p "$1" 2>/dev/null | awk '{ s = $1; for (k = 2; k <= NF; k++) s = s "_" $k; print s }'
}

# A process that exists and is not a zombie (kill -0 succeeds on zombies).
proc_alive() {
    kill -0 "$1" 2>/dev/null || return 1
    case "$(ps -o stat= -p "$1" 2>/dev/null)" in Z*) return 1 ;; esac
    return 0
}

on_exit() {
    local rc=$?
    # Cleanup must finish: a second INT/TERM/HUP here would abort it, leak the lock
    # and leave meson running.
    trap '' INT TERM HUP PIPE   # PIPE: a warning to a dead stderr pipe must not kill the cleanup
    # An orphaned `meson test` would keep writing counters after the lock is
    # gone and corrupt the next run. meson terminates its own test children on
    # SIGTERM, so forward it and wait.
    if [[ -n "$TEST_PID" ]]; then
        # Snapshot meson and its descendants BEFORE the TERM: once meson exits, its
        # children are re-parented and can no longer be found from it.
        local snap p pid stamp waited=0 alive=1 g="${YUZU_COVERAGE_KILL_GRACE_SECS:-30}" t0=$SECONDS
        INTERRUPTED=1
        [[ "$g" =~ ^[0-9]{1,4}$ ]] || g=30   # tool_check refuses a bad value; this is the backstop
        g=$(( 10#$g ))                       # a leading zero is decimal, not octal
        # Log first, then stderr through tee: a dead stderr pipe sends SIGPIPE to tee, not to this
        # shell (bash 3.2 on macOS does not reliably honour `trap '' PIPE` inside an EXIT trap), and
        # a closed stderr only fails the redirect.
        warn_log() { echo "coverage-gate: $1" >> "$GATE_LOG"; echo "coverage-gate: $1" | tee /dev/null >&2 || true; }
        command -v ps >/dev/null 2>&1 || warn_log "WARNING ps not found: meson's test processes cannot be found and are left running"
        warn_log "interrupted (exit $rc): stopping meson test and its test processes; waiting up to ${g}s, further signals are ignored"
        snap=$(descendants "$TEST_PID" | tr '\n' ' ')
        set -f
        local nsnap; nsnap=$(printf '%s\n' $snap | wc -l | tr -d ' ')
        set +f
        if (( nsnap >= 5000 )); then
            warn_log "WARNING the process tree under meson has 5000 or more entries; if it has more, only the first 5000 are tracked and the rest are not waited for or killed"
        fi
        # Meson is our own child, but bash reaps it the moment it exits, so its pid can be recycled
        # during the grace; the parent proof (ppid is this shell) is what makes it safe to signal.
        # When ps cannot report a parent at all (busybox: no output, or output that is not a pid) the
        # proof is unavailable and meson, our child a moment ago, is signalled. A pid that is
        # recycled between this check and the kill itself cannot be excluded; the window is
        # microseconds and the pid would also have to wrap.
        owns_meson() {
            kill -0 "$TEST_PID" 2>/dev/null || return 1   # gone: nothing to signal
            local pp; pp=$(ps -o ppid= -p "$TEST_PID" 2>/dev/null | head -n 1 | tr -d ' ')
            if [[ "$pp" =~ ^[0-9]+$ ]]; then [[ "$pp" == "$$" ]]; return; fi
            kill -0 "$TEST_PID" 2>/dev/null   # ps said nothing usable: still there, so signal it
        }
        if owns_meson; then
            kill -TERM "$TEST_PID" 2>/dev/null || true
        elif kill -0 "$TEST_PID" 2>/dev/null; then
            warn_log "WARNING meson test (pid $TEST_PID) is alive but not proven to be this gate's child: it is not signalled; the gate waits up to the grace, then leaves it running and releases the lock"
        fi
        local grace=$(( g * 10 ))
        # Bounded, to about the grace (each poll also costs a few ps calls): wait for meson AND its
        # tree to finish. Entries look like `123@Mon_Oct_19_20:14:53_2026` or `123@?`, so word
        # splitting stays on but pathname expansion is off for both loops.
        set -f
        # Also capped by wall-clock time: a poll costs ps forks, so ticks alone overshoot the grace.
        while (( alive && waited < grace && SECONDS - t0 <= g )); do
            alive=0
            for p in $snap; do
                if proc_alive "${p%%@*}"; then alive=1; break; fi
            done
            if (( alive )); then sleep 0.1; waited=$(( waited + 1 )); fi
        done
        # Whatever of the snapshot is still running now is killed. Meson is proven ours by its
        # parent pid, not by its start time, so a clock step between snapshot and compare cannot
        # leave the gate waiting on a meson that ignores TERM; a pid that is no longer our child
        # (recycled) is not signalled. Every other entry is killed only with proof that it is
        # still the SAME process (same start time), never a reused pid; one whose start time was
        # unavailable ("?", e.g. busybox ps) or changed cannot be proven and is left running,
        # which is logged.
        for p in $snap; do
            pid=${p%%@*}; stamp=${p#*@}
            proc_alive "$pid" || continue
            if [[ "$pid" == "$TEST_PID" ]]; then
                owns_meson && kill -KILL "$pid" 2>/dev/null
            elif [[ "$stamp" != "?" && "$(proc_start "$pid")" == "$stamp" ]]; then
                kill -KILL "$pid" 2>/dev/null
            elif proc_alive "$pid"; then
                warn_log "WARNING left test process $pid running: its identity could not be proven (no start time from ps, or it changed)"
            fi
        done
        set +f
        wait "$TEST_PID" 2>/dev/null || true
        TEST_PID=""
    fi
    # An interrupted run leaves a record: without it the Coverage gate has no row at all.
    if (( INTERRUPTED )) && (( ! GATE_ROW_WRITTEN )); then
        write_gate WARN "$(( $(date +%s) - GATE_START ))" "interrupted (exit $rc): coverage was NOT checked"
    fi
    # Only a lock THIS process created, and only while it still points to us: a
    # refused run whose pid happens to equal the holder's (pid reuse, another PID
    # namespace) must not delete somebody else's lock.
    if (( LOCK_HELD )) && [[ -n "$LOCK_PATH" && "$(readlink "$LOCK_PATH" 2>/dev/null)" == "$$" ]]; then
        rm -f "$LOCK_PATH" 2>/dev/null || true
    fi
    # A takeover guard this run created and was interrupted inside.
    if [[ -n "$LOCK_GUARD" && "$(readlink "$LOCK_GUARD" 2>/dev/null)" == "$$" ]]; then
        rm -f "$LOCK_GUARD" 2>/dev/null || true
    fi
    if (( DB_WRITE_FAILED )) && [[ $rc -eq 0 ]]; then
        exit 2
    fi
}
# Signals are caught so the EXIT handler runs promptly (bash defers a trap until
# a foreground child ends; the test run below is a background job we `wait` on).
trap on_exit EXIT
# Each handler first ignores all three signals: a second one arriving between `exit` and the
# `trap '' ...` at the top of on_exit would otherwise abort the cleanup (meson left running,
# lock leaked; reproduced with a burst of signals).
trap 'trap "" INT TERM HUP; INTERRUPTED=1; exit 130' INT
trap 'trap "" INT TERM HUP; INTERRUPTED=1; exit 143' TERM
trap 'trap "" INT TERM HUP; INTERRUPTED=1; exit 129' HUP

tool_check() {
    # Exit code discipline:
    #   --full / enforce mode: exit 2 so the caller sees a hard failure it
    #     can choose to bubble up. The WARN row is already recorded.
    #   --report-only (default-mode caller): exit 0 so the caller's `|| …`
    #     fallback doesn't fire and double-write a gate row. The WARN row
    #     from this function is authoritative and sufficient.
    #   --capture-baselines: exit 2 (same as enforce) — a missing tool here
    #     would otherwise silently capture a zero-coverage baseline.
    local tool_miss_exit=$REFUSE_EXIT

    if ! command -v gcovr >/dev/null 2>&1; then
        echo "coverage-gate: gcovr not on PATH (pip install gcovr)" | tee -a "$GATE_LOG"
        write_gate WARN 0 "gcovr missing — install with 'pip3 install --user gcovr' and re-run"
        exit "$tool_miss_exit"
    fi
    if ! command -v meson >/dev/null 2>&1; then
        echo "coverage-gate: meson not on PATH" | tee -a "$GATE_LOG"
        write_gate WARN 0 "meson missing"
        exit "$tool_miss_exit"
    fi
    if [[ ! "${YUZU_COVERAGE_KILL_GRACE_SECS:-30}" =~ ^[0-9]{1,4}$ ]]; then
        echo "coverage-gate: YUZU_COVERAGE_KILL_GRACE_SECS='${YUZU_COVERAGE_KILL_GRACE_SECS//[^[:print:]]/?}' must be a whole number of seconds (at most 4 digits)" | tee -a "$GATE_LOG"
        write_gate WARN 0 "invalid YUZU_COVERAGE_KILL_GRACE_SECS"
        exit "$tool_miss_exit"
    fi
    if [[ ! "$MIN_FREE_KB" =~ ^[0-9]{1,12}$ ]]; then
        echo "coverage-gate: YUZU_COVERAGE_MIN_FREE_KB='${MIN_FREE_KB//[^[:print:]]/?}' must be a whole number of KB" | tee -a "$GATE_LOG"
        write_gate WARN 0 "invalid YUZU_COVERAGE_MIN_FREE_KB"
        exit "$tool_miss_exit"
    fi
    # Refuse a bad multiplier BEFORE the long build. meson rejects a non-number
    # and crashes on a very long digit string (zero tests run, then gcovr reads
    # an empty tree and reports ~0%), treats 0 or a negative value as "no
    # timeout at all" (a hung test would hang the gate with no outer bound), and
    # a value under 1 would shorten every test's budget below its own. Accept
    # only a number >= 1 with at most 6 digits on each side of the point.
    if [[ ! "$TIMEOUT_MULT" =~ ^[1-9][0-9]{0,5}(\.[0-9]{1,6})?$ ]]; then
        echo "coverage-gate: YUZU_COVERAGE_TIMEOUT_MULT='${TIMEOUT_MULT//[^[:print:]]/?}' must be a number >= 1 (digits only, at most 6 before and after the point)" | tee -a "$GATE_LOG"
        write_gate WARN 0 "invalid YUZU_COVERAGE_TIMEOUT_MULT"
        exit "$tool_miss_exit"
    fi
}

# Coverage is only checked on a Linux host. The baseline is captured on Linux/gcc, and a real run
# on macOS (Apple clang, gcovr) measured an implausibly low figure (#6187): a figure the gate
# cannot vouch for would otherwise be compared with the baseline and reported as a regression.
# Refuse before the tool check, the lock and the 20+ minute build and test run, with a WARN row
# (the same record an inconclusive run leaves), no metric and no baseline comparison;
# --capture-baselines is a FAIL.
# YUZU_COVERAGE_HOST_OS names the host for the test harness only. If it differs from the real
# `uname -s` the gate says so loudly, in the log, on the console and in every Coverage row it
# writes, because a measurement taken on a host other than the one named is not comparable with
# the baseline.
REAL_OS=$(uname -s)
HOST_OS="${YUZU_COVERAGE_HOST_OS:-$REAL_OS}"
HOST_OS="${HOST_OS//[^[:print:]]/?}"
HOST_OS="${HOST_OS:-unknown}"   # uname missing or failing: refused, with a readable name
if [[ -n "${YUZU_COVERAGE_HOST_OS:-}" && "$HOST_OS" != "$REAL_OS" ]]; then
    OVERRIDE_WARNING="coverage-gate: WARNING YUZU_COVERAGE_HOST_OS=$HOST_OS overrides the real host ($REAL_OS): this is a test-harness setting, and any figure measured this way is NOT comparable with the baseline"
    echo "$OVERRIDE_WARNING" >> "$GATE_LOG"
    # Through tee: a dead stderr pipe sends SIGPIPE to tee, not to this shell (on_exit ignores
    # SIGPIPE, but that handler has not run yet); a closed stderr fails the redirect.
    echo "$OVERRIDE_WARNING" | tee /dev/null >&2 || true
    # Every Coverage row of this run says so too: the DB, not only the log, must show that the
    # figure was measured under an assumed host.
    OVERRIDE_MARK=" [HOST OVERRIDE: assumed $HOST_OS on a real $REAL_OS host; not comparable with the baseline]"
fi
if [[ "$HOST_OS" != "Linux" ]]; then
    NOTE="coverage NOT checked on $HOST_OS: the baseline is captured on Linux/gcc and this host's coverage data is not comparable with it (#6187). Run the gate on a Linux host; no metric was recorded and no baseline comparison was made"
    echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
    if [[ $CAPTURE -eq 1 ]]; then
        write_gate FAIL 0 "refused --capture-baselines: $NOTE"
        exit 1
    fi
    write_gate WARN 0 "$NOTE"
    exit "$REFUSE_EXIT"
fi

tool_check

# ── Serialise runs on the build directory ──────────────────────────────
#
# Two overlapping runs against one build dir race ninja/meson and read each
# other's gcda files (and the stale-gcda purge below would zero the other run's
# counters mid-test), producing a number that looks like a measurement but is
# not. The lock is a SYMLINK named `<build-dir>.lock` whose target text is the
# holder's pid: `ln -s` creates it atomically WITH its content, so there is no
# window in which a lock exists without a pid, and it is portable (macOS has no
# flock). It sits next to the build dir, never inside it, because the
# reconfigure-failure path deletes the whole build dir. A lock whose holder is
# gone is a crashed run's leftover; taking it over is serialised by a second
# short-lived symlink guard so two runs cannot both clear and re-take it. (Both
# use `ln -s`, not `mkdir`: uutils coreutils' mkdir is not atomic under
# contention. A guard left by a taker that died inside its few-microsecond
# critical section blocks takeover of a LATER stale lock until
# `<build-dir>.lock.takeover` is removed; the EXIT handler removes a guard it
# created.)
# `ln -sn` (not plain `ln -s`) so a pre-planted symlink-to-directory at the lock
# path is an "already exists" failure instead of a link created INSIDE that
# directory. INT, TERM and HUP are forwarded to meson and waited for before the
# lock is released (exit 130/143/129); a TERM sent to the gate alone while it is
# inside `meson compile` or gcovr is acted on when that command ends. Residual:
# SIGKILL (and SIGQUIT/SIGPIPE) leave meson test running; a pgrep check below
# refuses a run while a `meson test` on this build dir is still alive. PID reuse
# can make a dead holder look alive; the run is then refused, naming the lock.
BUILD_DIR_ABS="${BUILD_DIR_ABS%/}"
LOCK_PATH="${BUILD_DIR_ABS}.lock"
LOCK_GUARD="${LOCK_PATH}.takeover"
LOCK_HOLDER=""

pid_alive() {  # kill -0 fails with EPERM for another user's live process; ps -p does not
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$1" 2>/dev/null || ps -p "$1" >/dev/null 2>&1
}

acquire_build_lock() {
    local holder
    # LOCK_HELD is raised BEFORE the ln and dropped if it fails: bash runs a pending signal trap
    # only after the external `ln` returns, and the handler must already own the lock then
    # (it removes it only while the link still points at this process).
    LOCK_HELD=1
    if ln -sn -- "$$" "$LOCK_PATH" 2>/dev/null; then return 0; fi
    LOCK_HELD=0
    holder=$(readlink "$LOCK_PATH" 2>/dev/null || true)
    if [[ "$holder" =~ ^[0-9]+$ ]] && ! pid_alive "$holder"; then
        # Only one contender at a time may judge and clear a stale lock. The guard
        # is a symlink too (`ln -s` is atomic everywhere we measured; `mkdir` is
        # NOT under uutils coreutils 0.8.0, Ubuntu 26.04's default, where two
        # simultaneous mkdirs of one path can both succeed).
        if ln -sn -- "$$" "$LOCK_GUARD" 2>/dev/null; then
            holder=$(readlink "$LOCK_PATH" 2>/dev/null || true)
            if [[ "$holder" =~ ^[0-9]+$ ]] && ! pid_alive "$holder"; then
                echo "coverage-gate: clearing stale lock $LOCK_PATH (holder pid $holder is not running)" | tee -a "$GATE_LOG"
                rm -f "$LOCK_PATH"
                LOCK_HELD=1
                if ln -sn -- "$$" "$LOCK_PATH" 2>/dev/null; then
                    rm -f "$LOCK_GUARD"
                    return 0
                fi
                LOCK_HELD=0
            fi
            rm -f "$LOCK_GUARD"
            holder=$(readlink "$LOCK_PATH" 2>/dev/null || true)
        fi
    fi
    holder="${holder//[^[:print:]]/?}"
    LOCK_HOLDER="${holder:-unreadable}"
    return 1
}
if acquire_build_lock; then
    :
else
    if [[ ! -L "$LOCK_PATH" && ! -e "$LOCK_PATH" ]]; then
        NOTE="refused: cannot create the lock $LOCK_PATH (is its directory writable and not read-only?)"
    else
        NOTE="refused: another coverage-gate run (pid $LOCK_HOLDER) holds $LOCK_PATH; wait for it, or remove that file if no such run is active"
        [[ -L "$LOCK_GUARD" ]] && NOTE="$NOTE. A takeover guard $LOCK_GUARD is also present; remove it too if its pid ($(readlink "$LOCK_GUARD" 2>/dev/null | tr -cd '0-9')) is not running"
    fi
    echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
    write_gate WARN 0 "$NOTE"
    exit "$REFUSE_EXIT"
fi

# A gate killed with SIGKILL (or a manual `meson test`) can leave a test run alive
# on this build dir; running our own purge/tests next to it would corrupt both.
# Best-effort: it matches the command line of a `meson test -C <resolved dir>`;
# a manual run spelled with a relative path, or a process wrapped in `bash -c`,
# is matched or missed by its text alone.
ORPHAN_PIDS=""
if command -v pgrep >/dev/null 2>&1; then
    # Escape ERE metacharacters in the path so `+`, `(`, `[`, `|` and `.` are literal.
    ORPHAN_PAT=$(printf '%s' "$BUILD_DIR" | sed 's/[]\\.*+?(){}|^$[]/\\&/g')
    ORPHAN_PIDS=$(pgrep -f "meson test -C ${ORPHAN_PAT}( |\$)" 2>/dev/null | tr '\n' ' ' || true)
else
    echo "coverage-gate: WARNING pgrep not found; the check for a surviving meson test is skipped" | tee -a "$GATE_LOG"
fi
if [[ -n "${ORPHAN_PIDS// /}" ]]; then
    NOTE="refused: a meson test is already running on $BUILD_DIR (pid ${ORPHAN_PIDS% }), probably left by a killed coverage-gate; wait for it or stop it"
    echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
    write_gate WARN 0 "$NOTE"
    exit "$REFUSE_EXIT"
fi

# ── Configure build-linux-coverage with -Db_coverage ──────────────────

# Propagate the vcpkg install root so the coverage build dir can find
# grpc/protobuf/sqlite3/etc.; it does not inherit the options of the sibling
# `build-linux/`. The install tree lives per-OS (issue #460), so pick the
# per-host tree. (#1009)
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  VCPKG_TRIPLET="x64-linux" ;;
    Linux-aarch64) VCPKG_TRIPLET="arm64-linux" ;;
    Darwin-arm64)  VCPKG_TRIPLET="arm64-osx" ;;
    Darwin-x86_64) VCPKG_TRIPLET="x64-osx" ;;
    *)             VCPKG_TRIPLET="x64-linux" ;;
esac
VCPKG_INSTALLED="$YUZU_ROOT/vcpkg_installed/$VCPKG_TRIPLET"
# Applied to BOTH the fresh setup and the --reconfigure of an existing dir: a
# dir left behind by the #5803 link failure was configured without
# pkg_config_path, and --reconfigure keeps the options a dir was created with
# unless they are passed again.
VCPKG_MESON_OPTS=()
if [[ -d "$VCPKG_INSTALLED" ]]; then
    VCPKG_MESON_OPTS+=(-Dcmake_prefix_path="$VCPKG_INSTALLED")
    echo "coverage-gate: using cmake_prefix_path=$VCPKG_INSTALLED" | tee -a "$GATE_LOG"
    # BOTH paths are load-bearing (CLAUDE.md "Build"): cmake_prefix_path alone
    # leaves pkg-config dependencies (c-ares, zlib via trantor/drogon)
    # unresolved and the link dies late with undefined ares_*/inflateEnd
    # symbols (#5803, #3725 class).
    if [[ -d "$VCPKG_INSTALLED/lib/pkgconfig" ]]; then
        VCPKG_MESON_OPTS+=(-Dpkg_config_path="$VCPKG_INSTALLED/lib/pkgconfig")
        echo "coverage-gate: using pkg_config_path=$VCPKG_INSTALLED/lib/pkgconfig" | tee -a "$GATE_LOG"
    else
        echo "coverage-gate: WARNING $VCPKG_INSTALLED/lib/pkgconfig missing; pkg_config_path not set; the build may fail to link" | tee -a "$GATE_LOG"
    fi
else
    echo "coverage-gate: WARNING $VCPKG_INSTALLED missing; neither cmake_prefix_path nor pkg_config_path set" | tee -a "$GATE_LOG"
fi

if [[ -d "$BUILD_DIR" ]]; then
    echo "coverage-gate: reconfiguring existing $BUILD_DIR" | tee -a "$GATE_LOG"
    meson setup "$BUILD_DIR" \
        --reconfigure \
        ${VCPKG_MESON_OPTS[@]+"${VCPKG_MESON_OPTS[@]}"} \
        -Dbuild_tests=true \
        -Db_coverage=true \
        >> "$GATE_LOG" 2>&1 || {
            echo "coverage-gate: reconfigure failed — wiping and retrying" | tee -a "$GATE_LOG"
            rm -rf "$BUILD_DIR"
        }
fi

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "coverage-gate: fresh meson setup $BUILD_DIR" | tee -a "$GATE_LOG"
    # bci-S5: use a pinned native file so the compiler is reproducible. This
    # gate pins `meson/native/linux-gcc13.ini`; the nightly coverage job
    # (.github/workflows/nightly.yml, gcc-15) uses `linux-gcc15.ini`, so a
    # compiler-version difference can shift branch counts: compare a local
    # number against `tests/coverage-baseline.json`, not against nightly's
    # absolute figure.
    MESON_SETUP_EXTRA=()
    # The Linux native-file pins gcc-13.
    # On macOS the host toolchain is Apple Clang 15 and gcc-13 isn't on PATH,
    # so applying the Linux native-file resolves grpc/grpc++ against the wrong
    # pkg-config tree and the configure step fails. Only apply on Linux. (#1009)
    # (A non-Linux host is refused before this point; the branch is reachable there only through
    # the harness override YUZU_COVERAGE_HOST_OS.)
    if [[ "$(uname -s)" == "Linux" ]]; then
        NATIVE_FILE="$YUZU_ROOT/meson/native/linux-gcc13.ini"
        if [[ -f "$NATIVE_FILE" ]]; then
            MESON_SETUP_EXTRA+=(--native-file "$NATIVE_FILE")
            echo "coverage-gate: using native-file $NATIVE_FILE (gcc-13 pin; nightly.yml uses linux-gcc15.ini)" | tee -a "$GATE_LOG"
        fi
    else
        echo "coverage-gate: host $(uname -s) — skipping linux-gcc13 native-file, using host default compiler" | tee -a "$GATE_LOG"
    fi
    MESON_SETUP_EXTRA+=(${VCPKG_MESON_OPTS[@]+"${VCPKG_MESON_OPTS[@]}"})
    if ! meson setup "$BUILD_DIR" \
        ${MESON_SETUP_EXTRA[@]+"${MESON_SETUP_EXTRA[@]}"} \
        --buildtype=debug \
        -Dbuild_tests=true \
        -Db_coverage=true \
        >> "$GATE_LOG" 2>&1
    then
        GATE_DUR=$(( $(date +%s) - GATE_START ))
        write_gate WARN "$GATE_DUR" "meson setup failed — see coverage.log"
        exit 2
    fi
fi

# ── Compile ────────────────────────────────────────────────────────────

echo "coverage-gate: compiling $BUILD_DIR" | tee -a "$GATE_LOG"
if ! meson compile -C "$BUILD_DIR" >> "$GATE_LOG" 2>&1; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "coverage build failed — see coverage.log"
    exit 2
fi

# ── Run tests ──────────────────────────────────────────────────────────

echo "coverage-gate: running meson test" | tee -a "$GATE_LOG"
# --no-rebuild because meson compile already covered it.
# A test failure does not stop the run: the exit code is captured separately and
# gcovr still runs so the log shows the figure, but a nonzero code makes the run
# INCONCLUSIVE (see below): no metric, no comparison, no capture.
TEST_RC=0
# gcov counters ACCUMULATE across runs in a reused build dir, so a test that
# ran last time but is skipped, killed or timed out this time would still
# contribute its old counters and the number could not drop for lost tests.
# Start every run from zero.
# -H: BUILD_DIR may be a symlink (the path guard above accepts one that resolves
# under an allowed prefix) and find does not follow a command-line symlink
# without it. A failed delete is not fatal but must not be silent.
PURGE_FAILED=0
if ! find -H "$BUILD_DIR" -name '*.gcda' -type f -delete 2>>"$GATE_LOG"; then
    PURGE_FAILED=1
    echo "coverage-gate: WARNING could not delete every stale .gcda under $BUILD_DIR; counters from an earlier run may remain, so this run will be INCONCLUSIVE" | tee -a "$GATE_LOG"
fi
# Instrumented (-Db_coverage) binaries run slower than the normal build, and a
# loaded host slower still: the pg shards hit their 700s budget and the 60s/90s
# smoke tests timed out on a busy box, truncating the gcda data (a test killed
# on timeout writes none). nightly.yml uses 2; default higher here because a
# local run shares the box. Override with YUZU_COVERAGE_TIMEOUT_MULT, which
# tool_check() has already validated as a number >= 1.
echo "coverage-gate: meson test --timeout-multiplier $TIMEOUT_MULT" | tee -a "$GATE_LOG"
# A background job we `wait` on, so a signal to this script reaches the EXIT handler
# (which terminates meson and its tree) instead of being deferred until meson ends.
# `set -m` puts meson in its OWN process group: a signal aimed at the gate's group (a
# terminal hangup, a wrapper killing the group) then reaches only the gate, which
# terminates meson and its test processes in an orderly way; without it meson would die at
# once and strand its tests (they sit in their own sessions). stdin is /dev/null so nothing
# in the tree can be stopped by a terminal read from a background group. `trap - INT QUIT`
# is belt and braces: under `set -m` the child already starts with INT/QUIT at their default
# (measured on bash 5.3), but a signal that was ALREADY ignored when the gate itself was started
# (nohup, `cmd &` from a non-interactive shell) stays ignored, because bash cannot un-ignore a
# signal ignored on entry.
set -m
( trap - INT QUIT; exec meson test -C "$BUILD_DIR" --no-rebuild --print-errorlogs \
    --timeout-multiplier "$TIMEOUT_MULT" ) >> "$GATE_LOG" 2>&1 </dev/null &
TEST_PID=$!
set +m
wait "$TEST_PID" || TEST_RC=$?
TEST_PID=""
if [[ $TEST_RC -ne 0 ]]; then
    echo "coverage-gate: meson test exit=$TEST_RC (gcovr still runs so the log shows the figure, but the run is INCONCLUSIVE)" \
        | tee -a "$GATE_LOG"
fi

# ── Decide whether the run can be trusted ──────────────────────────────
#
# A failed or timed-out test writes no counters, and a full disk makes libgcov
# truncate them while the tests and gcovr still exit 0. Either way the figure is
# a lower bound of unknown size, not a measurement, so it must not be recorded
# as an ordinary metric or compared with the baseline.
INCONCLUSIVE=()
if (( PURGE_FAILED )); then
    # Surviving counters from an earlier run add their hits to this run's, so a test that
    # executed less code this time still reads as covered: the figure is not a measurement.
    INCONCLUSIVE+=("could not delete every stale .gcda before the run (counters from an earlier run may be mixed in)")
fi
if [[ $TEST_RC -ne 0 ]]; then
    INCONCLUSIVE+=("meson test exit=$TEST_RC")
fi
TESTLOG="$BUILD_DIR/meson-logs/testlog.txt"
if [[ -f "$TESTLOG" ]]; then
    # libgcov writes at process exit with no leading newline, so the message can
    # directly follow a test's last unterminated line: no line anchor. The
    # patterns are the specific libgcov messages (gcc 15: Cannot create
    # directory / Cannot open / Skip / exiting after an error, and the
    # `libgcov profiling error:` family), not the bare word "profiling:".
    PROFILING_ERRORS=$(grep -cE 'libgcov profiling error:|profiling:exiting after an error|profiling:[^[:space:]]+:(Cannot|Skip)' "$TESTLOG" 2>/dev/null || true)
    if [[ "$PROFILING_ERRORS" =~ ^[0-9]+$ ]] && (( PROFILING_ERRORS > 0 )); then
        INCONCLUSIVE+=("libgcov reported $PROFILING_ERRORS profiling error line(s) in $TESTLOG (counters not written or mismatched)")
    fi
fi
FREE_KB_AFTER=$(df -Pk "$BUILD_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
if [[ "$FREE_KB_AFTER" =~ ^[0-9]+$ ]]; then
    # 10# so a leading zero in either number is not read as octal.
    if (( 10#$FREE_KB_AFTER < 10#$MIN_FREE_KB )); then
        INCONCLUSIVE+=("only ${FREE_KB_AFTER} KB free on the build filesystem after the run (minimum ${MIN_FREE_KB} KB; counters may be truncated)")
    fi
else
    INCONCLUSIVE+=("could not read the free space of the build filesystem")
fi

INC_SUFFIX=""
if (( ${#INCONCLUSIVE[@]} )); then
    INC_REASONS=$(printf '%s; ' "${INCONCLUSIVE[@]}")
    INC_SUFFIX=" (the run was also inconclusive: ${INC_REASONS%; })"
fi

# ── Run gcovr ──────────────────────────────────────────────────────────
#
# Filter set mirrors the .github/workflows/nightly.yml coverage job. Any drift
# between here and CI causes local/CI coverage deltas that look like
# regressions but aren't.
#
# The build directory is passed as gcovr's search path. Without it gcovr searches only
# `--root`, so a build dir outside the repo (the path guard allows /tmp/build-*) is not
# searched at all: gcovr exits 0 with "All coverage data is filtered out" and 0.0% branch,
# which the gate would report as a regression; a second coverage dir inside the repo would
# be swept in with this one.
#
# No `--branches`: in gcovr 8.6 it is a deprecated alias of `--txt-branches`
# and only changes the TEXT report, which this gate does not produce; the
# JSON/XML/HTML branch data is the same with or without it. gcovr 8.7 removed
# the flag, so passing it there is a hard error. (nightly.yml still passes it;
# it pins gcovr 8.6.)

echo "coverage-gate: running gcovr" | tee -a "$GATE_LOG"
GCOVR_JSON="$BUILD_DIR/coverage-summary.json"
GCOVR_XML="$BUILD_DIR/coverage.xml"
GCOVR_HTML_DIR="$BUILD_DIR/coverage-html"
mkdir -p "$GCOVR_HTML_DIR"

# A summary left by an earlier run must never be mistaken for this run's.
rm -f "$GCOVR_JSON" "$GCOVR_XML"

GCOVR_RC=0
(
    cd "$YUZU_ROOT"
    gcovr \
        --root "$YUZU_ROOT" \
        --filter 'server/' --filter 'agents/' --filter 'sdk/' --filter 'tests/' \
        --exclude '.*\.pb\.(h|cc)$' \
        --gcov-ignore-parse-errors=negative_hits.warn \
        --json-summary "$GCOVR_JSON" \
        --xml "$GCOVR_XML" \
        --html --html-details -o "$GCOVR_HTML_DIR/index.html" \
        "$BUILD_DIR" \
        >> "$GATE_LOG" 2>&1
) || GCOVR_RC=$?

if [[ $GCOVR_RC -ne 0 || ! -f "$GCOVR_JSON" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "gcovr failed (rc=$GCOVR_RC) — see coverage.log${INC_SUFFIX}"
    exit 2
fi

# ── Parse branch and line coverage percentages ────────────────────────
#
# UP-2: gcovr --json-summary schema varies across versions.
#   gcovr 6.x/7.x top-level: branch_percent, line_percent, branches_covered,
#                            branches_valid, lines_covered, lines_valid
#   gcovr 5.x top-level:     branches_covered, branches_valid (no percent)
#   gcovr 7.x w/ root:       {"root": {branch_percent, ...}}
#   very old:                branch_covered/branch_total (wrong in our old code)
# Return None if no recognized shape is found so we WARN loudly instead
# of silently defaulting to 0 (which would anchor a false baseline).

PARSE_RC=0
COVERAGE_JSON=$(python3 - "$GCOVR_JSON" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception as e:
    print(json.dumps({"error": f"json.load failed: {e}"}))
    sys.exit(1)

# Unwrap gcovr 7.x+ {"root": ...} wrapper if present.
root = data.get("root") if isinstance(data.get("root"), dict) else data

def pct_from(d, p_key, num_keys, den_keys):
    v = d.get(p_key)
    if v is not None:
        return float(v)
    for num, den in zip(num_keys, den_keys):
        n, t = d.get(num), d.get(den)
        if n is not None and t not in (None, 0):
            return 100.0 * float(n) / float(t)
    return None

branch = pct_from(root,
    "branch_percent",
    ["branches_covered", "branch_covered"],
    ["branches_valid",   "branch_total"])
line = pct_from(root,
    "line_percent",
    ["lines_covered", "line_covered"],
    ["lines_valid",   "line_total"])

if branch is None:
    print(json.dumps({
        "error": "no recognized branch-coverage key",
        "top_level_keys": sorted(list(root.keys()))[:30],
    }))
    sys.exit(1)
print(json.dumps({
    "branch_percent": round(branch, 2),
    "line_percent":   round(line if line is not None else 0.0, 2),
    "line_resolved":  line is not None,
}))
PY
) || PARSE_RC=$?

if [[ $PARSE_RC -ne 0 || -z "$COVERAGE_JSON" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "could not parse gcovr output: $COVERAGE_JSON${INC_SUFFIX}"
    exit 2
fi

BRANCH_PCT=$(echo "$COVERAGE_JSON" | python3 -c "import json, sys; print(json.load(sys.stdin)['branch_percent'])")
LINE_PCT=$(echo "$COVERAGE_JSON" | python3 -c "import json, sys; print(json.load(sys.stdin)['line_percent'])")
LINE_RESOLVED=$(echo "$COVERAGE_JSON" | python3 -c "import json, sys; print(json.load(sys.stdin).get('line_resolved', False))")

echo "coverage-gate: branch=$BRANCH_PCT% line=$LINE_PCT% (line_resolved=$LINE_RESOLVED)" | tee -a "$GATE_LOG"

# An inconclusive run records NO ordinary metric and is not compared: a metric
# row carries no qualification, so a low figure from partial data would read as
# a real regression in every trend query.
if (( ${#INCONCLUSIVE[@]} )); then
    REASONS=$(printf '%s; ' "${INCONCLUSIVE[@]}")
    REASONS=${REASONS%; }
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    if [[ $CAPTURE -eq 1 ]]; then
        # UP-18 / co-2 / sre-3: refuse to capture a baseline from a broken env.
        # A capture that succeeds on partial data permanently anchors a false
        # low coverage number and silently disables the gate for the audit
        # window. Operator must `--capture-baselines` on a known-clean tree.
        NOTE="refused --capture-baselines: inconclusive run ($REASONS); fix the cause listed and re-run on a quiet box; see $GATE_LOG"
        echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
        write_gate FAIL "$GATE_DUR" "$NOTE"
        exit 1
    fi
    NOTE="inconclusive: $REASONS; ${BRANCH_PCT}% branch measured from incomplete data, not compared with the baseline and not recorded as a metric. See $GATE_LOG (meson testlog: $TESTLOG); re-run once the cause is fixed or the box is quiet"
    echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
    write_gate WARN "$GATE_DUR" "$NOTE"
    exit "$REFUSE_EXIT"
fi

write_metric branch_coverage_overall "$BRANCH_PCT" "%"
# Never record an unknown as a number: gcovr's summary can lack line_percent.
if [[ "$LINE_RESOLVED" == "True" ]]; then
    write_metric line_coverage_overall "$LINE_PCT" "%"
else
    echo "coverage-gate: line coverage not reported by gcovr; line_coverage_overall not recorded" | tee -a "$GATE_LOG"
fi

# ── Capture mode: rewrite baseline and exit ─────────────────────────────

if [[ $CAPTURE -eq 1 ]]; then
    # The baseline carries a line figure too; do not anchor an unknown as 0.0.
    if [[ "$LINE_RESOLVED" != "True" ]]; then
        GATE_DUR=$(( $(date +%s) - GATE_START ))
        NOTE="refused --capture-baselines: gcovr did not report line coverage, so the baseline's line_percent would be fabricated"
        echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
        write_gate FAIL "$GATE_DUR" "$NOTE"
        exit 1
    fi

    # Diff old vs new if a prior baseline exists (hp-S1).
    # sec-h-1: pass $BASELINE via sys.argv, not string interpolation —
    # an operator-controlled path containing a single quote would break
    # out of the Python literal and execute arbitrary code.
    OLD_BRANCH=""
    OLD_LINE=""
    if [[ -f "$BASELINE" ]]; then
        OLD_BRANCH=$(python3 - "$BASELINE" 2>/dev/null <<'PY' || echo "?"
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("branch_percent", "?"))
except Exception:
    print("?")
PY
)
        OLD_LINE=$(python3 - "$BASELINE" 2>/dev/null <<'PY' || echo "?"
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("line_percent", "?"))
except Exception:
    print("?")
PY
)
        echo "coverage-gate: diff branch $OLD_BRANCH% → $BRANCH_PCT%, line $OLD_LINE% → $LINE_PCT%" | tee -a "$GATE_LOG"
    fi

    echo "coverage-gate: --capture-baselines set — rewriting $BASELINE"
    python3 - "$BASELINE" "$GCOVR_JSON" "$BRANCH_PCT" "$LINE_PCT" "$YUZU_ROOT" <<'PY'
import json, os, subprocess, sys, time
path, summary_path, branch_pct, line_pct, repo = sys.argv[1:]
try:
    commit = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True
    ).strip()
except Exception:
    commit = "unknown"
baseline = {
    "__schema": "coverage-baseline/v1",
    "__doc": (
        "Locked branch coverage baseline enforced by "
        "scripts/test/coverage-gate.sh. Regenerate with "
        "'bash scripts/test/coverage-gate.sh --run-id manual --capture-baselines' "
        "then commit this file alongside the change that earned the new baseline. "
        "Hardware fingerprint deliberately omitted — line-level coverage is "
        "compiler-deterministic, unlike perf timings."
    ),
    "captured_at": int(time.time()),
    "captured_commit": commit,
    "branch_percent": float(branch_pct),
    "line_percent": float(line_pct),
    "slack_pp": 0.5,
}
# Pretty-print to keep git diffs readable. Write beside the target and rename, so an
# interrupted or ENOSPC capture cannot leave a truncated baseline behind.
tmp = f"{path}.tmp{os.getpid()}"
try:
    with open(tmp, "w") as f:
        json.dump(baseline, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
except Exception as e:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    print(f"coverage-gate: baseline write failed: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
print(f"coverage-gate: wrote baseline to {path}")
PY
    CAPTURE_RC=$?
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    if [[ $CAPTURE_RC -ne 0 ]]; then
        NOTE="--capture-baselines could not write $BASELINE (is its directory writable and not full?); the existing baseline is unchanged"
        echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
        write_gate FAIL "$GATE_DUR" "$NOTE"
        exit 1
    fi
    write_gate PASS "$GATE_DUR" "captured baseline at ${BRANCH_PCT}% branch / ${LINE_PCT}% line"
    exit 0
fi

# ── Compare against baseline ───────────────────────────────────────────

if [[ ! -f "$BASELINE" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    write_gate WARN "$GATE_DUR" "no baseline at $BASELINE — run with --capture-baselines to create one"
    exit 2
fi

# UP-10 / co-2 / sre-2: honor the __seed sentinel. A seed baseline is a
# placeholder shipped with PR2 to make the gates' first run trivially
# pass on a fresh clone. It has slack_pp=100 and branch_percent=0, which
# means EVERY coverage value passes. That's intentional for the first-ship
# semantics, but it's CRITICAL that operators see a WARN rather than a
# misleading green PASS while the seed is in place — otherwise an unwary
# operator (or auditor) thinks enforcement is active when it isn't.
# Detect __seed and return WARN with a clear message.
# sec-h-1: $BASELINE is operator-controlled — pass via sys.argv, not
# string interpolation, to block code injection via path names with
# embedded single quotes.
SEED_FLAG=$(python3 - "$BASELINE" 2>/dev/null <<'PY' || echo "false"
import json, sys
try:
    with open(sys.argv[1]) as f:
        print("true" if json.load(f).get("__seed") else "false")
except Exception:
    print("false")
PY
)
if [[ "$SEED_FLAG" == "true" ]]; then
    GATE_DUR=$(( $(date +%s) - GATE_START ))
    NOTE="seed baseline active (${BRANCH_PCT}% measured) — enforcement disabled until 'coverage-gate.sh --capture-baselines'"
    echo "coverage-gate: $NOTE" | tee -a "$GATE_LOG"
    write_gate WARN "$GATE_DUR" "$NOTE"
    exit 2
fi

COMPARE_RC=0
RESULT=$(python3 - "$BASELINE" "$BRANCH_PCT" "$SLACK_PP" <<'PY'
import json, math, sys
baseline_path, branch_pct, slack_pp = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
try:
    with open(baseline_path) as f:
        baseline = json.load(f)
except Exception as e:
    print(f"WARN baseline {baseline_path} is unreadable ({type(e).__name__}); re-capture with --capture-baselines")
    sys.exit(2)
def num(v):
    # JSON true/false are Python ints and a string coerces: neither is a number here.
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError("not a number")
    return float(v)
if not math.isfinite(branch_pct):
    print(f"WARN measured branch coverage {branch_pct} is not finite; nothing was compared")
    sys.exit(2)
try:
    b = num(baseline.get("branch_percent", 0.0))
except Exception as e:
    print(f"WARN baseline {baseline_path} has an invalid branch_percent ({type(e).__name__}); re-capture with --capture-baselines")
    sys.exit(2)
# sec-L4: guard against pathological baselines. A negative or NaN
# baseline can't be compared; a zero baseline with non-seed metadata
# is almost certainly a broken capture and should be rejected.
if not math.isfinite(b) or b < 0:
    print(f"WARN baseline branch_percent={b} is not finite/non-negative — re-capture")
    sys.exit(2)
if b == 0.0:
    print(f"WARN baseline branch_percent=0 without __seed flag — suspicious, re-capture")
    sys.exit(2)
try:
    effective_slack = num(baseline["slack_pp"]) if "slack_pp" in baseline else slack_pp
except Exception as e:
    print(f"WARN baseline {baseline_path} has an invalid slack_pp ({type(e).__name__}); re-capture with --capture-baselines")
    sys.exit(2)
if not math.isfinite(effective_slack) or effective_slack < 0 or effective_slack > 50:
    print(f"WARN baseline slack_pp={effective_slack} out of [0,50] — suspicious, re-capture")
    sys.exit(2)
floor = b - effective_slack
if branch_pct + 1e-9 < floor:
    print(f"FAIL {branch_pct:.2f} vs {b:.2f} (floor {floor:.2f}, slack {effective_slack})")
    sys.exit(1)
print(f"PASS {branch_pct:.2f} vs {b:.2f} (floor {floor:.2f}, slack {effective_slack})")
PY
) || COMPARE_RC=$?
echo "coverage-gate: $RESULT" | tee -a "$GATE_LOG"

GATE_DUR=$(( $(date +%s) - GATE_START ))

if [[ $REPORT_ONLY -eq 1 ]]; then
    if [[ $COMPARE_RC -eq 2 ]]; then
        # An unreadable or pathological baseline is a WARN, never a PASS row.
        write_gate WARN "$GATE_DUR" "report-only: ${BRANCH_PCT}% branch ($RESULT)"
        exit "$REFUSE_EXIT"
    fi
    write_gate PASS "$GATE_DUR" "report-only: ${BRANCH_PCT}% branch ($RESULT)"
    exit 0
fi

# Compare python exits: 0 PASS, 1 FAIL (regression), 2 WARN (pathological baseline).
case $COMPARE_RC in
    0)
        write_gate PASS "$GATE_DUR" "$RESULT"
        exit 0
        ;;
    2)
        write_gate WARN "$GATE_DUR" "$RESULT"
        exit 2
        ;;
    *)
        write_gate FAIL "$GATE_DUR" "$RESULT"
        exit 1
        ;;
esac
