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
#   --slack-pp F      — pp tolerance for regression (default: 0.5)
#   --capture-baselines — rewrite baseline from current run
#   --report-only     — parse + record metric, don't enforce baseline
#
# Environment:
#   YUZU_COVERAGE_TIMEOUT_MULT — number >= 1 passed to
#                       `meson test --timeout-multiplier` (default: 3)
#   YUZU_COVERAGE_MIN_FREE_KB — free KB the build filesystem must still have
#                       after the run, else the run is inconclusive (default:
#                       262144)
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
#   0  coverage measured and within tolerance (or --report-only), or under
#      --report-only a refusal / inconclusive run (the WARN row is the record)
#   1  coverage regressed beyond slack, or --capture-baselines was refused
# 129/130/143  interrupted (SIGHUP / SIGINT / SIGTERM): meson was terminated and
#      the lock released before exit
#   2  environmental refusal (missing tool, bad configuration, another run holds
#      the build dir), an inconclusive run, a build/gcovr/parse failure, or a
#      gate/metric DB write that failed (WARN row; also turns an exit 0 into 2)
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
  --slack-pp F           (default: 0.5)
  --capture-baselines    rewrite baseline from current run (then PASS)
  --report-only          parse + record metric, don't enforce baseline
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)             RUN_ID="$2"; shift 2 ;;
        --build-dir)          BUILD_DIR="$2"; shift 2 ;;
        --baseline)           BASELINE="$2"; shift 2 ;;
        --slack-pp)           SLACK_PP="$2"; shift 2 ;;
        --capture-baselines)  CAPTURE=1; shift ;;
        --report-only)        REPORT_ONLY=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        *)                    echo "coverage-gate: unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

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
BUILD_DIR_ABS=$(readlink -f "$BUILD_DIR" 2>/dev/null || echo "$BUILD_DIR")
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
# reason (missing tool, bad configuration, another run holding the build dir,
# an inconclusive result). In --report-only (the default-mode caller wraps the
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

write_gate() {
    local status="$1" duration="$2" notes="$3"
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

# One EXIT handler: release the build-dir lock (if this run holds it) and turn
# an exit-0 whose DB write failed into exit 2.
LOCK_HELD=0
LOCK_PATH=""
LOCK_GUARD=""
TEST_PID=""
on_exit() {
    local rc=$?
    # Cleanup must finish: a second INT/TERM/HUP here would abort it, leak the lock
    # and leave meson running.
    trap '' INT TERM HUP
    # An orphaned `meson test` would keep writing counters after the lock is
    # gone and corrupt the next run. meson terminates its own test children on
    # SIGTERM, so forward it and wait.
    if [[ -n "$TEST_PID" ]]; then
        kill -TERM "$TEST_PID" 2>/dev/null || true
        # Bounded: a meson that ignores TERM is killed after the grace period
        # rather than holding this handler (and the lock) forever.
        local waited=0 grace=$(( ${YUZU_COVERAGE_KILL_GRACE_SECS:-30} * 10 ))
        while kill -0 "$TEST_PID" 2>/dev/null && (( waited < grace )); do
            sleep 0.1; waited=$(( waited + 1 ))
        done
        kill -0 "$TEST_PID" 2>/dev/null && kill -KILL "$TEST_PID" 2>/dev/null
        wait "$TEST_PID" 2>/dev/null || true
        TEST_PID=""
    fi
    # Ownership alone decides (not LOCK_HELD): a signal landing between taking the
    # lock and recording it must not leak the lock.
    if [[ -n "$LOCK_PATH" && "$(readlink "$LOCK_PATH" 2>/dev/null)" == "$$" ]]; then
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
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

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
    # Refuse a bad multiplier BEFORE the long build. meson rejects a non-number
    # and crashes on a very long digit string (zero tests run, then gcovr reads
    # an empty tree and reports ~0%), treats 0 or a negative value as "no
    # timeout at all" (a hung test would hang the gate with no outer bound), and
    # a value under 1 would shorten every test's budget below its own. Accept
    # only a number >= 1 with at most 6 digits on each side of the point.
    if [[ ! "$MIN_FREE_KB" =~ ^[0-9]{1,12}$ ]]; then
        echo "coverage-gate: YUZU_COVERAGE_MIN_FREE_KB='${MIN_FREE_KB//[^[:print:]]/?}' must be a whole number of KB" | tee -a "$GATE_LOG"
        write_gate WARN 0 "invalid YUZU_COVERAGE_MIN_FREE_KB"
        exit "$tool_miss_exit"
    fi
    if [[ ! "$TIMEOUT_MULT" =~ ^[1-9][0-9]{0,5}(\.[0-9]{1,6})?$ ]]; then
        echo "coverage-gate: YUZU_COVERAGE_TIMEOUT_MULT='${TIMEOUT_MULT//[^[:print:]]/?}' must be a number >= 1 (digits only, at most 6 before and after the point)" | tee -a "$GATE_LOG"
        write_gate WARN 0 "invalid YUZU_COVERAGE_TIMEOUT_MULT"
        exit "$tool_miss_exit"
    fi
}

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
    ln -sn -- "$$" "$LOCK_PATH" 2>/dev/null && return 0
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
                if ln -sn -- "$$" "$LOCK_PATH" 2>/dev/null; then
                    rm -f "$LOCK_GUARD"
                    return 0
                fi
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
    LOCK_HELD=1
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
if ! find -H "$BUILD_DIR" -name '*.gcda' -type f -delete 2>>"$GATE_LOG"; then
    echo "coverage-gate: WARNING could not delete every stale .gcda under $BUILD_DIR; counters from an earlier run may remain" | tee -a "$GATE_LOG"
fi
# Instrumented (-Db_coverage) binaries run slower than the normal build, and a
# loaded host slower still: the pg shards hit their 700s budget and the 60s/90s
# smoke tests timed out on a busy box, truncating the gcda data (a test killed
# on timeout writes none). nightly.yml uses 2; default higher here because a
# local run shares the box. Override with YUZU_COVERAGE_TIMEOUT_MULT, which
# tool_check() has already validated as a number >= 1.
echo "coverage-gate: meson test --timeout-multiplier $TIMEOUT_MULT" | tee -a "$GATE_LOG"
# A background job we `wait` on, so a signal to this script reaches the EXIT
# handler (which terminates meson) instead of being deferred until meson ends.
# Subshell + exec: a background job of a non-interactive shell starts with SIGINT
# and SIGQUIT ignored, which every test would inherit. `trap - INT QUIT` restores
# them on bash >= 4.4; macOS /bin/bash 3.2 keeps them ignored (same as before).
( trap - INT QUIT; exec meson test -C "$BUILD_DIR" --no-rebuild --print-errorlogs \
    --timeout-multiplier "$TIMEOUT_MULT" ) >> "$GATE_LOG" 2>&1 &
TEST_PID=$!
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
        NOTE="refused --capture-baselines: inconclusive run ($REASONS) — fix the cause listed and re-run on a quiet box; see $GATE_LOG"
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
with open(tmp, "w") as f:
    json.dump(baseline, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, path)
print(f"coverage-gate: wrote baseline to {path}")
PY
    GATE_DUR=$(( $(date +%s) - GATE_START ))
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
    print(f"WARN baseline {baseline_path} is unreadable ({type(e).__name__}) — re-capture with --capture-baselines")
    sys.exit(2)
b = float(baseline.get("branch_percent", 0.0))
# sec-L4: guard against pathological baselines. A negative or NaN
# baseline can't be compared; a zero baseline with non-seed metadata
# is almost certainly a broken capture and should be rejected.
if not math.isfinite(b) or b < 0:
    print(f"WARN baseline branch_percent={b} is not finite/non-negative — re-capture")
    sys.exit(2)
if b == 0.0:
    print(f"WARN baseline branch_percent=0 without __seed flag — suspicious, re-capture")
    sys.exit(2)
effective_slack = float(baseline.get("slack_pp", slack_pp))
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
