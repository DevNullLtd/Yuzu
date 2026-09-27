#!/usr/bin/env bash
# test_blocked_log_sink_sigterm.sh — #4666 PR-2 acceptance-evidence harness.
#
# Formalizes a manual repro of the blocked-log-sink SIGTERM scenario
# (main.cpp's async log hand-off, log_handoff.hpp): pre-fix (before that
# wiring), SIGTERM into an agent whose stderr sink is wedged behind a
# saturated pipe left the process alive well past a bound and needed
# SIGKILL; post-fix, the same scenario exits within a few seconds — either
# drained cleanly (exit 0) or via LogHandoff::teardown()'s own bounded
# watchdog firing (kLogTeardownExitCode == 5, log_handoff.hpp) — both are
# correct, BOUNDED outcomes under sustained blockage. A process still alive
# past the 8s bound asserted below is a real regression, not something any
# case here works around.
#
# CORRECTIONS FROM THE ORIGINAL MANUAL REPRO (found empirically while
# building this harness — see the per-scenario comments below for the full
# detail):
#   * The manual repro's own readiness loop (grep agent.log for the marker,
#     100 x 0.1s) never actually observed the marker -- it ran the full 10s
#     unconditionally and then sent SIGTERM regardless, so "readiness" there
#     was cosmetic, not gating. spdlog's plain rotating_file_sink has no
#     per-line auto-flush (unlike the color console sinks, which fflush()
#     every write -- ansicolor_sink-inl.h) -- at this agent's real startup
#     log volume, the libc stdio buffer backing the file sink often does not
#     fill for many seconds, so external `tail`/`grep` on the FILE can stay
#     blind long after the marker was actually logged. This harness uses a
#     log-INDEPENDENT readiness gate for every case where stderr itself is
#     the fault under test (see "BLOCKED-CASE READINESS" below) and polls
#     stderr directly (always flushed) everywhere else.
#   * "on the main thread" (of the wedged worker) does not hold post-fix:
#     the thread that blocks in pipe_write is LogHandoff's dedicated
#     thread_pool worker, not the process's main thread. This harness scans
#     every task under /proc/<pid>/task/*/wchan, not just the PID's own.
#
# BLOCKED-CASE READINESS (F1, F3, R2 -- every case that wedges stderr from
# process start): readiness is gated on "$dir/data/kv_store.db" existing on
# disk. AgentImpl::run() opens the KvStore immediately after logging the
# readiness marker itself (agent.cpp), and BEFORE main.cpp's signal handlers
# are installed only for the earlier agent-id resolution in make_agent() --
# by the time KvStore opens, handlers are live -- so this is a reliable,
# log-buffering-independent proxy for "the agent has genuinely started",
# confirmed against a real transcript while developing this harness.
#
# Linux-only: the blockage-detection mechanism (R2, and required for F1/F3)
# reads /proc/<pid>/task/*/wchan, which has no equivalent on macOS/Windows —
# gated in tests/meson.build on host_machine.system() == 'linux'.
#
# Cases (see docs/testing/unit-test-conventions.md for the skip-vs-fail
# convention this file follows — SKIP is `exit 0` with a `SKIP:`-prefixed
# message, matching every other shell test under tests/shell/, e.g.
# test_mfa_reset.sh / test_build_examples_gating.sh — NOT the exit-77
# Automake convention, which nothing else in this tree's shell suite uses):
#   P0    — healthy control (no injected fault): calibrates the bound the
#           fault cases are checked against and proves the harness itself
#           isn't just always-slow.
#   P1i   — no --log-file -> "Yuzu Agent v..." on stdout.
#   P1ii  — --log-file + console mode -> both file and stderr carry lines.
#   P1iii — --log-format json -> first log line parses as JSON with a
#           "timestamp" field.
#   P1iv  — --log-file pointed at an unopenable path -> the process still
#           starts (console fallback), fallback warning observed.
#   R1    — the readiness-marker poll helper: positive (marker seen) and
#           negative (bounded give-up, not a silent hang / false pass).
#   R2    — the /proc/*/wchan blockage-detection helper: two consecutive
#           ~0.5s-apart polls both showing a thread of the wedged agent
#           parked in pipe_write. SKIPs (not fails) if /proc/*/wchan isn't
#           readable in this sandbox.
#   F1a/b/c — the core acceptance evidence: SIGTERM (via `kill -TERM`, then
#           again via bare `kill`, then again with --log-format json) into
#           an agent whose stderr sink is wedged behind a saturated,
#           shrunk-buffer pipe. Must exit within 8s with code 0 or 5.
#   F2    — rotation-failure fault: a non-empty directory occupies the
#           rotation target path, forcing spdlog's rename to fail with
#           EISDIR on every attempt. Witnesses the failed-rotation ->
#           truncate-and-continue behavior (rotating_file_sink-inl.h), then
#           confirms a clean SIGTERM still works afterward.
#   F3    — F1 and F2's faults simultaneously; SIGTERM must still bound at
#           8s with code 0 or 5.
#
# Run:  bash tests/shell/test_blocked_log_sink_sigterm.sh <BUILDDIR> [CASE ...]

set -uo pipefail

usage() {
  echo "usage: $0 <BUILDDIR> [CASE ...]" >&2
  echo "  CASE one or more of: P0 P1i P1ii P1iii P1iv R1 R2 F1a F1b F1c F2 F3" >&2
  exit 2
}

(( $# >= 1 )) || usage
BUILDDIR="$1"; shift
BUILDDIR="$(cd "$BUILDDIR" 2>/dev/null && pwd)" || { echo "missing build dir: $1" >&2; exit 2; }

BIN="$BUILDDIR/agents/core/yuzu-agent"
[ -x "$BIN" ] || { echo "missing agent binary: $BIN (build with -Dbuild_tests=true -Dbuild_agent=true?)" >&2; exit 2; }

if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: python3 not on PATH — needed to shrink the stderr pipe buffer (F_SETPIPE_SZ) and to parse JSON log lines" >&2
  exit 0
fi

WORKROOT="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_blocked_log_sink.XXXXXX")"
[[ -n "$WORKROOT" && -d "$WORKROOT" ]] || { echo "mktemp -d failed" >&2; exit 2; }

# Real, fully-populated plugin directory (a symlink farm over every built
# agents/plugins/*/*.so) -- used ONLY by the blocked-stderr cases (F1, F3,
# R2), where reaching enough trace-level VOLUME to saturate the shrunk
# 4KiB pipe QUICKLY is load-bearing. With --plugin-dir pointing at an EMPTY
# directory (0 plugins, matching every other case here and the original
# manual repro this harness formalizes), the wedge took on the order of 20
# REAL SECONDS to engage in practice -- empirically measured while
# developing this harness; the reconnect loop's own exponential backoff
# accounts for most of that, since agent.cpp logs almost nothing during the
# ~6s of sequential AWS/Azure/GCP cloud-identity probing either. With all
# real plugins loaded (each one's PluginLoader::scan trace line adds
# volume), the wedge engages within ~200ms, reliably, every time measured --
# turning an ~8-30s fixture into one that fits comfortably inside the 8s
# bound these cases assert against. Built once, lazily; the plugin set does
# not vary per case.
REAL_PLUGIN_DIR="$WORKROOT/plugins-real"
mkdir -p "$REAL_PLUGIN_DIR"
for _so in "$BUILDDIR"/agents/plugins/*/*.so; do
  [ -e "$_so" ] || continue
  ln -sf "$_so" "$REAL_PLUGIN_DIR/$(basename "$_so")"
done
unset _so

# Backstop registry: every agent PID this run has launched and not yet
# reaped, so a Ctrl-C or an unexpected early exit never leaves a wedged
# agent process running after the script itself is gone. Entries are
# dropped as soon as `wait` genuinely reaps them (forget_launched_pid) --
# this repo's shared self-hosted runner boxes run several jobs as ONE OS
# identity (docs/testing/unit-test-conventions.md), so re-signaling an
# already-reaped PID risks hitting an unrelated, meanwhile-recycled process.
declare -a LAUNCHED_PIDS=()
forget_launched_pid() {
  local pid="$1" kept=() p
  for p in "${LAUNCHED_PIDS[@]:-}"; do
    [ -n "$p" ] && [ "$p" != "$pid" ] && kept+=("$p")
  done
  LAUNCHED_PIDS=("${kept[@]:-}")
}
cleanup() {
  local p
  for p in "${LAUNCHED_PIDS[@]:-}"; do
    [ -n "$p" ] || continue
    kill -9 "$p" 2>/dev/null || true
  done
  # Best-effort: release fd 9 if a case left it open on an abnormal exit path.
  exec 9<&- 2>/dev/null || true
  rm -rf "$WORKROOT" 2>/dev/null || true
}
trap cleanup EXIT

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_CASES=()

say()  { printf '  %s\n' "$*"; }
ok()   { PASS_COUNT=$((PASS_COUNT+1)); printf '  PASS: %s\n' "$*"; }
bad()  { FAIL_COUNT=$((FAIL_COUNT+1)); FAILED_CASES+=("$1"); printf '  FAIL: %s: %s\n' "$1" "$2"; }
skip() { SKIP_COUNT=$((SKIP_COUNT+1)); printf '  SKIP: %s: %s\n' "$1" "$2"; }

# On any FAIL, dump the tails of every capture file under the case's own
# directory — the shell precedent (test_pr2_gates.sh) prints inline context
# per scenario; a process-I/O harness needs the actual captured output, not
# just the assertion message, to debug a red run without re-executing it.
dump_case_transcripts() {
  local dir="$1"
  local f
  say "---- transcripts under $dir ----"
  for f in "$dir"/stdout.log "$dir"/stderr.log "$dir"/logs/agent*.log; do
    [ -f "$f" ] || continue
    say "-- tail -n 40 $f --"
    tail -n 40 "$f" | sed 's/^/    /'
  done
  say "---------------------------------"
}

new_case_dir() {
  local name="$1"
  local d="$WORKROOT/$name"
  mkdir -p "$d/data" "$d/plugins-empty" "$d/logs"
  printf '%s' "$d"
}

# Bounded poll: does `file` contain `pattern` (fixed string) within
# `timeout_s`? Never hangs past the bound — R1's own negative case pins this.
wait_for_pattern() {
  local file="$1" pattern="$2" timeout_s="${3:-10}"
  local max_polls=$(( timeout_s * 10 ))
  local i
  for ((i = 0; i < max_polls; i++)); do
    if [ -f "$file" ] && grep -qF -- "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# Bounded poll for a path's mere existence -- the BLOCKED-CASE READINESS gate
# (see module banner): filesystem-level, independent of any spdlog sink's
# own buffering.
wait_for_file_exists() {
  local file="$1" timeout_s="${2:-10}"
  local max_polls=$(( timeout_s * 10 ))
  local i
  for ((i = 0; i < max_polls; i++)); do
    [ -e "$file" ] && return 0
    sleep 0.1
  done
  return 1
}

# Starts yuzu-agent with stdout/stderr captured to plain files (no induced
# blockage). Sets AGENT_PID / AGENT_STDOUT_FILE / AGENT_STDERR_FILE. Must run
# directly in this shell (not a command substitution) so `$!`/`wait` below
# see the real job.
start_agent_plain() {
  local dir="$1"; shift
  AGENT_STDOUT_FILE="$dir/stdout.log"
  AGENT_STDERR_FILE="$dir/stderr.log"
  "$BIN" --server 127.0.0.1:1 --no-tls \
    --data-dir "$dir/data" --plugin-dir "$dir/plugins-empty" \
    "$@" \
    >"$AGENT_STDOUT_FILE" 2>"$AGENT_STDERR_FILE" &
  AGENT_PID=$!
  LAUNCHED_PIDS+=("$AGENT_PID")
}

# Opens a FIFO read-write on fd 9 (so it succeeds immediately with no other
# writer required -- a read-only open here would deadlock the whole script,
# since nothing else opens the write end until the agent process itself does,
# started by the caller AFTER this returns) and shrinks its kernel pipe
# buffer to 4KiB. VERIFIES the shrink actually took (F_GETPIPE_SZ readback),
# not just that the python3 call ran: silently keeping the OS default (64KiB
# on this box) would mean trace-level startup logging alone might never
# saturate it, and every case built on this fixture would go green for the
# wrong reason (the sink never actually wedges). A shrink failure is a
# harness/environment defect, not a test result -- exit 2, not a FAIL.
# Sets BLOCKED_FIFO_PATH.
open_blocked_fifo() {
  local dir="$1"
  local fifo="$dir/stderr.fifo"
  mkfifo "$fifo"
  exec 9<>"$fifo"
  if ! python3 -c "
import fcntl, sys
F_SETPIPE_SZ = 1031
F_GETPIPE_SZ = 1032
fcntl.fcntl(9, F_SETPIPE_SZ, 4096)
actual = fcntl.fcntl(9, F_GETPIPE_SZ)
sys.exit(0 if actual <= 4096 else 1)
" 9<>"$fifo"; then
    echo "harness error: could not shrink+verify the stderr FIFO's kernel pipe buffer to <=4096 bytes (F_SETPIPE_SZ/F_GETPIPE_SZ) -- the blocked-sink fixture would silently never engage, making every case built on it meaningless" >&2
    exit 2
  fi
  BLOCKED_FIFO_PATH="$fifo"
}

# Best-effort: after the agent behind a blocked FIFO is dead (or right
# before sending the terminating signal, on a case that's about to fail),
# drain whatever is still sitting in the pipe into stderr.log so
# dump_case_transcripts has real content to show on a red run -- otherwise a
# wedged case's "stderr" is invisible (it never reached a plain capture
# file). Uses bash's own `read -t` (bounded per-line wait), NOT `dd
# iflag=nonblock`: empirically, on this box's `dd` (uutils coreutils, a Rust
# reimplementation -- `dd --version`), `iflag=nonblock` against a read-write
# self-referencing FIFO fd simply HUNG (even with data already sitting in
# the pipe) rather than returning once no more data was available -- found
# while developing this harness when it stalled the whole run indefinitely.
drain_fifo_leftovers() {
  local dir="$1"
  local line
  {
    while IFS= read -r -t 0.3 line <&9; do
      printf '%s\n' "$line" >> "$dir/stderr.log"
    done
  } 2>/dev/null || true
}

close_blocked_fifo() {
  exec 9<&- 2>/dev/null || true
}

# Sends a signal to $1 (either "-TERM" or "" for a bare `kill`, matching F1's
# ask to exercise both forms) and polls at 0.5s steps for up to $3 seconds.
# Sets RESULT_ELAPSED / RESULT_EXITCODE / RESULT_STILL_ALIVE.
terminate_and_wait() {
  local pid="$1" sig_args="$2" bound_s="$3"
  local t0 i max_polls
  t0=$(date +%s)
  if [ -n "$sig_args" ]; then
    kill "$sig_args" "$pid" 2>/dev/null || true
  else
    kill "$pid" 2>/dev/null || true
  fi
  max_polls=$(( bound_s * 2 ))
  RESULT_STILL_ALIVE=1
  for ((i = 0; i < max_polls; i++)); do
    sleep 0.5
    if ! kill -0 "$pid" 2>/dev/null; then
      RESULT_STILL_ALIVE=0
      break
    fi
  done
  RESULT_ELAPSED=$(( $(date +%s) - t0 ))
  if [ "$RESULT_STILL_ALIVE" = "0" ]; then
    wait "$pid" 2>/dev/null
    RESULT_EXITCODE=$?
    forget_launched_pid "$pid"
  else
    RESULT_EXITCODE=""
  fi
}

# Final safety net for a case that's already done with its process (whether
# terminate_and_wait reaped it or not) — idempotent, guarded so it can never
# signal a PID this run didn't itself observe as still alive.
hard_kill_backstop() {
  local pid="$1"
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    forget_launched_pid "$pid"
  fi
}

# Shared post-SIGTERM assertion for the no-injected-fault cases (P0, P1*):
# must exit within `bound`s with code 0.
assert_clean_exit() {
  local name="$1" bound="$2"
  if [ "$RESULT_STILL_ALIVE" = "1" ]; then
    bad "$name" "still alive ${RESULT_ELAPSED}s after SIGTERM (bound ${bound}s, no fault injected)"
    return 1
  elif [ "$RESULT_EXITCODE" != "0" ]; then
    bad "$name" "exited in ${RESULT_ELAPSED}s but with code $RESULT_EXITCODE (want 0, no fault injected)"
    return 1
  fi
  ok "$name: exited cleanly in ${RESULT_ELAPSED}s (code 0)"
  return 0
}

# Shared post-SIGTERM assertion for the fault-injected cases (F1*, F2, F3):
# must exit within `bound`s with code 0 or 5 (see the module banner).
assert_bounded_fault_exit() {
  local name="$1" bound="$2"
  if [ "$RESULT_STILL_ALIVE" = "1" ]; then
    bad "$name" "still alive ${RESULT_ELAPSED}s after SIGTERM with a fault injected — this is the exact pre-fix regression this harness exists to catch"
    return 1
  elif [[ " 0 5 " != *" $RESULT_EXITCODE "* ]]; then
    bad "$name" "exited in ${RESULT_ELAPSED}s but with unexpected code $RESULT_EXITCODE (want 0 -- drained -- or 5 -- log-teardown watchdog, kLogTeardownExitCode)"
    return 1
  fi
  ok "$name: exited in ${RESULT_ELAPSED}s with code $RESULT_EXITCODE (bound ${bound}s)"
  return 0
}

# ── R2's mechanism: a single scan of every thread's wchan ──────────────────
# Return via $?: 0 = pipe_write found on >=1 task; 1 = scanned OK, none
# blocked; 2 = the mechanism is unavailable (nothing under task/*/wchan was
# readable at all — permission, or no /proc, or the process is already gone).
# Deliberately scans EVERY task, not just the PID's own: post-fix, the
# thread that blocks in pipe_write is LogHandoff's dedicated thread_pool
# worker, never the process's main thread (see the module banner).
#
# Matches *pipe_write* (substring), NOT an exact "pipe_write" equality --
# found empirically while developing this harness (a synthetic FIFO-writer
# repro, isolated from the agent, confirmed the FIFO/shrink/blocking
# mechanism itself works, but /proc/<pid>/task/<tid>/wchan on THIS box's
# kernel (7.0.0, `uname -r`) reports "anon_pipe_write", not "pipe_write" --
# an exact-match check silently never fired, which is exactly the kind of
# false-negative this harness exists to catch elsewhere; do not narrow this
# back to an exact match without re-verifying against the kernel this runs
# on, since the symbol name is not a stable ABI across kernel versions.
scan_pipe_write_once() {
  local pid="$1"
  local any_readable=0 found=0
  local f w
  for f in /proc/"$pid"/task/*/wchan; do
    [ -e "$f" ] || continue
    if w=$(cat "$f" 2>/dev/null); then
      any_readable=1
      [[ "$w" == *pipe_write* ]] && found=1
    fi
  done
  [ "$any_readable" = "1" ] || return 2
  [ "$found" = "1" ] && return 0
  return 1
}

# Cheap capability probe against THIS shell's own process: if we can't even
# read our own /proc/<pid>/task/*/wchan, the mechanism is unavailable in this
# sandbox (permissions), or /proc isn't the Linux procfs shape this harness
# assumes at all.
wchan_probe_available() {
  scan_pipe_write_once "$$"
  [ "$?" != 2 ]
}

# R2's bounded, two-consecutive-polls confirmation (a single sample can catch
# a thread transiently mid-syscall-entry/exit). Return via $?: 0 = confirmed;
# 1 = bound elapsed with no two-in-a-row match; 2 = mechanism unavailable.
wait_for_pipe_write_block() {
  local pid="$1" timeout_s="${2:-5}"
  local max_polls=$(( timeout_s * 2 ))
  local i prev_hit=0 rc
  for ((i = 0; i < max_polls; i++)); do
    scan_pipe_write_once "$pid"
    rc=$?
    [ "$rc" = 2 ] && return 2
    if [ "$rc" = 0 ]; then
      [ "$prev_hit" = "1" ] && return 0
      prev_hit=1
    else
      prev_hit=0
    fi
    sleep 0.5
  done
  return 1
}

# Used by every blocked-stderr case (F1/F3, and required by R2's own
# purpose): if /proc/*/wchan is usable, REQUIRE a confirmed wedge (a
# fixture that silently failed to engage would make the caller's later
# bounded-exit assertion vacuous -- proving nothing) — return 1 so the
# caller FAILs loudly instead. If the mechanism is unavailable in this
# sandbox, fall back to a fixed delay past readiness (long enough for
# trace-level output to saturate the shrunk 4KiB pipe) with a printed note,
# since there is no way to independently verify the fixture here.
confirm_wedge_engaged() {
  local pid="$1" name="$2" timeout_s="${3:-8}"
  if wchan_probe_available; then
    wait_for_pipe_write_block "$pid" "$timeout_s"
    local rc=$?
    if [ "$rc" = 0 ]; then
      return 0
    elif [ "$rc" = 2 ]; then
      say "$name: /proc/$pid/task/*/wchan became unreadable mid-test -- falling back to a fixed 5s delay instead of a confirmed wedge"
      sleep 5
      return 0
    fi
    return 1
  fi
  say "$name: /proc/*/wchan unavailable in this sandbox -- falling back to a fixed 5s delay after readiness instead of a confirmed wedge (cannot independently verify the fixture engaged here)"
  sleep 5
  return 0
}

readiness_marker="Yuzu agent starting (id="

# ── P0: healthy control ─────────────────────────────────────────────────
#
# Readiness is polled on STDERR, not the --log-file: spdlog's
# rotating_file_sink has no per-line auto-flush (unlike the color console
# sinks, which fflush() after every write -- ansicolor_sink-inl.h), so at
# plain --log-level info's modest startup volume the file sink's libc stdio
# buffer may simply never fill before a short poll bound gives up --
# empirically reproduced while developing this harness (the file stayed
# completely empty to an external reader for the whole run, while stderr
# already showed everything; see the module banner's discovery note).
# LogHandoff::teardown()'s T1 step (logger_->flush(), log_handoff.hpp)
# guarantees every sink -- including the file -- is flushed by the time a
# clean SIGTERM exit is observed, so the trailer check below reads the file
# only AFTER that has happened.
scenario_P0() {
  local name="P0"
  local dir; dir="$(new_case_dir p0)"
  local logfile="$dir/logs/agent.log"
  start_agent_plain "$dir" --log-level info --log-file "$logfile" \
    --log-max-size 1048576 --log-max-files 2
  local pid=$AGENT_PID

  if ! wait_for_pattern "$AGENT_STDERR_FILE" "$readiness_marker" 10; then
    bad "$name" "readiness marker never appeared on stderr within 10s -- calibration failure, the harness itself may be broken"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    return
  fi

  # Bound is 8s, not a tighter one: SIGTERM can land mid the sequential
  # AWS/Azure/GCP cloud-identity metadata probes agent.cpp runs during
  # startup (~2s each, not interruptible mid-probe), observed pushing a
  # healthy exit to 4s+ in practice while developing this harness.
  terminate_and_wait "$pid" "-TERM" 8
  if ! assert_clean_exit "$name" 8; then
    dump_case_transcripts "$dir"
  elif grep -qF "$readiness_marker" "$logfile" 2>/dev/null && \
       tail -n 3 "$logfile" | grep -qF "Yuzu agent stopped"; then
    ok "${name}-trailer: agent.log (read post-exit, once teardown's flush is guaranteed to have run) carries the readiness marker and ends with 'Yuzu agent stopped'"
  else
    bad "${name}-trailer" "agent.log (read post-exit) is missing the readiness marker and/or a 'Yuzu agent stopped' trailer near its end"
    dump_case_transcripts "$dir"
  fi
  hard_kill_backstop "$pid"
}

# ── P1: flag-routing sanity ─────────────────────────────────────────────
scenario_P1i() {
  local name="P1i"
  local dir; dir="$(new_case_dir p1i)"
  start_agent_plain "$dir" --log-level info
  local pid=$AGENT_PID

  if ! wait_for_pattern "$AGENT_STDOUT_FILE" "$readiness_marker" 10; then
    bad "$name" "readiness marker never appeared on stdout (no --log-file -> console-only sink expected)"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    return
  fi
  if grep -qF "Yuzu Agent v" "$AGENT_STDOUT_FILE"; then
    ok "$name: no --log-file -> 'Yuzu Agent v...' observed on stdout"
  else
    bad "$name" "stdout never carried 'Yuzu Agent v' despite no --log-file"
    dump_case_transcripts "$dir"
  fi

  terminate_and_wait "$pid" "-TERM" 8
  assert_clean_exit "${name}-exit" 8
  hard_kill_backstop "$pid"
}

scenario_P1ii() {
  local name="P1ii"
  local dir; dir="$(new_case_dir p1ii)"
  local logfile="$dir/logs/agent.log"
  start_agent_plain "$dir" --log-level info --log-file "$logfile" \
    --log-max-size 1048576 --log-max-files 2
  local pid=$AGENT_PID

  # Readiness is polled on stderr, not the file -- see P0's comment. The
  # file half of "both file and stderr carry lines" is checked POST-EXIT
  # below, once LogHandoff::teardown()'s flush is guaranteed to have run.
  if ! wait_for_pattern "$AGENT_STDERR_FILE" "$readiness_marker" 10; then
    bad "$name" "readiness marker never appeared on stderr"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    return
  fi
  ok "${name}-stderr: --log-file + console mode -> stderr carries lines"

  terminate_and_wait "$pid" "-TERM" 8
  if assert_clean_exit "${name}-exit" 8; then
    if grep -qF "$readiness_marker" "$logfile" 2>/dev/null; then
      ok "${name}-file: agent.log (read post-exit) also carries the readiness line -- both file and stderr carry lines"
    else
      bad "${name}-file" "agent.log never carried the readiness line despite --log-file, even read post-exit"
      dump_case_transcripts "$dir"
    fi
  else
    dump_case_transcripts "$dir"
  fi
  hard_kill_backstop "$pid"
}

scenario_P1iii() {
  local name="P1iii"
  local dir; dir="$(new_case_dir p1iii)"
  local logfile="$dir/logs/agent.log"
  start_agent_plain "$dir" --log-level info --log-file "$logfile" \
    --log-max-size 1048576 --log-max-files 2 --log-format json
  local pid=$AGENT_PID

  # Same rationale as P0/P1ii: poll stderr (also JSON-formatted, and always
  # flushed per line) for readiness; read the file's first line only after a
  # confirmed clean exit, once teardown's flush is guaranteed to have run.
  if ! wait_for_pattern "$AGENT_STDERR_FILE" "$readiness_marker" 10; then
    bad "$name" "readiness marker never appeared on stderr under --log-format json"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    return
  fi

  terminate_and_wait "$pid" "-TERM" 8
  if ! assert_clean_exit "${name}-exit" 8; then
    dump_case_transcripts "$dir"
    hard_kill_backstop "$pid"
    return
  fi

  local first_line parse_err
  first_line="$(head -n 1 "$logfile")"
  parse_err="$dir/json_check.err"
  if printf '%s' "$first_line" | python3 -c '
import json, sys
obj = json.loads(sys.stdin.read())
assert "timestamp" in obj, "no timestamp field: " + repr(obj)
' 2>"$parse_err"; then
    ok "$name: first log line under --log-format json parses as JSON with a 'timestamp' field"
  else
    bad "$name" "first log line failed JSON/timestamp check: $(cat "$parse_err" 2>/dev/null) -- line was: $first_line"
    dump_case_transcripts "$dir"
  fi
  hard_kill_backstop "$pid"
}

scenario_P1iv() {
  local name="P1iv"
  local dir; dir="$(new_case_dir p1iv)"
  # A bare nonexistent PARENT DIRECTORY does NOT force a real open failure:
  # spdlog's file_helper::open() auto-creates missing parent directories
  # (os::create_dir(), file_helper-inl.h) before opening -- empirically
  # reproduced while developing this harness (the "nonexistent" directory
  # got silently created and the file opened fine, no fallback). What DOES
  # force a genuine, privilege-independent open failure (matching F2's own
  # "no chmod, root bypasses permissions" principle): a REGULAR FILE sitting
  # where a path component must be a directory. os::create_dir()'s own
  # per-component loop treats "already exists" (path_exists(), which stats
  # true for a file too, not just a directory) as success and skips mkdir()
  # for that component, so it silently does nothing here -- the following
  # fopen() on ".../blocker/agent.log" then fails ENOTDIR regardless of
  # privilege, exhausts file_helper::open()'s 5 retries (10ms apart), and
  # throws -- which is exactly LogHandoff::create()'s documented fallback
  # trigger.
  local blocker="$dir/logs/blocker"
  : > "$blocker"
  local badlog="$blocker/agent.log"
  start_agent_plain "$dir" --log-level info --log-file "$badlog" \
    --log-max-size 1048576 --log-max-files 2
  local pid=$AGENT_PID

  if ! wait_for_pattern "$AGENT_STDERR_FILE" "Failed to open log file" 10; then
    bad "$name" "fallback warning never appeared on stderr for an unopenable --log-file directory"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    return
  fi
  ok "${name}-stderr: process started and printed the log-file-open fallback warning on stderr"

  if wait_for_pattern "$AGENT_STDOUT_FILE" "Failed to open log file" 5; then
    ok "${name}-stdout: the fallback warning also reached the async console sink (stdout)"
  else
    bad "${name}-stdout" "fallback warning reached stderr (the synchronous std::cerr print) but never the async console sink"
    dump_case_transcripts "$dir"
  fi

  terminate_and_wait "$pid" "-TERM" 8
  assert_clean_exit "${name}-exit" 8
  hard_kill_backstop "$pid"
}

# ── R1: readiness-marker helper, positive + negative ────────────────────
# DEVIATION FROM THE DELIVERY PLAN'S WORDING ("appears in the log file"):
# console-only (no --log-file), polling stdout, for the SAME reason P0/P1ii
# read the file only post-exit -- see the module banner's discovery note.
# stdout always flushes per line (ansicolor_sink), so this genuinely proves
# wait_for_pattern's own bounded-poll mechanism works, without depending on
# spdlog's file-sink buffering timing.
scenario_R1() {
  local name="R1"
  local dir; dir="$(new_case_dir r1)"
  start_agent_plain "$dir" --log-level info
  local pid=$AGENT_PID

  if wait_for_pattern "$AGENT_STDOUT_FILE" "$readiness_marker" 10; then
    ok "${name}-positive: readiness marker observed within the bounded poll"
  else
    bad "${name}-positive" "readiness marker never appeared on stdout within 10s"
    dump_case_transcripts "$dir"
  fi
  terminate_and_wait "$pid" "-TERM" 8
  hard_kill_backstop "$pid"

  # Negative: wait_for_pattern must give up loudly and BOUNDED, never hang or
  # silently report success, when the marker genuinely never appears.
  local sentinel="$dir/logs/never_gets_the_marker.log"
  : > "$sentinel"
  local t0 elapsed
  t0=$(date +%s)
  if wait_for_pattern "$sentinel" "$readiness_marker" 2; then
    bad "${name}-negative" "wait_for_pattern reported success against a file that never contains the marker"
  else
    elapsed=$(( $(date +%s) - t0 ))
    if [ "$elapsed" -gt 6 ]; then
      bad "${name}-negative" "wait_for_pattern took ${elapsed}s to give up on a 2s bound -- not actually bounded"
    else
      ok "${name}-negative: wait_for_pattern correctly gave up after ~${elapsed}s instead of hanging or false-passing"
    fi
  fi
}

# ── R2: /proc/*/wchan blockage-detection helper ─────────────────────────
scenario_R2() {
  local name="R2"
  if ! wchan_probe_available; then
    skip "$name" "/proc/*/wchan is not readable in this sandbox -- the blockage-detection mechanism this harness depends on is unavailable here"
    return
  fi

  local dir; dir="$(new_case_dir r2)"
  open_blocked_fifo "$dir"
  # `9<&-` on the agent's own launch: without it the background process
  # INHERITS our fd 9 (a second, independent read-write handle on the same
  # FIFO), so closing OUR copy in close_blocked_fifo never actually drops
  # the pipe's reader count to zero from the agent's own perspective --
  # exactly why the original manual repro "needed SIGKILL even 5s after the
  # pipe was released" (the release never actually released anything the
  # agent itself held). This keeps the FIFO-release backstop meaningful.
  "$BIN" --server 127.0.0.1:1 --no-tls \
    --data-dir "$dir/data" --plugin-dir "$REAL_PLUGIN_DIR" \
    --log-level trace --log-file "$dir/logs/agent.log" \
    --log-max-size 1048576 --log-max-files 2 \
    2>"$BLOCKED_FIFO_PATH" 1>"$dir/stdout.log" 9<&- &
  local pid=$!
  LAUNCHED_PIDS+=("$pid")

  if ! wait_for_file_exists "$dir/data/kv_store.db" 10; then
    bad "$name" "$dir/data/kv_store.db never appeared -- cannot exercise the blockage probe (agent never reached KvStore::open in run())"
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    close_blocked_fifo
    return
  fi

  wait_for_pipe_write_block "$pid" 8
  local rc=$?
  if [ "$rc" = 2 ]; then
    skip "$name" "/proc/$pid/task/*/wchan became unreadable partway through the test"
  elif [ "$rc" = 0 ]; then
    ok "$name: observed a thread of pid $pid parked in pipe_write on two consecutive ~0.5s-apart polls while the stderr sink was wedged"
  else
    bad "$name" "never observed pipe_write on any thread of pid $pid within 8s of a wedged stderr sink"
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
  fi

  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  forget_launched_pid "$pid"
  close_blocked_fifo
}

# ── F1: the core blocked-sink SIGTERM acceptance evidence ───────────────
scenario_F1() {
  local suffix="$1" kill_style="$2" log_format="$3"
  local name="F1${suffix}"
  local dir; dir="$(new_case_dir "f1${suffix}")"
  local logfile="$dir/logs/agent.log"
  open_blocked_fifo "$dir"

  local extra=(--log-level trace --log-file "$logfile" --log-max-size 1048576 --log-max-files 2)
  [ -n "$log_format" ] && extra+=(--log-format "$log_format")

  # `9<&-` -- see R2's comment on why this is load-bearing for the
  # FIFO-release backstop, not just tidiness.
  "$BIN" --server 127.0.0.1:1 --no-tls \
    --data-dir "$dir/data" --plugin-dir "$REAL_PLUGIN_DIR" \
    "${extra[@]}" \
    2>"$BLOCKED_FIFO_PATH" 1>"$dir/stdout.log" 9<&- &
  local pid=$!
  LAUNCHED_PIDS+=("$pid")

  if ! wait_for_file_exists "$dir/data/kv_store.db" 10; then
    bad "$name" "$dir/data/kv_store.db never appeared (agent never reached KvStore::open in run())"
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    close_blocked_fifo
    return
  fi

  # REQUIRED, not best-effort: a fixture that never actually wedged would
  # make the bounded-exit assertion below vacuous (a healthy agent would
  # also exit in time) -- see confirm_wedge_engaged's own comment.
  if ! confirm_wedge_engaged "$pid" "$name" 8; then
    bad "$name" "never observed the stderr sink actually wedge (pipe_write on any task) within 8s -- the fixture itself didn't engage, so the SIGTERM timing below would prove nothing; not asserting it"
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    close_blocked_fifo
    forget_launched_pid "$pid"
    return
  fi

  case "$kill_style" in
    TERM) terminate_and_wait "$pid" "-TERM" 8 ;;
    bare) terminate_and_wait "$pid" "" 8 ;;
    *) echo "internal error: unknown kill_style $kill_style" >&2; exit 2 ;;
  esac

  if ! assert_bounded_fault_exit "$name" 8; then
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
  fi
  close_blocked_fifo
  hard_kill_backstop "$pid"
}

# ── F2: rotation-failure fault ───────────────────────────────────────────
scenario_F2() {
  local name="F2"
  local dir; dir="$(new_case_dir f2)"
  local logfile="$dir/logs/agent.log"
  start_agent_plain "$dir" --log-level trace --log-file "$logfile" \
    --log-max-size 1024 --log-max-files 1
  local pid=$AGENT_PID

  if ! wait_for_pattern "$AGENT_STDERR_FILE" "$readiness_marker" 10; then
    bad "$name" "readiness marker never appeared on stderr"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    return
  fi

  # Arm the fault only AFTER readiness: installing the blocker before the
  # process starts risks a race against spdlog's OWN early rotation --
  # rotate_() flushes already-buffered content to the file BEFORE attempting
  # the rename, so a marker that was about to be flushed could be flushed
  # and then immediately truncated away (on the failing branch,
  # file_helper_.reopen(true) truncates the active file right before
  # throwing) inside the same synchronous call, before any external poll of
  # ours could ever observe it.
  #
  # Placement is --log-max-files 1, not 2: with max-files >= 2, rotate_()'s
  # cascade loop (i = max_files_ down to 1) reaches i=2 FIRST on a rotation
  # that already has an agent.1.log present -- src=agent.1.log,
  # target=agent.2.log. path_exists() does not care whether src is a
  # directory or a file, and renaming an EXISTING DIRECTORY to a new,
  # nonexistent path SUCCEEDS -- so our blocker directory would itself get
  # renamed OUT of agent.1.log by that cascade step, silently vacating it
  # for the i=1 step (src=agent.log, target=agent.1.log) to succeed
  # normally right afterward. With max-files=1, rotate_()'s loop is a single
  # i=1 iteration -- agent.1.log is used ONLY as a rename TARGET, never a
  # cascade SOURCE -- confirmed empirically while developing this harness
  # (max-files=2 let the blocker "walk away" and rotation silently
  # succeeded; max-files=1 reproduces EISDIR every time).
  #
  # Installed with a short retry loop, forcibly clearing whatever's at the
  # path first: readiness (the stderr marker, ~line #5) and the FIRST
  # rotation (crossing --log-max-size=1024) can both happen within the SAME
  # ~100ms bash poll granularity at this agent's startup volume -- a plain
  # one-shot `mkdir` empirically lost this race outright (spdlog's own
  # unblocked rotation had already turned agent.1.log into a real file by
  # the time this ran, and `mkdir` on an existing non-directory path fails
  # silently under this script's `set -uo pipefail`, which has no `-e`) --
  # found while developing this harness. `rm -rf` before each attempt
  # guarantees a clean install regardless of what a preceding successful
  # rotation left there.
  local blocker="$dir/logs/agent.1.log"
  local armed=0 _try
  for _try in 1 2 3 4 5; do
    rm -rf "$blocker" 2>/dev/null
    mkdir -p "$blocker" 2>/dev/null
    : > "$blocker/placeholder" 2>/dev/null
    if [ -d "$blocker" ] && [ -e "$blocker/placeholder" ]; then
      armed=1
      break
    fi
    sleep 0.05
  done
  if [ "$armed" != "1" ]; then
    bad "${name}-witness" "could not install the rotation-blocker directory at $blocker after 5 attempts"
    dump_case_transcripts "$dir"
    terminate_and_wait "$pid" "-TERM" 8
    assert_bounded_fault_exit "${name}-sigterm" 8 || dump_case_transcripts "$dir"
    hard_kill_backstop "$pid"
    return
  fi

  # Let repeated rotation attempts fail (truncate-and-continue) for a bit,
  # gated on stderr's OWN growth (unwedged, same messages, always flushed)
  # as a volume proxy -- bounded so a stalled agent can't hang this case.
  # target_bytes is 2x --log-max-size, not 3x: this agent's initial startup
  # burst (0 plugins) plateaus around ~2.8KB and then goes nearly silent for
  # several seconds (the sequential AWS/Azure/GCP cloud-identity probes,
  # ~2s each -- see the module banner's discovery note), so a 3x (3072B)
  # target needed the reconnect loop to kick back in and occasionally missed
  # the 5s bound -- found while developing this harness. 2x (2048B) is
  # comfortably below that plateau and still clearly demonstrates repeated
  # growth past a single --log-max-size chunk.
  local target_bytes=$(( 1024 * 2 ))
  local waited_ms=0
  while [ "$waited_ms" -lt 5000 ]; do
    local stderr_sz; stderr_sz="$(stat -c %s "$AGENT_STDERR_FILE" 2>/dev/null || echo 0)"
    [ "$stderr_sz" -ge "$target_bytes" ] && break
    sleep 0.2
    waited_ms=$((waited_ms + 200))
  done

  if [ ! -d "$blocker" ]; then
    bad "${name}-witness" "rotation succeeded despite the directory blocker (agent.1.log is no longer a directory) -- the EISDIR fault never engaged"
    dump_case_transcripts "$dir"
  elif [ ! -e "$blocker/placeholder" ]; then
    bad "${name}-witness" "the blocker directory's placeholder file vanished -- something wrote through agent.1.log"
    dump_case_transcripts "$dir"
  else
    local file_sz stderr_sz
    file_sz="$(stat -c %s "$logfile" 2>/dev/null || echo -1)"
    stderr_sz="$(stat -c %s "$AGENT_STDERR_FILE" 2>/dev/null || echo 0)"
    if [ "$file_sz" -lt 0 ]; then
      bad "${name}-witness" "could not stat $logfile"
      dump_case_transcripts "$dir"
    elif [ "$stderr_sz" -lt "$target_bytes" ]; then
      bad "${name}-witness" "stderr only reached ${stderr_sz}B (wanted >= ${target_bytes}B) within 5s -- not enough volume passed through to exercise repeated failed-rotation attempts"
      dump_case_transcripts "$dir"
    elif [ "$file_sz" -gt $((1024 * 2)) ]; then
      bad "${name}-witness" "$logfile (the FILE sink) grew to ${file_sz}B, well past --log-max-size=1024, while stderr (unwedged, same messages) reached ${stderr_sz}B -- expected the failed-rotation truncate-and-continue behavior to keep the FILE sink bounded even while stderr kept growing"
      dump_case_transcripts "$dir"
    else
      ok "${name}-witness: rotation fault engaged -- agent.1.log stayed a non-empty directory while stderr (same messages, never wedged) grew to ${stderr_sz}B and the FILE sink stayed bounded at ${file_sz}B under repeated failed-rotation truncation (rotating_file_sink-inl.h's rotate_() truncates the active file via file_helper_.reopen(true), drops the triggering message, and throws -- caught by spdlog's per-sink try/catch and routed to LogHandoff's non-I/O error handler; logging then continues on the next message)"
    fi
  fi

  terminate_and_wait "$pid" "-TERM" 8
  if ! assert_bounded_fault_exit "${name}-sigterm" 8; then
    dump_case_transcripts "$dir"
  fi
  hard_kill_backstop "$pid"
}

# ── F3: F1 + F2's faults simultaneously ──────────────────────────────────
scenario_F3() {
  local name="F3"
  local dir; dir="$(new_case_dir f3)"
  local logfile="$dir/logs/agent.log"
  # Pre-armed (before the process even starts) is safe here, unlike F2's
  # own after-readiness arming: F3 makes no assertion about the FILE sink's
  # content, only about the bounded SIGTERM exit under both faults, so the
  # marker-truncation race F2's comment describes doesn't matter for
  # anything this case actually checks. Same --log-max-files 1 placement
  # rationale as F2.
  local blocker="$dir/logs/agent.1.log"
  mkdir -p "$blocker"
  : > "$blocker/placeholder"

  open_blocked_fifo "$dir"
  "$BIN" --server 127.0.0.1:1 --no-tls \
    --data-dir "$dir/data" --plugin-dir "$REAL_PLUGIN_DIR" \
    --log-level trace --log-file "$logfile" --log-max-size 1024 --log-max-files 1 \
    2>"$BLOCKED_FIFO_PATH" 1>"$dir/stdout.log" 9<&- &
  local pid=$!
  LAUNCHED_PIDS+=("$pid")

  if ! wait_for_file_exists "$dir/data/kv_store.db" 10; then
    bad "$name" "$dir/data/kv_store.db never appeared while both faults were staged"
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    close_blocked_fifo
    return
  fi

  if ! confirm_wedge_engaged "$pid" "$name" 8; then
    bad "$name" "never observed the stderr sink actually wedge within 8s with both faults staged"
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
    kill -9 "$pid" 2>/dev/null || true
    close_blocked_fifo
    forget_launched_pid "$pid"
    return
  fi
  # A little extra slack for a few more failed-rotation cycles to have run
  # too (not independently witnessed here -- that's F2's job).
  sleep 1

  terminate_and_wait "$pid" "-TERM" 8
  if ! assert_bounded_fault_exit "$name" 8; then
    drain_fifo_leftovers "$dir"
    dump_case_transcripts "$dir"
  fi
  close_blocked_fifo
  hard_kill_backstop "$pid"
}

# ── Dispatch ─────────────────────────────────────────────────────────────

ALL_CASES=(P0 P1i P1ii P1iii P1iv R1 R2 F1a F1b F1c F2 F3)
CASES=("${ALL_CASES[@]}")
if (( $# > 0 )); then
  CASES=("$@")
fi

for c in "${CASES[@]}"; do
  echo "== $c =="
  case "$c" in
    P0)    scenario_P0 ;;
    P1i)   scenario_P1i ;;
    P1ii)  scenario_P1ii ;;
    P1iii) scenario_P1iii ;;
    P1iv)  scenario_P1iv ;;
    R1)    scenario_R1 ;;
    R2)    scenario_R2 ;;
    F1a)   scenario_F1 a TERM "" ;;
    F1b)   scenario_F1 b bare "" ;;
    F1c)   scenario_F1 c TERM json ;;
    F2)    scenario_F2 ;;
    F3)    scenario_F3 ;;
    *)     echo "unknown case: $c" >&2; exit 2 ;;
  esac
done

echo ""
echo "=================================================="
echo "  blocked-log-sink SIGTERM harness results"
echo "  PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  SKIP: $SKIP_COUNT"
if (( FAIL_COUNT > 0 )); then
  echo "  failed: ${FAILED_CASES[*]}"
  exit 1
fi
exit 0
