#!/usr/bin/env bash
# test_start_uat_kill_stale.sh — scripts/start-UAT.sh must signal only PIDs it
# recorded at spawn and refuse (not kill) when a UAT port has a foreign holder
# (#5333). The script is sourced; kill/ps/pgrep/lsof/docker/sleep are replaced by
# bash functions backed by files under a yuzu_test_ temp dir. Nothing is spawned
# and nothing is signalled. The decoy command line contains "yuzu-agent", the way
# `meson compile ... yuzu-agent` did when the old pgrep -f killed it.
#
# Run:  bash tests/shell/test_start_uat_kill_stale.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SCRIPT="$ROOT/scripts/start-UAT.sh"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_uat.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# shellcheck source=scripts/start-UAT.sh
source "$SCRIPT"
# The script hard-wires these (no env override); point them at the temp dir.
UAT_DIR="$TMP/uat"; PID_DIR="$UAT_DIR/pids"; BUILDDIR="$TMP/build"; GATEWAY_DIR="$TMP/gw"

# shellcheck disable=SC2032  # shadows the builtin for the sourced functions only
kill() {
  case $1 in
    -0) [[ -e $TMP/alive/$2 ]] ;;
    *) printf '%s\n' "$*" >> "$TMP/kills"
       # unkillable: fail like EPERM and leave the process alive
       if [[ -e $TMP/unkillable/${*: -1} ]]; then return 1; fi
       rm -f "$TMP/alive/${*: -1}" ;;
  esac
}
sudo()  { echo "sudo $*" >> "$TMP/sudo"; return 1; }
ps()    { cat "$TMP/cmd/${*: -1}" 2>/dev/null; }
pgrep() { case $1 in -P) cat "$TMP/children/$2" 2>/dev/null ;; *) echo "pgrep $*" >> "$TMP/violations"; return 1 ;; esac; }
pkill() { echo "pkill $*" >> "$TMP/violations"; return 1; }
lsof()  { printf 'COMMAND PID\nfake-holder 777 ...\n'; }
docker() { echo "docker $*" >> "$TMP/docker-calls"; return 1; }
sleep() { :; }
have_port_inspector() { [[ ! -e $TMP/no-inspector ]]; }
# Busy ports: persistent unless the fake kill of a PID clears them (see owned case).
listening_ports_among() { cat "$TMP/busy" 2>/dev/null || true; }

pass=0 fail=0
check() { # check <desc> <condition-exit>
  if [ "$2" = 0 ]; then printf '  [pass] %s\n' "$1"; pass=$((pass + 1))
  else printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); fi
}
has()  { grep -qF -- "$2" "$1" 2>/dev/null; }
reset() {
  rm -rf "$TMP/alive" "$TMP/cmd" "$TMP/children" "$TMP/unkillable" "$TMP/kills" "$TMP/sudo" \
         "$TMP/violations" "$TMP/docker-calls" "$TMP/busy" "$TMP/no-inspector" "$UAT_DIR"
  mkdir -p "$TMP/alive" "$TMP/cmd" "$TMP/children" "$TMP/unkillable" "$PID_DIR"
}
alive() { : > "$TMP/alive/$1"; printf '%s\n' "$2" > "$TMP/cmd/$1"; }
run()   { set +e; out=$("$@" 2>&1); rc=$?; set -e; }

DECOY='bash /Users/x/.claude/skills/snr-dev/snr-with-lock.sh meson compile -C /Users/x/Yuzu-worktrees/w/build-macos -j4 yuzu-agent'
SRV="$BUILDDIR/server/core/yuzu-server"
AGT="$BUILDDIR/agents/core/yuzu-agent"

echo "decoy"
reset; alive 4242 "$DECOY"; alive 4243 yuzu-server-lookalike
run kill_stale
check "decoy untouched, rc 0, nothing to stop" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [[ $out == *'No recorded processes'* ]] && echo 0 || echo 1)"
check "no pgrep -f / pkill" "$([ ! -e "$TMP/violations" ] && echo 0 || echo 1)"

echo "owned"
reset; alive 100 "$SRV --no-tls"; alive 101 child; echo 101 > "$TMP/children/100"
record_pid server 100 "$SRV"
run kill_stale
check "owned tree killed, record removed, docker rm called" "$([ $rc = 0 ] && has "$TMP/kills" '-9 100' && has "$TMP/kills" '-9 101' && [ ! -e "$PID_DIR/server.pid" ] && ! has "$TMP/kills" 4242 && has "$TMP/docker-calls" "rm -f $PG_CONTAINER" && echo 0 || echo 1)"

echo "pid reuse"
reset; alive 200 "$DECOY"; record_pid agent 200 "$AGT"
run kill_stale
check "reused PID not signalled, record dropped" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/agent.pid" ] && [[ $out == *'another process'* ]] && echo 0 || echo 1)"

echo "dead"
reset; record_pid gateway 300 "$GATEWAY_DIR/rel"
run kill_stale
check "dead record dropped, nothing killed" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/gateway.pid" ] && echo 0 || echo 1)"

echo "foreign holder"
reset; echo '8080,50051' > "$TMP/busy"
run kill_stale
check "refuses naming both ports, docker untouched" "$([ $rc = 1 ] && [[ $out == *8080* && $out == *50051* && $out == *refusing* ]] && [ ! -e "$TMP/docker-calls" ] && [ ! -e "$TMP/kills" ] && echo 0 || echo 1)"

echo "status"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"; alive 200 "$DECOY"; record_pid agent 200 "$AGT"
run show_status
check "owned reported running" "$([[ $out == *'server running (PID 100'* ]] && echo 0 || echo 1)"
check "reused reported as another process" "$([[ $out == *'agent not running (recorded PID 200 now belongs to another process)'* ]] && echo 0 || echo 1)"
check "status never signals or pgreps, keeps records" "$([ ! -e "$TMP/violations" ] && [ ! -e "$TMP/kills" ] && [ -f "$PID_DIR/agent.pid" ] && echo 0 || echo 1)"

echo "cross-worktree"
reset; A=/Users/x/Yuzu-worktrees/A/build-macos/server/core/yuzu-server
alive 100 "$A --no-tls"; record_pid server 100 "$A"
run kill_stale
check "other worktree's recorded stack replaced" "$([ $rc = 0 ] && has "$TMP/kills" '-9 100' && [ ! -e "$PID_DIR/server.pid" ] && echo 0 || echo 1)"

echo "no inspector"
reset; : > "$TMP/no-inspector"
run kill_stale
check "refuses when ports cannot be inspected" "$([ $rc = 1 ] && [[ $out == *lsof* && $out == *refusing* ]] && echo 0 || echo 1)"

echo "survivor"
reset; alive 200 "$AGT --server x"; record_pid agent 200 "$AGT"; : > "$TMP/unkillable/200"
run kill_stale
check "survivor: sudo fallback tried, record kept, rc 1" "$([ $rc = 1 ] && has "$TMP/kills" '-9 200' && has "$TMP/sudo" 'kill -9 200' && [ -f "$PID_DIR/agent.pid" ] && [[ $out == *survived* && $out == *'kept its record'* ]] && echo 0 || echo 1)"

echo "beam fixture"
reset; rel="$GATEWAY_DIR/_build/prod/rel/yuzu_gw"
alive 300 "/opt/homebrew/lib/erlang/erts-15.2/bin/beam.smp -- -root $rel -bindir $rel/erts-15.2/bin -boot $rel/releases/0.1.0/yuzu_gw -noinput +Bd"
record_pid gateway 300 "$rel"
run kill_stale
check "realistic beam command line is owned and killed" "$([ $rc = 0 ] && has "$TMP/kills" '-9 300' && echo 0 || echo 1)"

echo "prepare_fresh_run"
reset; : > "$UAT_DIR/marker"; echo 8080 > "$TMP/busy"
run prepare_fresh_run
check "refusal happens before the wipe" "$([ $rc = 1 ] && [ -e "$UAT_DIR/marker" ] && echo 0 || echo 1)"
rm -f "$TMP/busy"
run prepare_fresh_run
check "free ports: wiped and agent-data recreated" "$([ $rc = 0 ] && [ ! -e "$UAT_DIR/marker" ] && [ -d "$UAT_DIR/agent-data" ] && echo 0 || echo 1)"

echo "lexical wiring"
cnt() { grep -cF -- "$1" "$SCRIPT" || true; }
# shellcheck disable=SC2016  # the patterns are literal source text, not expansions
check "record_pid after each of the three spawns" "$([ "$(cnt 'record_pid server "$server_pid"')" = 1 ] && [ "$(cnt 'record_pid gateway "$gw_pid"')" = 1 ] && [ "$(cnt 'record_pid agent "$agent_pid"')" = 1 ] && echo 0 || echo 1)"
check "no pgrep -f / pkill in start-UAT.sh" "$(! grep -qE 'pgrep -f|pkill' "$SCRIPT" && echo 0 || echo 1)"
check "start_all calls prepare_fresh_run once" "$([ "$(cnt 'prepare_fresh_run || exit 1')" = 1 ] && echo 0 || echo 1)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
