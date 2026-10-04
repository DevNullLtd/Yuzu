#!/usr/bin/env bash
# test_start_uat_kill_stale.sh — scripts/start-UAT.sh must signal only PIDs it
# recorded at spawn and refuse (not kill) when a UAT port has a foreign holder
# (#5333). The script is sourced; kill/ps/pgrep/lsof/docker/sleep are replaced by
# bash functions backed by files under a yuzu_test_ temp dir. Nothing is spawned
# and nothing is signalled. The decoy command line contains "yuzu-agent", the way
# `meson compile ... yuzu-agent` did when the old pgrep -f killed it.
#
# Run:  bash tests/shell/test_start_uat_kill_stale.sh
# shellcheck disable=SC2016  # the lexical pins below deliberately match literal $-expressions
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
# Fixture dirs must read as trusted (not group/other-writable) whatever the host umask.
umask 022
# reset() rm -rf's UAT_DIR: never let it point outside the temp dir.
[[ $UAT_DIR == "$TMP"/* && $PID_DIR == "$TMP"/* ]] || { echo 'refusing: UAT_DIR not under TMP' >&2; exit 2; }

# shellcheck disable=SC2032  # shadows the builtin for the sourced functions only
kill() {
  case $1 in
    # eperm: alive but not signalable by this user (root-owned sudo parent) -> kill -0 fails
    -0) [[ -e $TMP/alive/$2 && ! -e $TMP/eperm/$2 ]] ;;
    *) printf '%s\n' "$*" >> "$TMP/kills"
       # unkillable: fail like EPERM and leave the process alive
       if [[ -e $TMP/unkillable/${*: -1} ]]; then return 1; fi
       # vanish: exited between the ownership check and the kill -> ESRCH, nothing left
       if [[ -e $TMP/vanish/${*: -1} ]]; then rm -f "$TMP/alive/${*: -1}"; return 1; fi
       # a successful kill also frees the busy ports (the owned stack's listeners)
       rm -f "$TMP/alive/${*: -1}" "$TMP/busy" ;;
  esac
}
sudo()  { echo "sudo $*" >> "$TMP/sudo"; return 1; }
# Liveness comes from alive/ (what kill removes), like the real ps -p.
ps()    { local p=${*: -1}; [[ -e $TMP/alive/$p ]] || return 1
          [[ $* == *command=* ]] && { cat "$TMP/cmd/$p" 2>/dev/null || true; }
          [[ $* == *lstart=* ]] && { cat "$TMP/birth/$p" 2>/dev/null || true; }
          return 0; }
pgrep() { case $1 in -P) cat "$TMP/children/$2" 2>/dev/null ;; *) echo "pgrep $*" >> "$TMP/violations"; return 1 ;; esac; }
pkill() { echo "pkill $*" >> "$TMP/violations"; return 1; }
lsof()  { printf 'COMMAND PID\nfake-holder 777 ...\n'; }
docker() { echo "docker $*" >> "$TMP/docker-calls"; [[ -e $TMP/docker-ok ]]; }
sleep() { :; }
# rm-fails: the wipe of UAT_DIR fails (files owned by someone else), as in a failed sudo cleanup.
# shellcheck disable=SC2032  # shadows rm for the sourced functions only
rm() { if [[ -e $TMP/rm-fails && ${2:-} == "$UAT_DIR" ]]; then return 1; fi; command rm "$@"; }
have_port_inspector() { [[ ! -e $TMP/no-inspector ]]; }
# Busy ports: the requested ports present in `busy`, comma-joined like the real
# helper; persistent unless a successful fake kill clears the file.
listening_ports_among() {
  local p h=""
  [[ -f $TMP/busy ]] || return 0
  for p in "$@"; do
    case ",$(cat "$TMP/busy")," in *",$p,"*) h+="${h:+,}$p" ;; esac
  done
  printf '%s' "$h"
}

pass=0 fail=0
check() { # check <desc> <condition-exit>
  if [ "$2" = 0 ]; then printf '  [pass] %s\n' "$1"; pass=$((pass + 1))
  else printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); fi
}
has()  { grep -qF -- "$2" "$1" 2>/dev/null; }
reset() {
  rm -rf "$TMP/alive" "$TMP/cmd" "$TMP/birth" "$TMP/children" "$TMP/unkillable" "$TMP/eperm" "$TMP/vanish" "$TMP/docker-ok" "$TMP/kills" "$TMP/sudo" \
         "$TMP/violations" "$TMP/docker-calls" "$TMP/busy" "$TMP/no-inspector" "$TMP/rm-fails" "$TMP/real.pid" "$UAT_DIR"
  mkdir -p "$TMP/alive" "$TMP/cmd" "$TMP/birth" "$TMP/children" "$TMP/unkillable" "$TMP/eperm" "$TMP/vanish" "$PID_DIR"
  chmod 755 "$UAT_DIR"
}
alive() { : > "$TMP/alive/$1"; printf '%s\n' "$2" > "$TMP/cmd/$1"; printf 'Sun Oct  4 10:00:%s 2026\n' "$1" > "$TMP/birth/$1"; }
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
record_pid server 100 "$SRV"; echo 8080 > "$TMP/busy"
run kill_stale
check "owned tree killed, busy port cleared by the kill, record removed, docker rm called" "$([ $rc = 0 ] && has "$TMP/kills" '-9 100' && has "$TMP/kills" '-9 101' && [ ! -e "$PID_DIR/server.pid" ] && ! has "$TMP/kills" 4242 && has "$TMP/docker-calls" "rm -f $PG_CONTAINER" && echo 0 || echo 1)"

echo "pid reuse"
reset; alive 200 "$DECOY"; record_pid agent 200 "$AGT"
run kill_stale
check "reused PID not signalled, record dropped" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/agent.pid" ] && [[ $out == *'another process'* ]] && echo 0 || echo 1)"

echo "birth token differs"
reset; alive 200 "lldb -- $AGT"; record_pid agent 200 "$AGT"; echo 'Mon Jan  1 00:00:00 2001' > "$TMP/birth/200"
run kill_stale
check "path matches but start time differs: not killed, record removed, another process" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/agent.pid" ] && [[ $out == *'another process'* ]] && echo 0 || echo 1)"

echo "record_pid write failure"
reset; alive 4242 "$AGT"; rm -rf "$PID_DIR"; : > "$PID_DIR"
run record_pid x 4242 /p
check "unwritable PID_DIR: rc 1, the just-spawned PID is killed" "$([ $rc = 1 ] && has "$TMP/kills" '-9 4242' && echo 0 || echo 1)"
reset; run record_pid x 4343 /p
check "unreadable start time (no such process): rc 1, no record written" "$([ $rc = 1 ] && [ ! -e "$PID_DIR/x.pid" ] && echo 0 || echo 1)"

echo "dead"
reset; mkdir -p "$PID_DIR"; printf '300\n%s\nSun Oct  4 10:00:00 2026\n' "$GATEWAY_DIR/rel" > "$PID_DIR/gateway.pid"  # a process that is gone
run kill_stale
check "dead record dropped, nothing killed" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/gateway.pid" ] && echo 0 || echo 1)"

echo "malformed"
reset; printf 'abc\n/x\n' > "$PID_DIR/server.pid"; printf '123\n' > "$PID_DIR/agent.pid"
run kill_stale
check "non-numeric PID and empty identity: nothing killed, records removed" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/server.pid" ] && [ ! -e "$PID_DIR/agent.pid" ] && echo 0 || echo 1)"

echo "foreign holder"
reset; echo '8080,50051' > "$TMP/busy"
run kill_stale
check "refuses naming both ports, docker untouched" "$([ $rc = 1 ] && [[ $out == *8080* && $out == *50051* && $out == *refusing* ]] && [ ! -e "$TMP/docker-calls" ] && [ ! -e "$TMP/kills" ] && echo 0 || echo 1)"

echo "pg port still held"
reset; echo 15433 > "$TMP/busy"; : > "$TMP/docker-ok"
run kill_stale
check "rm succeeded but 15433 still held: rc 1, names the port, PG arm (not UAT arm) fired" "$([ $rc = 1 ] && [[ $out == *15433* && $out == *"not this rig's sidecar"* && $out != *'refusing to signal'* ]] && has "$TMP/docker-calls" "rm -f $PG_CONTAINER" && echo 0 || echo 1)"

echo "status"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"; alive 200 "$DECOY"; record_pid agent 200 "$AGT"
run show_status
check "owned reported running" "$([[ $out == *'server running (PID 100'* ]] && echo 0 || echo 1)"
check "reused reported as another process" "$([[ $out == *'agent not running (recorded PID 200 now belongs to another process)'* ]] && echo 0 || echo 1)"
check "status never signals or pgreps, keeps records" "$([ ! -e "$TMP/violations" ] && [ ! -e "$TMP/kills" ] && [ -f "$PID_DIR/agent.pid" ] && echo 0 || echo 1)"

echo "status: absent / dead / malformed"
reset; mkdir -p "$PID_DIR"; printf '500\n%s\nSun Oct  4 10:00:00 2026\n' "$SRV" > "$PID_DIR/server.pid"; printf 'abc\n/x\n' > "$PID_DIR/agent.pid"
run show_status
check "absent record labelled" "$([[ $out == *'gateway not running (no record)'* ]] && echo 0 || echo 1)"
check "dead and malformed records labelled stale" "$([[ $out == *'server not running (stale record)'* && $out == *'agent not running (stale record)'* ]] && echo 0 || echo 1)"
check "status leaves records, signals nothing" "$([ -f "$PID_DIR/server.pid" ] && [ -f "$PID_DIR/agent.pid" ] && [ ! -e "$TMP/kills" ] && [ ! -e "$TMP/violations" ] && echo 0 || echo 1)"

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

echo "eperm (root-owned sudo parent, --as-user)"
reset; alive 200 "sudo -u _yuzu -H env $AGT"; record_pid agent 200 "$AGT"; : > "$TMP/eperm/200"; : > "$TMP/unkillable/200"
run kill_stale
check "alive-but-EPERM is not dead: sudo arm tried, record kept, rc 1, no Stopped" "$([ $rc = 1 ] && has "$TMP/sudo" 'kill -9 200' && [ -f "$PID_DIR/agent.pid" ] && [[ $out != *Stopped* ]] && echo 0 || echo 1)"
reset; alive 200 "sudo -u _yuzu -H env $AGT"; record_pid agent 200 "$AGT"; : > "$TMP/eperm/200"
run kill_stale
check "EPERM PID that the kill removes: Stopped, record removed" "$([ $rc = 0 ] && [[ $out == *'Stopped agent'* ]] && [ ! -e "$PID_DIR/agent.pid" ] && echo 0 || echo 1)"

echo "exits before the kill (ESRCH)"
reset; alive 200 "$AGT --server x"; record_pid agent 200 "$AGT"; : > "$TMP/vanish/200"
run kill_stale
check "no sudo kill aimed at a PID that is gone" "$([ $rc = 0 ] && [ ! -e "$TMP/sudo" ] && [ ! -e "$PID_DIR/agent.pid" ] && echo 0 || echo 1)"

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

echo "forged records: PID floor"
reset; alive 1 "$SRV --launchd"; record_pid server 1 "$SRV"
run kill_stale
check "PID 1 record with a matching command line: nothing killed, record dropped" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && [ ! -e "$PID_DIR/server.pid" ] && echo 0 || echo 1)"
reset; alive 0 "$AGT --x"; record_pid agent 0 "$AGT"; alive 1 "$SRV"
printf '01\n%s\nSun Oct  4 10:00:01 2026\n' "$SRV" > "$PID_DIR/server.pid"
run kill_stale
check "PID 0 and zero-padded 01 records: nothing killed" "$([ $rc = 0 ] && ! [ -e "$TMP/kills" ] && echo 0 || echo 1)"
reset; alive 100 "$SRV"; alive 1 init; echo 1 > "$TMP/children/100"
run kill_tree 100
check "kill_tree never descends into PID 1" "$(grep -qxF -- '-9 100' "$TMP/kills" && ! grep -qxF -- '-9 1' "$TMP/kills" && echo 0 || echo 1)"
reset; run kill_tree 0
check "kill_tree refuses PID 0" "$([ ! -e "$TMP/kills" ] && echo 0 || echo 1)"

echo "forged records: provenance"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"; chmod 777 "$PID_DIR"
run kill_stale
check "world-writable PID_DIR: untrusted, nothing killed, record kept, stop refuses (rc 1)" "$([ $rc = 1 ] && ! [ -e "$TMP/kills" ] && [ -f "$PID_DIR/server.pid" ] && [[ $out == *'ignoring PID records not owned by you'* ]] && echo 0 || echo 1)"
run show_status
check "status labels the ignored record" "$([[ $out == *'server record ignored'* ]] && echo 0 || echo 1)"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"; chmod 775 "$PID_DIR"
check "group-writable PID_DIR is untrusted too" "$([ "$(recorded_pid_state server)" = untrusted ] && echo 0 || echo 1)"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"; chmod 777 "$UAT_DIR"
check "world-writable UAT_DIR is untrusted" "$([ "$(recorded_pid_state server)" = untrusted ] && echo 0 || echo 1)"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"; mv "$PID_DIR/server.pid" "$TMP/real.pid"; ln -s "$TMP/real.pid" "$PID_DIR/server.pid"
run kill_stale
check "symlinked record: untrusted, nothing killed, link kept, stop refuses (rc 1)" "$([ $rc = 1 ] && ! [ -e "$TMP/kills" ] && [ -L "$PID_DIR/server.pid" ] && echo 0 || echo 1)"
reset; alive 100 "$SRV --no-tls"; record_pid server 100 "$SRV"
check "ordinary record is trusted and owned" "$([ "$(recorded_pid_state server)" = 'owned 100' ] && echo 0 || echo 1)"
check "record_pid leaves PID_DIR at 0700" "$([ "$(find "$PID_DIR" -maxdepth 0 -perm 700)" = "$PID_DIR" ] && echo 0 || echo 1)"

echo "prepare_fresh_run: directory provenance"
reset; mkdir -p "$UAT_DIR"; chmod 777 "$UAT_DIR"; : > "$TMP/rm-fails"
run prepare_fresh_run
check "wipe failed and UAT_DIR is world-writable: refuses, no agent-data" "$([ $rc = 1 ] && [[ $out == *refusing* ]] && [ ! -d "$UAT_DIR/agent-data" ] && echo 0 || echo 1)"
umask_prepare() { umask 002; prepare_fresh_run; }
reset
run umask_prepare
check "umask 002: UAT_DIR is still created unshared, run proceeds" "$([ $rc = 0 ] && dir_trusted "$UAT_DIR" && [ -d "$UAT_DIR/agent-data" ] && echo 0 || echo 1)"

echo "lexical wiring"
cnt() { grep -cF -- "$1" "$SCRIPT" || true; }
# shellcheck disable=SC2016  # the patterns are literal source text, not expansions
check "ownership probe reads the full command line (ps -ww)" "$([ "$(cnt 'ps -ww -o command= -p')" = 1 ] && echo 0 || echo 1)"
check "record_pid after each of the three spawns" "$([ "$(cnt 'record_pid server "$server_pid"')" = 1 ] && [ "$(cnt 'record_pid gateway "$gw_pid"')" = 1 ] && [ "$(cnt 'record_pid agent "$agent_pid"')" = 1 ] && echo 0 || echo 1)"
# shellcheck disable=SC2016
check "gateway identity is the physical rel dir" "$([ "$(cnt 'record_pid gateway "$gw_pid" "$(cd "$gw_rel" && pwd -P)"')" = 1 ] && echo 0 || echo 1)"
check "UAT_PORTS is the full eight-port list" "$([ "$UAT_PORTS" = "8080 50051 50052 50054 50055 50063 8081 9568" ] && echo 0 || echo 1)"
check "stop dispatches through the shared refusal gate" "$([ "$(cnt 'stop)   kill_stale || exit 1')" = 1 ] && echo 0 || echo 1)"
# File ownership cannot be faked in a test, so pin that the -O probes exist.
check "record and directory ownership probes (-O) are present" "$([ "$(cnt '[ -O "$f" ]')" = 1 ] && [ "$(cnt '[ -O "$1" ]')" = 1 ] && [ "$(cnt 'chmod 700 "$PID_DIR"')" = 1 ] && echo 0 || echo 1)"
check "no pgrep -f / pkill in start-UAT.sh" "$(! grep -qE 'pgrep -f|pkill' "$SCRIPT" && echo 0 || echo 1)"
check "start_all calls prepare_fresh_run once" "$([ "$(cnt 'prepare_fresh_run || exit 1')" = 1 ] && echo 0 || echo 1)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
