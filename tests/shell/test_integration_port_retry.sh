#!/usr/bin/env bash
# test_integration_port_retry.sh — locks the lost-port-race classifier and the process
# ownership guard of scripts/integration-test.sh (#7538).
#
# The script retries its stack start-up under --free-ports ONLY on unambiguous bind
# evidence. The classifier is the one thing that stands between a retry and a real
# product start-up failure going green, so each real bind line (all 8 port indexes,
# measured with YUZU_IT_PORT_HOG_INDEX=0..7) must classify as a bind failure, and the
# lines that look like one but are not (a TLS key failure behind "Failed to start gRPC
# server", the web listener's own line, a bare "Failed to add port") must not.
# The ownership half (is_own_child / signal_own, #7538 K2, G8-N01) is run against real
# processes: a reaped child, a live non-child and a stale start time are never signalled,
# and a live own child is neither misread as foreign nor waited on forever when the clock
# steps, the time zone changes, `ps` fails or prints no start time (the three-way answer).
# verify_stack_bound and the attempt loop (run_start_attempts) run with a fake `ss` and
# stub start functions (G8-N03), and cleanup()'s K19 guard is measured with real signals.
#
# The helpers are extracted from the script between its `testable-helpers` markers and
# sourced; no server, gateway, Postgres, network or root is needed, and `ss` is a fake
# on PATH. Nothing outside the yuzu_test_ temp dir is touched or signalled.
#
# Run:  bash tests/shell/test_integration_port_retry.sh
# shellcheck disable=SC2016,SC2034,SC2123  # SC2016: the lexical pins match literal $-expressions; SC2034: variables read by the sourced helpers; SC2123: a deliberate ss-less PATH
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SCRIPT="${YUZU_IT_SCRIPT_UNDER_TEST:-$ROOT/scripts/integration-test.sh}"  # override: mutation runs on a scratch copy
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_itretry.XXXXXX")"
# Every process this test starts is recorded as pid:stamp (stamp = /proc start time, the
# process's identity) and is killed at exit only while that identity still holds: a
# process the test has already stopped and reaped (its PID may be recycled by another job)
# is never signalled, and one that is NOT a child (a stranger standing in for another
# job's process, a sentinel behind a wrapper subshell) is still reached by identity, so an
# early abort leaves nothing running (G8-N02).
OWNED=()
track() {
    local p="$1"
    OWNED+=("$p:$(proc_stamp "$p")")
}
cleanup() {
    local e p st
    for e in "${OWNED[@]+"${OWNED[@]}"}"; do
        p="${e%%:*}"; st="${e#*:}"
        [[ -n "$st" && "$(PROC_ROOT=/proc proc_stamp "$p")" == "$st" ]] && kill -9 "$p" 2>/dev/null || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT

FAILS=0
CASES=0
ok()  { CASES=$((CASES + 1)); echo "  ok   $*"; }
bad() { CASES=$((CASES + 1)); FAILS=$((FAILS + 1)); echo "  FAIL $*"; }
# expect <0|1> <description> <command...>: the command's exit status must be 0 or 1.
expect() {
    local want="$1" desc="$2" rc=0
    shift 2
    "$@" > /dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq "$want" ]]; then ok "$desc"; else bad "$desc (expected rc $want, got $rc)"; fi
}

# ── Extract and source the helpers ────────────────────────────────────
HELPERS="$TMP/helpers.sh"
sed -n '/^# --- testable-helpers:begin ---$/,/^# --- testable-helpers:end ---$/p' "$SCRIPT" > "$HELPERS"
if [[ "$(grep -c 'testable-helpers' "$HELPERS")" -ne 2 ]]; then
    echo "FAIL: the testable-helpers markers are missing from $SCRIPT" >&2
    exit 2
fi
FREE_PORTS=true
LOGF=/dev/null
log() { echo "$*" >> "$LOGF"; }
# shellcheck disable=SC1090
source "$HELPERS"

# ── 1. The classifier: every real bind line is a bind failure ─────────
echo "classifier: real bind lines (one per port index)"
fx() { printf '%s\n' "$2" > "$TMP/$1.log"; }
fx idx0 "E0000 00:00:1794477974.219400  446596 add_port.cc:83] Failed to add port to server: No address added out of total 1 resolved for '127.0.0.1:42715' (Error in bind for address '[::ffff:127.0.0.1]:42715': Address already in use)"
fx idx2 "E0000 00:00:1794478116.050153  471079 add_port.cc:83] Failed to add port to server: No address added out of total 1 resolved for '127.0.0.1:47273' (Error in bind for address '[::ffff:127.0.0.1]:47273': Address already in use)"
fx idx4 "2026-11-12T10:10:59.432630+00:00 [error] Supervisor: {local,yuzu_gw_sup}. Context: start_error. Reason: {listen_failed,eaddrinuse}. Offender: id={yuzu_grpc_listener,agent},pid=undefined."
fx idx5 "2026-11-12T10:12:11.671173+00:00 [error] Supervisor: {local,yuzu_gw_sup}. Context: start_error. Reason: {listen_failed,eaddrinuse}. Offender: id={yuzu_grpc_listener,mgmt},pid=undefined."
fx idx6 "2026-11-12T10:13:23.993936+00:00 [error] Supervisor: {local,httpd_acceptor_sup_53785default}. Context: start_error. Reason: {listen,eaddrinuse}. Offender: id={httpd_acceptor_sup,any,53785,default},pid=undefined."
fx idx7 "2026-11-12T10:14:35.111543+00:00 [error] Health endpoint failed to listen on port 47277: eaddrinuse"
for i in idx0 idx2 idx4 idx5 idx6 idx7; do
    expect 0 "$i line is a bind failure" bind_failure_in_log "$TMP/$i.log"
done
# index 1 prints the same gRPC line as 0 and 2; index 3 is the web listener (section 2).
# The recorded evidence names the log and carries the line.
bind_failure_in_log "$TMP/idx4.log" || true
[[ "$BIND_EVIDENCE" == "idx4.log: "*"listen_failed,eaddrinuse"* ]] && ok "evidence names the log and the line" || bad "evidence text: $BIND_EVIDENCE"

echo "classifier: look-alikes are NOT bind failures"
fx tlskey "[2026-11-12 10:00:00.000] [error] [1234] Failed to start gRPC server -- check that ports 127.0.0.1:42715 and 127.0.0.1:33813 are available"
fx keymismatch "Failed to start gRPC server: key mismatch"
fx tlscreds "E0000 00:00:1794477974.219400  446596 add_port.cc:83] Failed to add port to server: Failed to create credentials: invalid private key"
fx weblist "[2026-11-12 10:09:47.008] [error] [480473] Web listener failed to bind or exited with an error on 127.0.0.1:42131"
fx redirect "[2026-11-12 10:09:47.008] [error] [480473] Redirect listener failed to bind or exited with an error on 127.0.0.1:80"
fx clean "[2026-11-12 10:00:00.000] [info] [1234] Server listening"
fx crash "terminate called after throwing an instance of 'std::runtime_error'"
for i in tlskey keymismatch tlscreds weblist redirect clean crash; do
    expect 1 "$i is not a bind failure" bind_failure_in_log "$TMP/$i.log"
done
expect 1 "a missing log is not a bind failure" bind_failure_in_log "$TMP/absent.log"
# The generic line is not evidence even when a real bind line sits elsewhere in the
# stack: only the errno line itself is.
fx both "$(cat "$TMP/tlskey.log")"
expect 1 "the generic start-failure line alone never classifies" bind_failure_in_log "$TMP/both.log"

# ── 2. The web listener: its line is evidence only with a foreign owner ─
echo "classifier: web listener line needs a foreign listener on the port"
mkdir -p "$TMP/bin"
cat > "$TMP/bin/ss" <<'SS'
#!/usr/bin/env bash
# fake ss: prints the header and the rows in $FAKE_SS_ROWS (one per line) that are on
# the port asked for ("sport = :N", the last argument)
echo "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
port="${*: -1}"; port="${port##*:}"
[[ -n "${FAKE_SS_ROWS:-}" ]] && printf '%b\n' "$FAKE_SS_ROWS" | grep -F ":$port " || true
exit 0
SS
chmod +x "$TMP/bin/ss"
export FAKE_SS_ROWS=""
ORIG_PATH="$PATH"
PATH="$TMP/bin:$ORIG_PATH"
OWN='LISTEN 0 4096 127.0.0.1:42131 0.0.0.0:* users:(("yuzu-server",pid=4242,fd=20))'
STRANGER='LISTEN 0 16 127.0.0.1:42131 0.0.0.0:* users:(("python3",pid=555,fd=3))'
NOPROC='LISTEN 0 16 127.0.0.1:42131 0.0.0.0:*'
LOOKALIKE='LISTEN 0 4096 127.0.0.1:42131 0.0.0.0:* users:(("other",pid=42421,fd=3))'
fx web "$(cat "$TMP/weblist.log")"
FAKE_SS_ROWS="$STRANGER";                expect 0 "web line + stranger owns the port -> lost race" web_bind_lost "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="$OWN";                     expect 1 "web line + the server owns the port -> not a bind failure" web_bind_lost "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="";                         expect 1 "web line + nothing listens -> not a bind failure" web_bind_lost "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="$NOPROC";                  expect 0 "web line + an unattributable listener -> foreign: the server's own listener failed (G8-N19)" web_bind_lost "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="$NOPROC";                  expect 1 "an unattributable listener WITHOUT the web line is not web_bind_lost" web_bind_lost "$TMP/clean.log" 4242 42131
FAKE_SS_ROWS="$NOPROC";                  expect 1 "port_foreign_listener: an unattributable row is not counted as foreign by default" port_foreign_listener 4242 42131
FAKE_SS_ROWS="$NOPROC";                  expect 0 "port_foreign_listener: ... unless the caller asks (web_bind_lost)" port_foreign_listener 4242 42131 yes
FAKE_SS_ROWS="$LOOKALIKE";               expect 0 "pid 42421 is not pid 4242 (no prefix match)" web_bind_lost "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="$OWN\n$STRANGER";          expect 0 "a SO_REUSEPORT co-listener beside the server is foreign" web_bind_lost "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="$OWN";                     expect 1 "no web line, our own listener -> not a bind failure" web_bind_lost "$TMP/clean.log" 4242 42131
FAKE_SS_ROWS="$STRANGER";                expect 1 "a stranger WITHOUT the web line is not web_bind_lost" web_bind_lost "$TMP/clean.log" 4242 42131
FAKE_SS_ROWS="$STRANGER";                expect 1 "a TLS-key failure with a stranger on the web port is not a bind failure" bind_loss_in_log "$TMP/tlskey.log" 4242 42131
FAKE_SS_ROWS="$STRANGER";                expect 0 "bind_loss_in_log: web line + stranger" bind_loss_in_log "$TMP/web.log" 4242 42131
FAKE_SS_ROWS="$STRANGER";                expect 1 "bind_loss_in_log: the web line is ignored without a pid and port (gateway log)" bind_loss_in_log "$TMP/web.log"
FAKE_SS_ROWS="";                         expect 0 "bind_loss_in_log: the errno needs no ss" bind_loss_in_log "$TMP/idx4.log"
FAKE_SS_ROWS="$OWN";                     expect 1 "port_foreign_listener: ours only" port_foreign_listener 4242 42131
FAKE_SS_ROWS="$STRANGER";                expect 0 "port_foreign_listener: a stranger" port_foreign_listener 4242 42131
# ss absent (and logged once): grep and basename stay reachable, ss does not.
mkdir -p "$TMP/noss"
for t in grep basename head tr sed ps; do ln -s "$(command -v "$t")" "$TMP/noss/$t"; done
# shellcheck disable=SC2123  # deliberately a PATH without ss
PATH="$TMP/noss"
FAKE_SS_ROWS="$STRANGER";                expect 1 "ss absent: nothing is classified from ownership" web_bind_lost "$TMP/web.log" 4242 42131
# ss absent is logged ONCE, from the main shell (a flag set inside $(...) is lost, G8-N09).
LOGF="$TMP/ssabsent.log"; : > "$LOGF"
note_ss_availability; note_ss_availability
port_foreign_listener 4242 42131 > /dev/null || true; web_bind_lost "$TMP/web.log" 4242 42131 || true
[[ "$(grep -c 'ss not found' "$LOGF")" -eq 1 ]] && ok "ss absent: one log line however many checks run" || bad "ss absent logged $(grep -c 'ss not found' "$LOGF") times"
LOGF=/dev/null
PATH="$TMP/bin:$ORIG_PATH"
SS_ABSENT_LOGGED=false
LOGF="$TMP/sspresent.log"; : > "$LOGF"
note_ss_availability
[[ ! -s "$LOGF" ]] && ok "ss present: nothing logged" || bad "ss present but logged: $(cat "$LOGF")"
LOGF=/dev/null

# ── 3. start_failed: the verdict the attempt loop acts on ─────────────
echo "classifier: start_failed verdicts"
FAKE_SS_ROWS="$OWN"
expect 10 "rc 10 from a wait is a lost race" start_failed 10 "$TMP/clean.log"
expect 10 "an exited server whose log has the errno is a lost race" start_failed 2 "$TMP/idx0.log"
expect 10 "a timeout whose log has the errno is a lost race" start_failed 1 "$TMP/idx4.log"
expect 1 "a TLS-key start failure is NOT retried" start_failed 2 "$TMP/tlskey.log" 4242 42131
expect 1 "a generic gRPC start failure without the errno is NOT retried" start_failed 2 "$TMP/keymismatch.log" 4242 42131
expect 1 "a crash is NOT retried" start_failed 2 "$TMP/crash.log" 4242 42131
FAKE_SS_ROWS="$STRANGER"
expect 1 "a TLS-key failure is not retried even with a stranger on the web port" start_failed 2 "$TMP/tlskey.log" 4242 42131
expect 10 "the web line + a stranger is a lost race" start_failed 1 "$TMP/web.log" 4242 42131
FREE_PORTS=false
expect 1 "without --free-ports a bind line is never classified" start_failed 2 "$TMP/idx0.log"
# shellcheck disable=SC2034  # read by the sourced classifier
FREE_PORTS=true

# ── 4. The CI annotation ──────────────────────────────────────────────
echo "annotation: a retry is visible behind a green step"
SUMMARY="$TMP/summary.md"
: > "$SUMMARY"
out="$(GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="$SUMMARY" emit_race_annotation 1 3 "gateway.log: Health endpoint failed to listen on port 100%: eaddrinuse")"
[[ "$out" == "::warning title=#7538 port race::attempt 1 of 3 lost a port before bind: gateway.log: Health endpoint failed to listen on port 100%25: eaddrinuse" ]] \
    && ok "::warning:: names attempt, evidence, and escapes %" || bad "annotation: $out"
grep -q "port race: attempt 1 of 3 lost a port before bind: gateway.log: Health endpoint failed to listen on port 100%: eaddrinuse" "$SUMMARY" \
    && ok "a step-summary line is appended" || bad "no step summary line"
out="$(GITHUB_ACTIONS=true GITHUB_STEP_SUMMARY="$SUMMARY" emit_race_annotation 1 3 $'a\rb\nc')"
[[ "$out" == "::warning title=#7538 port race::attempt 1 of 3 lost a port before bind: a b c" ]] \
    && ok "CR and LF in the evidence cannot inject a second workflow command (G8-N05)" || bad "CR/LF annotation: $(printf %q "$out")"
# ranch's one-line report is ~1.2 KB with the errno near its end (G8-N07): the excerpt must keep it.
ranch="gateway.log: $(printf 'x%.0s' $(seq 1 1100)) Reason: {listen_error,agent,eaddrinuse} tail"
out="$(GITHUB_ACTIONS=true emit_race_annotation 1 3 "$ranch")"
[[ "$out" == *eaddrinuse* && "${#out}" -lt 520 && "$out" == *"gateway.log: "* ]] \
    && ok "a 1.2 KB ranch-shaped line keeps the errno and the log name, bounded" || bad "ranch annotation lost the errno or is unbounded (${#out}): ${out:0:120}"
out="$(GITHUB_ACTIONS=true emit_race_annotation 1 3 "gateway.log: $(printf 'y%.0s' $(seq 1 900))")"
[[ "${#out}" -lt 520 ]] && ok "an over-long line without an errno is still bounded" || bad "unbounded annotation (${#out})"
out="$(GITHUB_ACTIONS='' GITHUB_STEP_SUMMARY="$SUMMARY" emit_race_annotation 1 3 "x")"
[[ -z "$out" ]] && ok "silent outside GitHub Actions" || bad "annotation outside CI: $out"

# ── 5. Ownership: only a live child with its launch start time is signalled ─
echo "ownership: is_own_child / signal_own against real processes"
sleep 60 & own=$!; track "$own"
own_stamp="$(proc_stamp "$own")"
[[ "$own_stamp" == p:* ]] && ok "a live child has a /proc start stamp" || bad "stamp for a live child: '$own_stamp'"
expect 0 "a live child with its stamp is ours" is_own_child "$own" "$own_stamp"
expect 1 "the same child with a stale start time is not ours (recycled PID)" is_own_child "$own" "p:1"
expect 2 "an empty stamp on a live pid is unknown, never ours" is_own_child "$own" ""
expect 1 "an empty pid is never ours" is_own_child "" "$own_stamp"
signal_own TERM "$own" "p:1" && bad "signalled a child with a stale stamp" || ok "a stale stamp is not signalled"
kill -0 "$own" 2>/dev/null && ok "... and the child is still alive" || bad "the stale-stamp child died"
# A live process that is not a child of this shell (a stranger on the same host).
( sleep 60 & echo $! > "$TMP/stranger.pid"; wait ) &
track "$!"
for _ in $(seq 1 50); do [[ -s "$TMP/stranger.pid" ]] && break; sleep 0.1; done
stranger="$(cat "$TMP/stranger.pid")"; track "$stranger"
stranger_stamp="$(proc_stamp "$stranger")"
expect 1 "a live non-child with its own correct stamp is not ours" is_own_child "$stranger" "$stranger_stamp"
signal_own KILL "$stranger" "$stranger_stamp" && bad "signalled a non-child" || ok "a non-child is not signalled"
kill -0 "$stranger" 2>/dev/null && ok "... and the non-child is still alive" || bad "the non-child died"
# A reaped child: its PID may be recycled by anyone, so it is never signalled.
sleep 60 & gone=$!; track "$gone"
gone_stamp="$(proc_stamp "$gone")"
kill "$gone"; wait "$gone" 2>/dev/null || true
expect 1 "a reaped child is not ours" is_own_child "$gone" "$gone_stamp"
expect 1 "a reaped child with an empty stamp is gone, not unknown" is_own_child "$gone" ""
signal_own KILL "$gone" "$gone_stamp" && bad "signalled a reaped child" || ok "a reaped child is not signalled"

# ── 5a. A live OWN child is never misread as foreign (#7538 G8-N01) ──────
# The old check compared `ps -o lstart`, which moves with the wall clock and the time zone
# and needs a working ps: a live own child read as "not ours", so nothing was signalled and
# the reap `wait` blocked on the live PID. The stamp is now the /proc start time; where
# there is no /proc the answer for a start time that moved is UNKNOWN, which is never
# signalled and never waited for.
echo "ownership: clock step, time zone, ps failure and an unreadable /proc entry"
REAL_PS="$(command -v ps)"
mkdir -p "$TMP/psbin" "$TMP/noproc" "$TMP/fakeproc/self"
cat > "$TMP/psbin/ps" <<PS
#!/usr/bin/env bash
# fake ps: FAKE_PS_MODE=fail fails; =shift adds a second to every lstart (a clock step); else real
case "\${FAKE_PS_MODE:-real}" in
    fail) exit 1 ;;
    shift) out="\$($REAL_PS "\$@")" || exit \$?; case "\$*" in *lstart*) echo "\$out +1s" ;; *) echo "\$out" ;; esac ;;
    *) exec $REAL_PS "\$@" ;;
esac
PS
chmod +x "$TMP/psbin/ps"
NOPROC_DIR="$TMP/noproc"
# own_with <fake-ps-mode> <proc-root> <pid> <stamp>: is_own_child under that environment.
own_with() {
    local mode="$1" root="$2"; shift 2
    ( PATH="$TMP/psbin:$PATH" FAKE_PS_MODE="$mode" PROC_ROOT="$root" is_own_child "$@" )
}
expect 0 "/proc stamp: a clock step (every lstart +1 s) does not make a live own child foreign" own_with shift /proc "$own" "$own_stamp"
expect 0 "/proc stamp: a failing ps does not make a live own child foreign" own_with fail /proc "$own" "$own_stamp"
TZ_A="$(TZ=UTC PROC_ROOT="$NOPROC_DIR" proc_stamp "$own")"
[[ "$TZ_A" == s:* ]] && ok "without /proc the stamp falls back to ps (s:<lstart>)" || bad "no-/proc stamp: '$TZ_A'"
expect 0 "ps fallback: an unchanged start time is ours" own_with real "$NOPROC_DIR" "$own" "$TZ_A"
expect 2 "ps fallback: a clock step is UNKNOWN, not foreign" own_with shift "$NOPROC_DIR" "$own" "$TZ_A"
expect 2 "ps fallback: a failing ps is UNKNOWN, not foreign" own_with fail "$NOPROC_DIR" "$own" "$TZ_A"
tz_rc=0; ( TZ=UTC-14 PROC_ROOT="$NOPROC_DIR" is_own_child "$own" "$TZ_A" ) || tz_rc=$?
[[ "$tz_rc" -eq 2 ]] && ok "ps fallback: a time-zone change is UNKNOWN, not foreign" || bad "time-zone change: rc $tz_rc (expected 2)"
expect 2 "an unreadable /proc entry for a live pid is UNKNOWN" own_with real "$TMP/fakeproc" "$own" "$own_stamp"
expect 1 "ps fallback: a reaped child is not ours" own_with real "$NOPROC_DIR" "$gone" "$TZ_A"
( export PATH="$TMP/psbin:$PATH" FAKE_PS_MODE=shift; PROC_ROOT="$NOPROC_DIR"; LOGF="$TMP/unk.log"; signal_own TERM "$own" "$TZ_A" ) \
    && bad "signalled on an unknown ownership" || ok "an unknown ownership is never signalled"
grep -q 'ownership could not be established' "$TMP/unk.log" && ok "... and says so" || bad "unknown ownership not logged"
kill -0 "$own" 2>/dev/null && ok "the unknown-ownership child is untouched" || bad "the unknown-ownership child died"

# stop_own_stack on each trigger, in its own bash with a watchdog: the old code blocked in
# `wait` on the live PID until the step timeout (verified rc 124 with a fake ps).
cat > "$TMP/stop_case.sh" <<'CASE'
#!/usr/bin/env bash
set -euo pipefail
source "$HELPERS"
FREE_PORTS=true; log() { :; }; STOP_TERM_POLLS=3; STOP_KILL_POLLS=3
sleep 60 & real=$!
export PATH="$PSBIN:$PATH" FAKE_PS_MODE=real
[[ -n "${NOPROC:-}" ]] && PROC_ROOT="$NOPROC"
stamp="$(proc_stamp "$real")"
SERVER_PID="$real"; SERVER_STAMP="$stamp"; GATEWAY_PID=""; GATEWAY_STAMP=""
export FAKE_PS_MODE="$AFTER_STAMP_MODE"
rc=0; ( stop_own_stack ) || rc=$?   # a subshell: it may `exit 1`, and the child below must still be killed
echo "stop_own_stack-returned rc=$rc"
if kill -0 "$real" 2>/dev/null; then echo "child-alive"; kill -9 "$real" 2>/dev/null || true; else echo "child-gone"; fi
CASE
stop_case() { # <mode-at-stop> <noproc|proc> -> STOP_OUT, STOP_RC
    local noproc=""; [[ "$2" == noproc ]] && noproc="$NOPROC_DIR"
    STOP_RC=0
    STOP_OUT="$(HELPERS="$HELPERS" PSBIN="$TMP/psbin" AFTER_STAMP_MODE="$1" NOPROC="$noproc" timeout 30 bash "$TMP/stop_case.sh" 2>&1)" || STOP_RC=$?
}
stop_case shift proc
[[ "$STOP_RC" -eq 0 && "$STOP_OUT" == *"returned rc=0"* && "$STOP_OUT" == *"child-gone"* ]] && ok "stop_own_stack, /proc stamp, shifted ps clock: the live child is stopped (no hang)" || bad "stop (shift, /proc): rc $STOP_RC: $STOP_OUT"
stop_case fail proc
[[ "$STOP_RC" -eq 0 && "$STOP_OUT" == *"returned rc=0"* && "$STOP_OUT" == *"child-gone"* ]] && ok "stop_own_stack, /proc stamp, failing ps: the live child is stopped (no hang)" || bad "stop (fail, /proc): rc $STOP_RC: $STOP_OUT"
stop_case shift noproc
[[ "$STOP_OUT" == *"returned rc=1"* && "$STOP_OUT" == *"ownership could not be established"* && "$STOP_OUT" == *"child-alive"* ]] \
    && ok "stop_own_stack, ps fallback, clock step: reports the unknown, signals and waits for nothing, exits 1 in bounded time" \
    || bad "stop (shift, no /proc): rc $STOP_RC: $STOP_OUT"
stop_case fail noproc
[[ "$STOP_OUT" == *"returned rc=1"* && "$STOP_OUT" == *"ownership could not be established"* && "$STOP_OUT" == *"child-alive"* ]] \
    && ok "stop_own_stack, ps fallback, failing ps: reports the unknown, never blocks" \
    || bad "stop (fail, no /proc): rc $STOP_RC: $STOP_OUT"
stop_case real proc
[[ "$STOP_RC" -eq 0 && "$STOP_OUT" == *"returned rc=0"* && "$STOP_OUT" == *"child-gone"* ]] && ok "stop_own_stack, healthy: the live child is stopped" || bad "stop (healthy): rc $STOP_RC: $STOP_OUT"

# ── 5b. stop_own_stack: the recycled-PID regression (#7538 K2, chaos CH-1) ─
# The real failure: on a lost race the server/gateway has exited and bash has reaped it,
# the kernel hands its PID to a process of another job (same OS identity), and
# stop_own_stack then TERMs and KILLs that PID. A recycled PID cannot be forced without
# root, so the stranger here is a LIVE non-child standing on the PID the script holds,
# with a correct stamp (the worst case); it must receive nothing, while a real own child
# in the same call is stopped.
echo "ownership: stop_own_stack never signals a PID it does not own (CH-1)"
SENT_OUT="$TMP/sentinel.out"; : > "$SENT_OUT"
( bash -c 'trap "echo TERM >> '"$SENT_OUT"'" TERM; trap "echo INT >> '"$SENT_OUT"'" INT; echo $$ > '"$TMP"'/sentinel.pid; while :; do sleep 0.1; done'; : ) &   # the trailing `:` stops the subshell exec'ing it, so it is NOT our child
track "$!"
for _ in $(seq 1 50); do [[ -s "$TMP/sentinel.pid" ]] && break; sleep 0.1; done
sentinel="$(cat "$TMP/sentinel.pid")"; track "$sentinel"
sleep 60 & real=$!; track "$real"
GATEWAY_PID="$sentinel"; GATEWAY_STAMP="$(proc_stamp "$sentinel")"
SERVER_PID="$real";      SERVER_STAMP="$(proc_stamp "$real")"
stop_own_stack
# The sentinel runs its TERM trap between its 0.1 s sleeps: wait long enough for a
# signal sent by mistake to have been recorded (polled, not a fixed sleep, G8-N06).
for _ in $(seq 1 20); do [[ -s "$SENT_OUT" ]] && break; sleep 0.1; done
[[ ! -s "$SENT_OUT" ]] && ok "the stranger on the gateway's PID received no signal" || bad "the stranger was signalled: $(cat "$SENT_OUT")"
kill -0 "$sentinel" 2>/dev/null && ok "... and is still alive" || bad "the stranger was killed"
kill -0 "$real" 2>/dev/null && bad "the real own child survived stop_own_stack" || ok "a real own child was stopped and reaped"
[[ -z "$SERVER_PID$GATEWAY_PID$SERVER_STAMP$GATEWAY_STAMP" ]] && ok "stop_own_stack clears its records" || bad "records not cleared"
# And a live own child IS signalled.
signal_own TERM "$own" "$own_stamp" && ok "a live own child is signalled" || bad "own child not signalled"
wait "$own" 2>/dev/null || true
kill -0 "$own" 2>/dev/null && bad "own child survived TERM" || ok "... and it exited"

# ── 5c. verify_stack_bound (#7538 G8-N03) ────────────────────────────────
echo "verify_stack_bound: dead pids, foreign listeners on each of the stack's ports"
VSB="$TMP/vsb"; mkdir -p "$VSB"
sleep 60 & vs_srv=$!; track "$vs_srv"
sleep 60 & vs_gw=$!; track "$vs_gw"
sleep 60 & vs_dead=$!; track "$vs_dead"; kill "$vs_dead"; wait "$vs_dead" 2>/dev/null || true
WORK_DIR="$VSB"; USE_TLS=true; FREE_PORTS=true
SERVER_AGENT_PORT=41001; SERVER_MGMT_PORT=41002; SERVER_GW_PORT=41003; SERVER_WEB_PORT=41004
GW_AGENT_PORT=41005; GW_MGMT_PORT=41006; GW_METRICS_PORT=41007; GW_HEALTH_PORT=41008
SERVER_PID="$vs_srv"; GATEWAY_PID="$vs_gw"
lrow() { printf 'LISTEN 0 128 127.0.0.1:%s 0.0.0.0:* users:(("p",pid=%s,fd=3))' "$1" "$2"; }
all_own() {
    local r="" p
    for p in 41001 41002 41003 41004; do r="$r$(lrow "$p" "$vs_srv")\n"; done
    for p in 41005 41006 41007 41008; do r="$r$(lrow "$p" "$vs_gw")\n"; done
    printf '%s' "$r"
}
: > "$VSB/server.log"; : > "$VSB/gateway.log"
FAKE_SS_ROWS="$(all_own)"
expect 0 "every port held by its own process -> 0" verify_stack_bound
FAKE_SS_ROWS=""
expect 0 "nothing listening at all (ss shows no row) -> 0: not this check's failure" verify_stack_bound
for p in 41001 41002 41003 41004 41005 41006 41007 41008; do
    FAKE_SS_ROWS="$(all_own)$(lrow "$p" 555)"
    expect 10 "a stranger sharing port $p -> lost race" verify_stack_bound
done
USE_TLS=false
FAKE_SS_ROWS="$(all_own)$(lrow 41006 555)"
expect 0 "plaintext mode: the management port is not part of the stack, a stranger there is ignored" verify_stack_bound
FAKE_SS_ROWS="$(all_own)$(lrow 41005 555)"
expect 10 "plaintext mode: a stranger on the gateway agent port is still caught" verify_stack_bound
USE_TLS=true
FAKE_SS_ROWS="$(all_own)\nLISTEN 0 128 127.0.0.1:41002 0.0.0.0:*"
expect 0 "an unattributable row on a stack port is not counted as foreign" verify_stack_bound
FREE_PORTS=false
FAKE_SS_ROWS="$(all_own)$(lrow 41005 555)"
expect 0 "without --free-ports the ownership check does not run" verify_stack_bound
FREE_PORTS=true
FAKE_SS_ROWS="$(all_own)"
fx_in() { printf '%s\n' "$2" > "$VSB/$1"; }
fx_in gateway.log "$(cat "$TMP/idx4.log")"
expect 10 "alive, but the gateway log carries the errno -> lost race" verify_stack_bound
: > "$VSB/gateway.log"
fx_in server.log "$(cat "$TMP/weblist.log")"
FAKE_SS_ROWS="$(all_own)$(lrow 41004 555)"
expect 10 "alive, the server's web line and a stranger on the web port -> lost race" verify_stack_bound
: > "$VSB/server.log"
# a dead process: a lost race only when its log proves a bind failure
FAKE_SS_ROWS=""
SERVER_PID="$vs_dead"; GATEWAY_PID="$vs_gw"
expect 1 "the server is gone, no bind evidence -> a crash (1)" verify_stack_bound
fx_in server.log "$(cat "$TMP/idx0.log")"
expect 10 "the server is gone and its log has the errno -> lost race (10)" verify_stack_bound
FREE_PORTS=false
expect 1 "the server is gone and its log has the errno, without --free-ports -> 1" verify_stack_bound
FREE_PORTS=true
: > "$VSB/server.log"
SERVER_PID="$vs_srv"; GATEWAY_PID="$vs_dead"
expect 1 "the gateway is gone, no bind evidence -> 1" verify_stack_bound
fx_in gateway.log "$(cat "$TMP/idx7.log")"
expect 10 "the gateway is gone and its log has the errno -> lost race (10)" verify_stack_bound
: > "$VSB/gateway.log"
PATH="$TMP/noss"
SERVER_PID="$vs_srv"; GATEWAY_PID="$vs_gw"
expect 0 "ss absent: the ownership half is skipped -> 0" verify_stack_bound
PATH="$TMP/bin:$ORIG_PATH"

# ── 5d. The attempt loop (#7538 G8-N03) ──────────────────────────────────
echo "run_start_attempts: classify, retry on new ports, give up on the third, never retry a non-bind failure"
cat > "$TMP/attempts.sh" <<'ATT'
#!/usr/bin/env bash
set -euo pipefail
source "$HELPERS"
FREE_PORTS="$FREE"; log() { echo "LOG $*"; }; retry_pause() { :; }
USE_TLS=true
CALLS="$WORK_DIR/calls"; : > "$CALLS"
allocate_free_ports() { echo draw >> "$CALLS"; }
start_port_hog() { echo "hog $1" >> "$CALLS"; }
compute_port_derived() { :; }
write_gateway_config() { :; }
stop_own_stack() { echo stop >> "$CALLS"; }
stop_port_hog() { echo stophog >> "$CALLS"; }
IFS=' ' read -ra RC <<< "$RCS"
n=0
start_own_stack() {
    echo "start $START_ATTEMPT" >> "$CALLS"
    echo "server-attempt-$START_ATTEMPT" > "$WORK_DIR/server.log"; echo "gw-attempt-$START_ATTEMPT" > "$WORK_DIR/gateway.log"
    echo crash > "$WORK_DIR/gateway.attempt${START_ATTEMPT}.crash"
    BIND_EVIDENCE="fake bind evidence"
    local r="${RC[$n]}"; n=$((n + 1)); return "$r"
}
run_start_attempts
echo RETURNED
ATT
attempts() { # <free_ports> <rc list> [hog index] -> AT_OUT, AT_RC, files in $TMP/at
    rm -rf "$TMP/at"; mkdir -p "$TMP/at"
    AT_RC=0
    AT_OUT="$(HELPERS="$HELPERS" WORK_DIR="$TMP/at" FREE="$1" RCS="$2" YUZU_IT_PORT_HOG_INDEX="${3:-}" bash "$TMP/attempts.sh" 2>&1)" || AT_RC=$?
}
count() { grep -c -- "$1" "$TMP/at/calls" || true; }
attempts true "0"
[[ "$AT_RC" -eq 0 && "$AT_OUT" == *RETURNED* && "$(count "^draw$")" -eq 1 && "$(count "^stop$")" -eq 0 ]] \
    && ok "first start ok: one attempt, one draw, no stop" || bad "first-start-ok: rc $AT_RC draws $(count "^draw$") stops $(count "^stop$")"
attempts true "10 0" 3
[[ "$AT_RC" -eq 0 && "$AT_OUT" == *RETURNED* && "$(count "^draw$")" -eq 2 && "$(count "^stop$")" -eq 1 && "$(count "^start ")" -eq 2 ]] \
    && ok "a lost race then ok: stopped once, 8 ports drawn again, second attempt starts" || bad "race-then-ok: rc $AT_RC draws $(count "^draw$") stops $(count "^stop$"): $AT_OUT"
[[ "$(cat "$TMP/at/server.attempt1.log")" == server-attempt-1 && "$(cat "$TMP/at/gateway.attempt1.log")" == gw-attempt-1 ]] \
    && ok "the lost attempt's logs are kept as *.attempt1.log" || bad "attempt logs not rotated"
[[ ! -e "$TMP/at/gateway.attempt1.crash" ]] && ok "the lost attempt's crash dump is removed with the rotation (G8-N21)" || bad "crash dump of a retried attempt kept"
[[ "$AT_OUT" == *"attempt 1 of 3 lost a port before bind (fake bind evidence)"* && "$AT_OUT" == *"Stack started on attempt 2 of 3"* ]] \
    && ok "the retry is logged with its evidence, and so is the success on attempt 2" || bad "retry log lines: $AT_OUT"
attempts true "10 10 0" 3
[[ "$(count "^hog ")" -eq 1 && "$(count "^draw$")" -eq 3 ]] && ok "the port-hog seam runs on attempt 1 only; three draws for three attempts" || bad "hog calls $(count "^hog "), draws $(count "^draw$")"
attempts true "10 10 10"
[[ "$AT_RC" -eq 1 && "$(count "^draw$")" -eq 3 && "$(count "^start ")" -eq 3 && "$(count "^stop$")" -eq 2 && "$AT_OUT" != *RETURNED* \
   && "$AT_OUT" == *"hit a port bind failure on attempt 3 of 3: fake bind evidence"* ]] \
    && ok "three lost races: fails on the third, exactly 3 attempts, the third is not retried" || bad "three races: rc $AT_RC draws $(count "^draw$") starts $(count "^start ") stops $(count "^stop$"): $AT_OUT"
attempts true "1 0"
[[ "$AT_RC" -eq 1 && "$(count "^draw$")" -eq 1 && "$(count "^stop$")" -eq 0 && "$AT_OUT" == *"no bind-failure evidence, not retried"* ]] \
    && ok "a non-bind failure on attempt 1 is not retried" || bad "non-bind failure: rc $AT_RC draws $(count "^draw$"): $AT_OUT"
attempts true "10 1 0"
[[ "$AT_RC" -eq 1 && "$(count "^draw$")" -eq 2 && "$AT_OUT" == *"no bind-failure evidence, not retried"* ]] \
    && ok "a race then a non-bind failure: stops at the second, never a third" || bad "race then crash: rc $AT_RC draws $(count "^draw$"): $AT_OUT"
attempts false "10 0"
[[ "$AT_RC" -eq 1 && "$(count "^draw$")" -eq 0 && "$(count "^start ")" -eq 1 && "$AT_OUT" == *"attempt 1 of 1"* ]] \
    && ok "without --free-ports there is exactly one attempt and no port is drawn" || bad "fixed ports: rc $AT_RC draws $(count "^draw$") starts $(count "^start "): $AT_OUT"
attempts false "1"
[[ "$AT_RC" -eq 1 && "$AT_OUT" == *"fixed ports: a bind failure is not classified or retried"* ]] \
    && ok "a failed start on fixed ports names the fixed-port policy" || bad "fixed-port failure text: $AT_OUT"

# ── 5e. cleanup(): a forked launch child never tears the run down (#7538 K19) ─
echo "cleanup: a signal between fork and exec must not run it in the child"
cat > "$TMP/k19.sh" <<'K19'
#!/usr/bin/env bash
# usage: k19.sh <script-with-cleanup> <signal> <launches>: prints the number of launches
# whose cleanup() ran in the CHILD (the signal lands right after the fork).
src="$1"; sig="$2"; n="$3"; M="$TMP_K19/marks"; : > "$M"
eval "$(awk '/^cleanup\(\) \{/{p=1} p{print} p&&/^}/{exit}' "$src")"
log() { [[ "$1" == "Tearing down..." ]] || return 0; if [[ "$BASHPID" != "$$" ]]; then echo child >> "$M"; else echo parent >> "$M"; fi; }
signal_own() { return 0; }
REUSE_STACK=false; AGENT_PIDS=(); AGENT_STAMPS=(); GATEWAY_PID=""; GATEWAY_STAMP=""; SERVER_PID=""; SERVER_STAMP=""
PORT_HOG_PID=""; PORT_HOG_STAMP=""; IT_DB=""; WORK_DIR=""
sleep() { :; }
trap cleanup EXIT
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP
for ((i = 0; i < n; i++)); do
    ( trap - EXIT TERM; exec /bin/true ) &
    pid=$!
    kill -"$sig" "$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
done
trap - EXIT
grep -c child "$M" || true
K19
mkdir -p "$TMP/k19"
k19_count() { TMP_K19="$TMP/k19" bash "$TMP/k19.sh" "$1" "$2" "$3" 2> /dev/null; }
sed '/\[\[ "\$BASHPID" == "\$\$" \]\] || return 0/d' "$SCRIPT" > "$TMP/script_noguard.sh"
if grep -q 'BASHPID' "$TMP/script_noguard.sh" && grep -qE '^\s*\[\[ "\$BASHPID" == "\$\$" \]\]' "$TMP/script_noguard.sh"; then
    bad "the no-guard control copy still has the guard"
fi
for sig in TERM HUP; do
    base="$(k19_count "$TMP/script_noguard.sh" "$sig" 200)"
    [[ "$base" -gt 0 ]] && ok "control: without the guard $base of 200 $sig launches ran cleanup() in the child (the harness sees the defect)" \
        || bad "control: the harness saw no child cleanup without the guard ($sig)"
    got="$(k19_count "$SCRIPT" "$sig" 200)"
    [[ "$got" -eq 0 ]] && ok "with the guard: 0 of 200 $sig launches ran cleanup() in the child" || bad "$got of 200 $sig launches ran cleanup() in the child"
done

# ── 5f. mono_seconds ─────────────────────────────────────────────────────
echo "mono_seconds: a monotonic integer, with a fallback"
m1="$(mono_seconds)"; sleep 1.1; m2="$(mono_seconds)"
[[ "$m1" =~ ^[0-9]+$ && "$m2" =~ ^[0-9]+$ && "$m2" -gt "$m1" ]] && ok "mono_seconds is an integer that advances" || bad "mono_seconds: $m1 then $m2"
m3="$(PROC_ROOT="$NOPROC_DIR" mono_seconds)"
[[ "$m3" =~ ^[0-9]+$ ]] && ok "without /proc/uptime it falls back to an integer" || bad "mono_seconds fallback: $m3"

# ── 6. Lexical pins: the script uses what is tested ───────────────────
echo "pins: the script wires the tested helpers"
grep -qF "BIND_FAILURE_RE='eaddrinuse|Address already in use'" "$SCRIPT" \
    && ok "the regex is exactly the errno alternatives" || bad "BIND_FAILURE_RE changed"
if grep -E "^BIND_FAILURE_RE=" "$SCRIPT" | grep -qE 'Failed to start gRPC server|Failed to add port|listener failed'; then
    bad "BIND_FAILURE_RE matches a generic start-failure line"
else
    ok "the regex carries no generic start-failure alternative"
fi
if grep -nE '^\s*(kill|signal)\s+(-9\s+|-KILL\s+|-TERM\s+)?"\$\{?(SERVER|GATEWAY)_PID' "$SCRIPT" | grep -v '^\s*#' | grep -q .; then
    bad "a bare kill of SERVER_PID/GATEWAY_PID is back (use signal_own)"
else
    ok "no bare kill of SERVER_PID/GATEWAY_PID"
fi
# stop_own_stack and cleanup signal only through signal_own: no other kill in their bodies.
for fn in stop_own_stack cleanup; do
    if sed -n "/^$fn() {\$/,/^}\$/p" "$SCRIPT" | grep -vE '^\s*#' | grep -vE 'kill -0' | grep -qE '(^|[^_a-z])kill '; then
        bad "$fn() signals with a bare kill (use signal_own)"
    else
        ok "$fn() signals only through signal_own"
    fi
done
for need in 'trap '"'"'exit 143'"'"' TERM' 'trap '"'"'exit 130'"'"' INT' 'emit_race_annotation "$START_ATTEMPT"'; do
    grep -qF -- "$need" "$SCRIPT" && ok "present: $need" || bad "missing: $need"
done

echo
if [[ "$FAILS" -ne 0 ]]; then
    echo "FAILED: $FAILS of $CASES checks"
    exit 1
fi
echo "OK: $CASES checks"
