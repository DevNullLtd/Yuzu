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
# The ownership half (is_own_child / signal_own, #7538 K2) is run against real
# processes: a reaped child, a live non-child and a stale start time are never signalled.
#
# The helpers are extracted from the script between its `testable-helpers` markers and
# sourced; no server, gateway, Postgres, network or root is needed, and `ss` is a fake
# on PATH. Nothing outside the yuzu_test_ temp dir is touched or signalled.
#
# Run:  bash tests/shell/test_integration_port_retry.sh
# shellcheck disable=SC2016  # the lexical pins below deliberately match literal $-expressions
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SCRIPT="${YUZU_IT_SCRIPT_UNDER_TEST:-$ROOT/scripts/integration-test.sh}"  # override: mutation runs on a scratch copy
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_itretry.XXXXXX")"
CHILDREN=()
cleanup() {
    local p
    for p in "${CHILDREN[@]+"${CHILDREN[@]}"}"; do kill "$p" 2>/dev/null || true; done
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
log() { :; }
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
# fake ss: prints the header and the rows in $FAKE_SS_ROWS (one per line)
echo "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
[[ -n "${FAKE_SS_ROWS:-}" ]] && printf '%b\n' "$FAKE_SS_ROWS"
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
FAKE_SS_ROWS="$NOPROC";                  expect 1 "web line + an unattributable listener -> not counted as foreign" web_bind_lost "$TMP/web.log" 4242 42131
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
PATH="$TMP/bin:$ORIG_PATH"

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
out="$(GITHUB_ACTIONS='' GITHUB_STEP_SUMMARY="$SUMMARY" emit_race_annotation 1 3 "x")"
[[ -z "$out" ]] && ok "silent outside GitHub Actions" || bad "annotation outside CI: $out"

# ── 5. Ownership: only a live child with its launch start time is signalled ─
echo "ownership: is_own_child / signal_own against real processes"
sleep 60 & own=$!; CHILDREN+=("$own")
own_stamp="$(proc_stamp "$own")"
[[ -n "$own_stamp" ]] && ok "a live child has a start stamp" || bad "no stamp for a live child"
expect 0 "a live child with its stamp is ours" is_own_child "$own" "$own_stamp"
expect 1 "the same child with a stale start time is not ours (recycled PID)" is_own_child "$own" "Thu Jan  1 00:00:00 1970"
expect 1 "an empty stamp is never ours" is_own_child "$own" ""
expect 1 "an empty pid is never ours" is_own_child "" "$own_stamp"
signal_own TERM "$own" "Thu Jan  1 00:00:00 1970" && bad "signalled a child with a stale stamp" || ok "a stale stamp is not signalled"
kill -0 "$own" 2>/dev/null && ok "... and the child is still alive" || bad "the stale-stamp child died"
# A live process that is not a child of this shell (a stranger on the same host).
( sleep 60 & echo $! > "$TMP/stranger.pid"; wait ) &
CHILDREN+=("$!")
for _ in $(seq 1 50); do [[ -s "$TMP/stranger.pid" ]] && break; sleep 0.1; done
stranger="$(cat "$TMP/stranger.pid")"
stranger_stamp="$(proc_stamp "$stranger")"
expect 1 "a live non-child with its own correct stamp is not ours" is_own_child "$stranger" "$stranger_stamp"
signal_own KILL "$stranger" "$stranger_stamp" && bad "signalled a non-child" || ok "a non-child is not signalled"
kill -0 "$stranger" 2>/dev/null && ok "... and the non-child is still alive" || bad "the non-child died"
kill "$stranger" 2>/dev/null || true
# A reaped child: its PID may be recycled by anyone, so it is never signalled.
sleep 60 & gone=$!
gone_stamp="$(proc_stamp "$gone")"
kill "$gone"; wait "$gone" 2>/dev/null || true
expect 1 "a reaped child is not ours" is_own_child "$gone" "$gone_stamp"
signal_own KILL "$gone" "$gone_stamp" && bad "signalled a reaped child" || ok "a reaped child is not signalled"
# And a live own child IS signalled.
signal_own TERM "$own" "$own_stamp" && ok "a live own child is signalled" || bad "own child not signalled"
wait "$own" 2>/dev/null || true
kill -0 "$own" 2>/dev/null && bad "own child survived TERM" || ok "... and it exited"

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
CHILDREN+=("$!")
for _ in $(seq 1 50); do [[ -s "$TMP/sentinel.pid" ]] && break; sleep 0.1; done
sentinel="$(cat "$TMP/sentinel.pid")"
sleep 60 & real=$!; CHILDREN+=("$real")
GATEWAY_PID="$sentinel"; GATEWAY_STAMP="$(proc_stamp "$sentinel")"
SERVER_PID="$real";      SERVER_STAMP="$(proc_stamp "$real")"
stop_own_stack
sleep 0.5   # the sentinel runs its TERM trap between its sleeps
[[ ! -s "$SENT_OUT" ]] && ok "the stranger on the gateway's PID received no signal" || bad "the stranger was signalled: $(cat "$SENT_OUT")"
kill -0 "$sentinel" 2>/dev/null && ok "... and is still alive" || bad "the stranger was killed"
kill -0 "$real" 2>/dev/null && bad "the real own child survived stop_own_stack" || ok "a real own child was stopped and reaped"
[[ -z "$SERVER_PID$GATEWAY_PID$SERVER_STAMP$GATEWAY_STAMP" ]] && ok "stop_own_stack clears its records" || bad "records not cleared"
kill -9 "$sentinel" 2>/dev/null || true   # it traps TERM

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
    if sed -n "/^$fn() {\$/,/^}\$/p" "$SCRIPT" | grep -vE '^\s*#' | grep -qE '(^|[^_a-z])kill '; then
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
