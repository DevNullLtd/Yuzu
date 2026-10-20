#!/usr/bin/env bash
# test_uat_netns.sh — scripts/uat-netns.sh.
#   1. argument contract (every rejection happens before Docker or Postgres is touched;
#      the stubs are on PATH anyway, so a regression in validation order cannot reach a
#      real docker);
#   2. STUBBED runs of the wrapper (fake docker + bwrap on PATH, state dir under a
#      yuzu_test_ temp dir): the exact bwrap and docker argv, that no credential ever
#      reaches a command line or the wrapper's output (argv is world-readable through
#      /proc), the locks, container reuse, concurrent cold starts, exit codes, pg-down.
#      This is what pins the isolation flags — a grep for the flag text would stay
#      green if the flags moved out of the real exec;
#   3. the property the wrapper exists for, where unprivileged user namespaces are
#      available: two namespaces bind the SAME loopback port at once and the host
#      cannot reach it.
# Needs neither Docker, Postgres, nor a built binary.
#
# What stubs CANNOT see: whether the real image's init-phase server answers a socket
# probe early (the reason readiness probes loopback TCP) — the probe's argv is pinned
# below instead.
#
# Run:  bash tests/shell/test_uat_netns.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
WRAP="$ROOT/scripts/uat-netns.sh"
[ -f "$WRAP" ] || { echo "missing $WRAP" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_netns.XXXXXX")"
JOBS_TO_KILL=""
cleanup() {
  # shellcheck disable=SC2086  # JOBS_TO_KILL is a deliberate word list of pids
  [ -z "$JOBS_TO_KILL" ] || kill $JOBS_TO_KILL 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

pass=0 fail=0
check() { if [ "$2" = 0 ]; then printf '  [pass] %s\n' "$1"; pass=$((pass + 1)); else printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); fi; }
skip() { printf '  [skip] %s\n' "$1"; }
has() { grep -qF -- "$2" "$1" 2>/dev/null; }
count() { grep -cF -- "$2" "$1" 2>/dev/null || true; }

# This suite must not inherit a real rig's state.
unset YUZU_UAT_PG_DSN YUZU_NETNS_RIG YUZU_NETNS_STATE

# Stubs. docker records argv (one line per call, each arg bracketed) and the password
# env it was handed; bwrap records argv, the rig environment and which descriptors the
# rig inherited. Both are inert: no container, no namespace.
BIN="$TMP/bin"; mkdir -p "$BIN"
cat > "$BIN/docker" <<'STUB'
#!/usr/bin/env bash
{ printf 'docker'; for a in "$@"; do printf ' [%s]' "$a"; done; echo; } >> "$STUB_DIR/docker.log"
[ -z "${POSTGRES_PASSWORD:-}" ] || printf '%s\n' "$POSTGRES_PASSWORD" > "$STUB_DIR/env.su"
[ -z "${YUZU_DB_PASSWORD:-}" ] || printf '%s\n' "$YUZU_DB_PASSWORD" > "$STUB_DIR/env.app"
case "$1" in
  info) [ -z "${STUB_NO_DAEMON:-}" ] || exit 1 ;;
  exec) case " $* " in *" pg_isready "*) [ -z "${STUB_NOT_READY:-}" ] || exit 1 ;; esac ;;
  ps) [ ! -e "$STUB_DIR/started" ] || echo yuzu-netns-pg ;;
  rm) rm -f "$STUB_DIR/started" ;;
  run) case " $* " in *" -d "*) sleep "${STUB_RUN_SLEEP:-0}"; : > "$STUB_DIR/started" ;; esac ;;
esac
exit 0
STUB
cat > "$BIN/bwrap" <<'STUB'
#!/usr/bin/env bash
{ printf 'bwrap'; for a in "$@"; do printf ' [%s]' "$a"; done; echo; } >> "$STUB_DIR/bwrap.log"
# The probe is `... true`; the real call carries --tmpfs.
case " $* " in
  *" --tmpfs "*)
    printf '%s\n' "${YUZU_UAT_PG_DSN:-}" > "$STUB_DIR/dsn"
    printf '%s\n' "${YUZU_NETNS_RIG:-}" > "$STUB_DIR/rig"
    { [ -e /dev/fd/8 ] && echo fd8; [ -e /dev/fd/9 ] && echo fd9; } > "$STUB_DIR/leaked-fds" || true
    : > "$STUB_DIR/real-call"
    # Hold (the rig is "running") until released, so a second run can be refused.
    if [ -n "${STUB_HOLD:-}" ]; then
      n=0; while [ ! -e "$STUB_DIR/release" ] && [ "$n" -lt 160 ]; do sleep 0.25; n=$((n + 1)); done
    fi
    exit "${STUB_EXIT:-0}" ;;
esac
exit 0
STUB
chmod +x "$BIN/docker" "$BIN/bwrap"

export STUB_DIR="$TMP/stub"; mkdir -p "$STUB_DIR"
STATE_DIR="$TMP/state"
# stubbed <args...>: run the wrapper with the stubs first on PATH and a private state dir.
stubbed() { set +e; out=$(PATH="$BIN:$PATH" YUZU_NETNS_STATE="$STATE_DIR" bash "$WRAP" "$@" 2>&1); rc=$?; set -e; }
# run <args...>: the contract cases — same stubs, throwaway state, so even a regression
# in argument validation cannot reach a real docker or the real fixed names.
run() { set +e; out=$(PATH="$BIN:$PATH" YUZU_NETNS_STATE="$TMP/contract-state" bash "$WRAP" "$@" 2>&1); rc=$?; set -e; }

echo "argument contract"
run run
check "run with no rig is a usage error" "$([ $rc != 0 ] && [[ $out == *usage* ]] && echo 0 || echo 1)"
for bad in 'A' '1a' 'a-b' 'a;drop' 'a b' 'abcdefghijklmnopqrstuvwxyz'; do
  run run "$bad" -- true
  check "rig name '$bad' rejected (it becomes a database name)" "$([ $rc != 0 ] && [[ $out == *'rig name must match'* ]] && echo 0 || echo 1)"
done
run run a true
check "missing -- separator rejected" "$([ $rc != 0 ] && [[ $out == *usage* ]] && echo 0 || echo 1)"
run run a --
check "empty command after -- rejected" "$([ $rc != 0 ] && [[ $out == *'no command'* ]] && echo 0 || echo 1)"
run bogus
check "unknown subcommand rejected" "$([ $rc != 0 ] && [[ $out == *'unknown subcommand'* ]] && echo 0 || echo 1)"
run pg-down --bogus
check "pg-down rejects an unknown flag" "$([ $rc != 0 ] && [[ $out == *usage* ]] && echo 0 || echo 1)"
run --help
check "--help prints the header and exits 0" "$([ $rc = 0 ] && [[ $out == *'private network'* && $out == *'NOT A SANDBOX'* && $out == *'pg-down [--force]'* ]] && echo 0 || echo 1)"
check "the contract cases never reached docker" "$([ ! -e "$STUB_DIR/docker.log" ] && echo 0 || echo 1)"

echo "stubbed runs of the wrapper"
if command -v flock >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 \
   && [ "$(stat -c %a / 2>/dev/null || true)" != "" ]; then
  stubbed run a -- echo hello world
  check "stubbed run exits 0" "$([ $rc = 0 ] && echo 0 || { echo "$out" >&2; echo 1; })"
  real=$(grep -F '[--tmpfs]' "$STUB_DIR/bwrap.log" | tail -1)
  want_all=0
  for f in '[--dev-bind] [/] [/]' '[--proc] [/proc]' '[--unshare-net]' '[--unshare-pid]' '[--die-with-parent]' \
           '[--tmpfs] [/tmp/yuzu-uat]' '[echo] [hello] [world]'; do
    case "$real" in *"$f"*) ;; *) want_all=1; echo "    missing in bwrap argv: $f" >&2 ;; esac
  done
  check "bwrap gets every isolation flag and the user's command" "$want_all"
  probe=$(grep -vF '[--tmpfs]' "$STUB_DIR/bwrap.log" | head -1)
  check "the capability probe uses the same namespace flags (incl. --proc)" "$([[ $probe == *'[--unshare-net]'* && $probe == *'[--unshare-pid]'* && $probe == *'[--proc] [/proc]'* ]] && echo 0 || echo 1)"
  check "the rig inherits neither the rig-lock fd nor the pg-lock fd" "$([ ! -s "$STUB_DIR/leaked-fds" ] && echo 0 || echo 1)"

  app=$(cat "$STATE_DIR/pgapp"); su=$(cat "$STUB_DIR/env.su")
  check "pgapp is a non-trivial secret, mode 600; state dir mode 700" "$([ "${#app}" -ge 32 ] && [ "$(stat -c %a "$STATE_DIR/pgapp")" = 600 ] && [ "$(stat -c %a "$STATE_DIR")" = 700 ] && echo 0 || echo 1)"
  check "no credential on ANY bwrap or docker command line" "$(! grep -qF -e "$app" -e "$su" "$STUB_DIR/bwrap.log" "$STUB_DIR/docker.log" && echo 0 || echo 1)"
  check "no credential in the wrapper's own output" "$([[ $out != *"$app"* && $out != *"$su"* ]] && echo 0 || echo 1)"
  check "bwrap argv carries no DSN at all" "$(! grep -qF 'postgresql://' "$STUB_DIR/bwrap.log" && echo 0 || echo 1)"
  check "the DSN reaches the rig in its environment, pointing at the unix socket and the rig's own database" \
    "$([ "$(cat "$STUB_DIR/dsn")" = "postgresql://yuzu:${app}@/yuzu_a?host=${STATE_DIR}/sock" ] && [ "$(cat "$STUB_DIR/rig")" = a ] && echo 0 || echo 1)"
  check "the passwords did reach docker, by environment (name-only -e)" "$([ "$(cat "$STUB_DIR/env.app")" = "$app" ] && has "$STUB_DIR/docker.log" '[-e] [POSTGRES_PASSWORD]' && has "$STUB_DIR/docker.log" '[-e] [YUZU_DB_PASSWORD]' && echo 0 || echo 1)"
  run_line=$(grep -F 'docker [run] [-d]' "$STUB_DIR/docker.log" | head -1)
  bad_net=0
  case "$run_line" in *'[--network] [none]'*) ;; *) bad_net=1 ;; esac
  for f in '[-p]' '[-P]' '[--publish]' '[--network] [host]' '[--net]' '[--privileged]' '[--cap-add]' '[--env-file]'; do
    case "$run_line" in *"$f"*) bad_net=1 ;; esac
  done
  check "postgres container: --network none, no published port, not privileged" "$bad_net"
  check "the socket directory is the only mount into the container" "$([[ $run_line == *"[-v] [${STATE_DIR}/sock:/var/run/postgresql]"* ]] && [ "$(grep -o '\[-v\]' <<<"$run_line" | wc -l | tr -d ' ')" = 1 ] && echo 0 || echo 1)"
  check "postgres is started with a connection ceiling above the image default" "$([[ $run_line == *'[postgres] [-c] [max_connections=300]'* ]] && echo 0 || echo 1)"
  cname=$(grep -o '\[--name\] \[[^]]*\]' <<<"$run_line" | sed 's/.*\[\(.*\)\]/\1/')
  check "the container name is keyed by the state dir" "$([[ $cname == yuzu-netns-pg-* ]] && echo 0 || echo 1)"
  check "readiness probes loopback TCP in the container (the init-phase server is socket-only)" \
    "$(has "$STUB_DIR/docker.log" "[exec] [$cname] [pg_isready] [-h] [127.0.0.1]" && ! has "$STUB_DIR/docker.log" '[pg_isready] [-h] [/var/run/postgresql]' && echo 0 || echo 1)"
  check "the rig's database is dropped and recreated" "$(has "$STUB_DIR/docker.log" 'DROP DATABASE IF EXISTS yuzu_a WITH (FORCE)' && has "$STUB_DIR/docker.log" 'CREATE DATABASE yuzu_a OWNER yuzu' && echo 0 || echo 1)"

  # Sequential re-run: works, and never restarts the running container.
  stubbed run a -- true
  check "a second SEQUENTIAL run of the same rig works" "$([ $rc = 0 ] && echo 0 || echo 1)"
  stubbed run b -- true
  check "another rig works too; the shared container was started exactly once" "$([ $rc = 0 ] && [ "$(count "$STUB_DIR/docker.log" 'docker [run] [-d]')" = 1 ] && echo 0 || echo 1)"

  # The rig's own exit status comes back through the wrapper.
  set +e; out=$(STUB_EXIT=7 PATH="$BIN:$PATH" YUZU_NETNS_STATE="$STATE_DIR" bash "$WRAP" run a -- false 2>&1); rc=$?; set -e
  check "the rig's exit status propagates (7 stays 7)" "$([ $rc = 7 ] && echo 0 || echo 1)"

  # A second `run` of a LIVE rig is refused before it can touch the database.
  rm -f "$STUB_DIR/real-call" "$STUB_DIR/release"
  ( STUB_HOLD=1 PATH="$BIN:$PATH" YUZU_NETNS_STATE="$STATE_DIR" bash "$WRAP" run a -- sleep 1 >/dev/null 2>&1 ) &
  hold_pid=$!; JOBS_TO_KILL="$hold_pid"
  for _ in $(seq 1 40); do [ -e "$STUB_DIR/real-call" ] && break; sleep 0.25; done
  drops_before=$(count "$STUB_DIR/docker.log" 'DROP DATABASE IF EXISTS yuzu_a')
  stubbed run a -- true
  check "a second run of a live rig name is refused, naming the lock" "$([ $rc != 0 ] && [[ $out == *'already running'* ]] && echo 0 || echo 1)"
  check "...and it did NOT drop the live rig's database first" "$([ "$(count "$STUB_DIR/docker.log" 'DROP DATABASE IF EXISTS yuzu_a')" = "$drops_before" ] && echo 0 || echo 1)"
  stubbed run c -- true
  check "a different rig name is still allowed alongside it" "$([ $rc = 0 ] && echo 0 || echo 1)"
  check "...and the shared container was still not restarted" "$([ "$(count "$STUB_DIR/docker.log" 'docker [run] [-d]')" = 1 ] && echo 0 || echo 1)"
  stubbed status
  check "status names the running rig" "$([[ $out == *'rig running: a'* ]] && echo 0 || echo 1)"
  stubbed pg-down
  check "pg-down REFUSES while a rig is running" "$([ $rc != 0 ] && [[ $out == *'still running'* && $out == *a* ]] && [ -s "$STATE_DIR/pgapp" ] && echo 0 || echo 1)"
  : > "$STUB_DIR/release"
  wait "$hold_pid" 2>/dev/null || true; JOBS_TO_KILL=""

  # Credentials gone but the container still running: refuse, do not remove it.
  runs_before=$(count "$STUB_DIR/docker.log" 'docker [run] [-d]')
  mv "$STATE_DIR/pgapp" "$STATE_DIR/pgapp.saved"
  stubbed run a -- true
  check "a running container whose credentials are gone is refused, not removed" "$([ $rc != 0 ] && [[ $out == *'credentials'* ]] && [ "$(count "$STUB_DIR/docker.log" 'docker [run] [-d]')" = "$runs_before" ] && echo 0 || echo 1)"
  mv "$STATE_DIR/pgapp.saved" "$STATE_DIR/pgapp"

  # pg-down, success path.
  rms_before=$(count "$STUB_DIR/docker.log" "[rm] [-fv] [$cname]")
  stubbed pg-down
  check "pg-down (no rig running) removes the container (with its volume), pgapp and the socket dir" \
    "$([ $rc = 0 ] && [ "$(count "$STUB_DIR/docker.log" "[rm] [-fv] [$cname]")" -gt "$rms_before" ] && [ ! -e "$STATE_DIR/pgapp" ] && [ ! -e "$STATE_DIR/sock" ] && echo 0 || echo 1)"

  # A start that never becomes ready must leave nothing a later run would trust.
  rms_before=$(count "$STUB_DIR/docker.log" "[rm] [-fv] [$cname]")
  set +e; out=$(STUB_NOT_READY=1 YUZU_NETNS_READY_TIMEOUT=2 PATH="$BIN:$PATH" YUZU_NETNS_STATE="$STATE_DIR" bash "$WRAP" run a -- true 2>&1); rc=$?; set -e
  check "a start that never becomes ready fails, shows the log, removes the container and pgapp" \
    "$([ $rc != 0 ] && [[ $out == *'did not become ready'* ]] && [ ! -e "$STATE_DIR/pgapp" ] && [ "$(count "$STUB_DIR/docker.log" "[rm] [-fv] [$cname]")" -gt "$rms_before" ] && has "$STUB_DIR/docker.log" "[logs] [--tail] [20] [$cname]" && echo 0 || echo 1)"
  stubbed run a -- true
  check "...and the next run starts clean" "$([ $rc = 0 ] && [ -s "$STATE_DIR/pgapp" ] && echo 0 || echo 1)"

  # Docker down is reported as Docker down, not as a missing image.
  set +e; out=$(STUB_NO_DAEMON=1 PATH="$BIN:$PATH" YUZU_NETNS_STATE="$STATE_DIR" bash "$WRAP" run a -- true 2>&1); rc=$?; set -e
  check "an unreachable Docker daemon is named as such" "$([ $rc != 0 ] && [[ $out == *'Docker daemon'* && $out != *'image'* ]] && echo 0 || echo 1)"

  # Two cold starts at once: the lock lets exactly one create the container.
  CS="$TMP/cold"; mkdir -p "$CS"; mkdir -m 700 "$TMP/state2"
  ( STUB_DIR="$CS" STUB_RUN_SLEEP=1 PATH="$BIN:$PATH" YUZU_NETNS_STATE="$TMP/state2" bash "$WRAP" run x -- true >"$CS/x.out" 2>&1; echo $? > "$CS/x.rc" ) &
  p1=$!
  ( STUB_DIR="$CS" STUB_RUN_SLEEP=1 PATH="$BIN:$PATH" YUZU_NETNS_STATE="$TMP/state2" bash "$WRAP" run y -- true >"$CS/y.out" 2>&1; echo $? > "$CS/y.rc" ) &
  p2=$!
  wait "$p1" "$p2" 2>/dev/null || true
  check "two simultaneous cold starts both succeed" "$([ "$(cat "$CS/x.rc" 2>/dev/null)" = 0 ] && [ "$(cat "$CS/y.rc" 2>/dev/null)" = 0 ] && echo 0 || { cat "$CS"/*.out >&2 2>/dev/null; echo 1; })"
  check "...and the container was created exactly once" "$([ "$(count "$CS/docker.log" 'docker [run] [-d]')" = 1 ] && echo 0 || echo 1)"
  cname2=$(grep -o '\[--name\] \[[^]]*\]' "$CS/docker.log" | head -1 | sed 's/.*\[\(.*\)\]/\1/')
  check "a different state dir gets a different container name (cannot remove the other's)" "$([ -n "$cname2" ] && [ "$cname2" != "$cname" ] && echo 0 || echo 1)"

  # The state directory is the only access control on a trust-auth socket.
  mkdir -p "$TMP/loose"; chmod 755 "$TMP/loose"
  set +e; out=$(PATH="$BIN:$PATH" YUZU_NETNS_STATE="$TMP/loose" bash "$WRAP" run c -- true 2>&1); rc=$?; set -e
  check "a state dir that is not mode 700 is refused" "$([ $rc != 0 ] && [[ $out == *'private directory'* ]] && echo 0 || echo 1)"
  mkdir -p "$TMP/real700"; chmod 700 "$TMP/real700"; ln -s "$TMP/real700" "$TMP/link"
  set +e; out=$(PATH="$BIN:$PATH" YUZU_NETNS_STATE="$TMP/link" bash "$WRAP" run c -- true 2>&1); rc=$?; set -e
  check "a state dir that is a symlink is refused" "$([ $rc != 0 ] && [[ $out == *'private directory'* ]] && echo 0 || echo 1)"
  set +e; out=$(PATH="$BIN:$PATH" YUZU_NETNS_STATE="$TMP/loose" bash "$WRAP" pg-down 2>&1); rc=$?; set -e
  check "pg-down applies the same guard (never rm -rf through a loose dir)" "$([ $rc != 0 ] && [[ $out == *'private directory'* ]] && echo 0 || echo 1)"
else
  skip "stubbed-run cases (need flock, openssl and GNU stat — Linux)"
fi

echo "isolation (needs unprivileged user namespaces)"
if command -v bwrap >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
   && bwrap --unshare-net --unshare-pid --dev-bind / / --proc /proc true 2>/dev/null; then
  # A per-run port, so a listener some other job holds on a well-known port cannot
  # make this flake, and the host-side probe is a connect(), not a before/after count.
  PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
  cat > "$TMP/bind.py" <<'PY'
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1)
open(sys.argv[2], "w").write("bound")
time.sleep(60)
PY
  pids=""
  for r in a b; do
    bwrap --dev-bind / / --proc /proc --unshare-net --unshare-pid --die-with-parent \
      python3 "$TMP/bind.py" "$PORT" "$TMP/$r.ok" 2> "$TMP/$r.err" &
    pids="$pids $!"
  done
  JOBS_TO_KILL="$pids"
  for _ in $(seq 1 40); do [ -e "$TMP/a.ok" ] && [ -e "$TMP/b.ok" ] && break; sleep 0.25; done
  check "two namespaces hold the same loopback port at the same time" "$([ -e "$TMP/a.ok" ] && [ -e "$TMP/b.ok" ] && echo 0 || { cat "$TMP"/*.err >&2 2>/dev/null; echo 1; })"
  refused=$(python3 - "$PORT" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); print("reachable")
except OSError:
    print("refused")
PY
)
  check "the host cannot connect to a namespace's listener" "$([ "$refused" = refused ] && echo 0 || echo 1)"
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true; wait 2>/dev/null || true; JOBS_TO_KILL=""
else
  skip "isolation case (bwrap missing or unprivileged user namespaces unavailable)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
