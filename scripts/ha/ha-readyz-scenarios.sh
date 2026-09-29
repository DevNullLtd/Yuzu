#!/usr/bin/env bash
# ha-readyz-scenarios.sh — WS-9 failover scenarios for HA WS-8 (ADR-2002 §12).
#
# Boots a REAL yuzu-server against throwaway Postgres containers and proves the
# /readyz contract a load balancer relies on:
#
#   A. frozen primary   `docker pause` the database (the kernel keeps ACKing, so
#                       no socket timeout fires) -> /readyz 503 within kStaleAfter
#                       (15s) + margin. The probe's own client-side deadlines
#                       normally catch it first (query 2s, then reconnect 5s:
#                       two failures -> pg=unreachable, ~11s); pg=stale is the
#                       backstop if a tick ever wedged. /livez stays 200 (never
#                       restart a replica for a database outage); unpause -> 200.
#   B. refused primary  stop the database container (connection refused) ->
#                       /readyz 503 pg=unreachable within a few seconds; start it
#                       -> 200.
#   D. read-only primary  ALTER SYSTEM default_transaction_read_only=on + reload
#                       (what managed Postgres does on a full disk) -> /readyz 503
#                       pg=read_only; reset -> 200. (Gate 4 UP-4 / chaos CH-1.)
#   C. drain            SIGTERM a server started with --shutdown-drain-seconds 5:
#                       /readyz 503 "draining" at once, while /livez and ordinary
#                       routes keep answering for the whole grace window, then
#                       the process exits.
#   F. drain x frozen primary  pause the database, wait for /readyz to report it,
#                       then SIGTERM with a 10s grace: "draining" at once, /livez
#                       answers inside the grace, and no exit before the grace.
#                       The exit time itself is reported, not asserted: later
#                       teardown joins overrun against a frozen primary with or
#                       without a grace (#3706 class). (Chaos CH-6.)
#   E. frozen FIRST host of a multi-host DSN  two databases behind
#                       `host=h1,h2 target_session_attrs=read-write`; pause h1 ->
#                       /readyz returns to (or stays) 200 via h2 within ~20s (a
#                       reconnect pays h1's connect_timeout, 10s by default), and
#                       a server BOOTED with h1 already frozen still becomes ready.
#                       libpq's non-blocking connect never advances past a silent
#                       first host on its own (Gate 4 UP-1 / chaos CH-2).
#   G. read-only second host  `host=A,B` with NO target_session_attrs, B read-only:
#                       stop A (red), start A -> /readyz 200 again, not pinned to B
#                       (Gate 8 round 2 UH-R2-1).
#   H. multi-host DSN without target_session_attrs: the server adds read-write
#                       and logs it (Gate 8 round 4 guard, pg/multi_host_dsn.hpp).
#   I. multi-host DSN with target_session_attrs=any: the server refuses to boot,
#                       naming the value, never the password.
#   J. load_balance_hosts=random (even with read-write): the server refuses to
#                       boot (Gate 8 round 6 operator decision), never naming the password.
#   K. the same setting from a pg_service.conf entry (service=): the DSN-only
#                       guard cannot see it, so the server checks what libpq resolved
#                       on its first connection and refuses to boot (Gate 8 round 7).
#   L. CPU-starved primary (#4944)  `docker update --cpus 0.01` on the database
#      under a pgbench select load: the probe query misses its 2 s deadline, so
#      /readyz goes red (sustained overload IS an outage from the operator's
#      seat — the same database cannot answer real requests either); restoring
#      the CPU brings it back within one probe. There is no server-side
#      hysteresis by decision: the LB's healthy/unhealthy thresholds are the
#      damping (docs/user-manual/server-admin.md, "Load balancers ...").
#   M. brief stall (#4944)  a 3 s `docker pause`/unpause never turns /readyz
#      red: one failed probe is a blip, two are needed.
#   N. max_connections exhaustion (#4943)  a third database with
#      max_connections=20 reserved_connections=8, the server on a NON-superuser
#      app role granted pg_use_reserved_connections, foreign sessions holding
#      every unreserved slot: killing the probe's backend makes it reconnect
#      into the reserve and /readyz stays 200; REVOKE the grant and the same
#      kill leaves the probe refused (53300) — /readyz 503 unreachable, the
#      failure the shipped default prevents.
#
# Before WS-8, scenario A stayed green indefinitely and C closed the listener
# immediately (see pg_reachability_probe.hpp / shutdown_drain_rules.hpp).
#
# Requires: docker, curl, python3, openssl and a built yuzu-server. Exits 0 only
# when every scenario passes. Ports and container names are salted per run —
# the self-hosted CI runners share one OS identity (#1871). Manual today, like
# the other scripts/ha/ harnesses (no workflow runs it).
#
# Passwords generated here (PG_PASS, APP_PASS) are for THROWAWAY, localhost-only
# containers this script creates and destroys, and this is a LOCAL harness, not
# a shipped artifact. Scenarios that grep the server log for a password's
# ABSENCE (e.g. N) prove only that the SERVER never logs it — every DSN/password
# is still visible in this process's own argv (`docker run`/`docker exec`/the
# server invocation itself), same as every earlier scenario's `$PG_PASS`-bearing
# DSN. Do not read a clean server-log grep as a complete secrecy proof
# (security-guardian, Gate 2 finding #6).
#
# usage: ha-readyz-scenarios.sh [--server-bin PATH]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"
if [[ "$(uname -s)" == "Darwin" ]]; then BUILD_DIR=build-macos; else BUILD_DIR=build-linux; fi
SERVER_BIN="${YUZU_ROOT}/${BUILD_DIR}/server/core/yuzu-server"
PG_IMAGE="${YUZU_HA_READYZ_PG_IMAGE:-postgres:18.4-bookworm@sha256:efef99e1558f86089bc84bece29208c0777a185ff717ec7fa288a652ce2d0adf}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        -h|--help)    sed -n '2,64p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -x "$SERVER_BIN" ]] || { echo "no server binary at $SERVER_BIN — build it, or pass --server-bin" >&2; exit 2; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
WEB="$(free_port)"; GRPC="$(free_port)"; MGMT="$(free_port)"
PGPORT="$(free_port)"; PG2PORT="$(free_port)"; PG3PORT="$(free_port)"

RIG="$(mktemp -d -t yuzu_ha_readyz.XXXXXX)"
SALT="$$-$RANDOM"
PG="yuzu-ha-readyz-pg-$SALT"
PG2="yuzu-ha-readyz-pg2-$SALT"
PG3="yuzu-ha-readyz-pg3-$SALT"
SERVER_PID=""
FAILS=0
PG_PASS="$(openssl rand -hex 24)"

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill -KILL "$SERVER_PID" 2>/dev/null
    for c in "$PG" "$PG2" "$PG3"; do
        docker unpause "$c" >/dev/null 2>&1
        docker rm -f "$c" >/dev/null 2>&1
    done
    rm -rf "$RIG"
}
trap cleanup EXIT

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }

code()  { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${WEB}$1"; }
body()  { curl -s --max-time 3 "http://127.0.0.1:${WEB}$1"; }
pg_reason() { body /readyz | grep -o '"pg":"[a-z_]*"'; }

# wait_for <path> <http-code> <timeout-s> [body-substring] — echoes seconds taken.
wait_for() {
    local path="$1" want="$2" limit="$3" needle="${4:-}" start now
    start=$(date +%s)
    while :; do
        if [[ "$(code "$path")" == "$want" ]] && { [[ -z "$needle" ]] || body "$path" | grep -q -- "$needle"; }; then
            now=$(date +%s); echo $((now - start)); return 0
        fi
        now=$(date +%s)
        (( now - start >= limit )) && { echo $((now - start)); return 1; }
        sleep 0.5
    done
}

start_pg() { # <name> <host-port> [extra postgres -c flags...]
    local name="$1" port="$2"; shift 2
    docker run -d --name "$name" -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=yuzu \
        -p "127.0.0.1:$port:5432" "$PG_IMAGE" -c fsync=off "$@" >/dev/null || return 1
    pg_up "$name"
}
pg_up() { # <name>
    for _ in $(seq 1 60); do
        docker exec "$1" pg_isready -h 127.0.0.1 -U yuzu -d yuzu >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
psql_in() { # <container> <sql> — as the superuser, immune to default_transaction_read_only
    docker exec -e PGOPTIONS='-c default_transaction_read_only=off' "$1" \
        psql -q -U yuzu -d yuzu -c "$2" >/dev/null
}

python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/yuzu-server.cfg"
chmod 600 "$RIG/yuzu-server.cfg"

boot() { # <dsn> [extra server flags...]
    local dsn="$1"; shift
    "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
        --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
        --postgres-dsn "$dsn" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
        --ca-dir "$RIG/certs" "$@" >> "$RIG/server.log" 2>&1 &
    SERVER_PID=$!
    if ! wait_for /readyz 200 120 >/dev/null; then
        echo "server never became ready; /readyz says: $(body /readyz)" >&2
        tail -20 "$RIG/server.log" >&2
        return 1
    fi
}
# wait_exit <limit-s> <start-epoch> — wait for the server to exit WITHOUT sending
# anything (a SECOND SIGTERM is the documented hard exit, which would fake a fast
# graceful stop). Sets ELAPSED (seconds since <start-epoch>) and clears SERVER_PID
# on exit. Call it directly, never as $(wait_exit ...): a command-substitution
# subshell would clear SERVER_PID only in the subshell.
ELAPSED=0
wait_exit() {
    local limit="$1" start="$2" now
    while kill -0 "$SERVER_PID" 2>/dev/null; do
        now=$(date +%s)
        ELAPSED=$((now - start))
        (( ELAPSED >= limit )) && return 1
        sleep 0.5
    done
    wait "$SERVER_PID" 2>/dev/null
    SERVER_PID=""
    ELAPSED=$(( $(date +%s) - start ))
}
stop_server() { # ONE graceful SIGTERM, then wait up to <limit>s (sets ELAPSED)
    local limit="${1:-60}" start
    start=$(date +%s)
    kill -TERM "$SERVER_PID" 2>/dev/null
    wait_exit "$limit" "$start"
}

start_pg "$PG" "$PGPORT" || { echo "postgres did not start" >&2; exit 2; }
DSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT}/yuzu"

echo "== boot"
boot "$DSN" || exit 1
pass "server ready (web :$WEB, pg :$PGPORT)"

echo "== A: frozen primary (docker pause)"
docker pause "$PG" >/dev/null
if t=$(wait_for /readyz 503 20 '"pg":"'); then pass "/readyz 503 $(pg_reason) after ${t}s (bound: kStaleAfter 15s + margin)"
else fail "/readyz not 503 within 20s: $(body /readyz)"; fi
[[ "$(code /livez)" == 200 ]] && pass "/livez still 200 while the database is frozen" || fail "/livez not 200 during the outage"
docker unpause "$PG" >/dev/null
if t=$(wait_for /readyz 200 20); then pass "/readyz 200 again ${t}s after unpause"
else fail "/readyz did not recover within 20s: $(body /readyz)"; fi

echo "== B: refused primary (container stopped)"
docker stop -t 5 "$PG" >/dev/null
if t=$(wait_for /readyz 503 20 '"pg":"'); then pass "/readyz 503 $(pg_reason) after ${t}s"
else fail "/readyz not 503 within 20s: $(body /readyz)"; fi
docker start "$PG" >/dev/null && pg_up "$PG"
if t=$(wait_for /readyz 200 30); then pass "/readyz 200 again ${t}s after restart"
else fail "/readyz did not recover within 30s: $(body /readyz)"; fi

echo "== D: read-only primary (default_transaction_read_only)"
psql_in "$PG" "ALTER SYSTEM SET default_transaction_read_only = on" && psql_in "$PG" "SELECT pg_reload_conf()"
if t=$(wait_for /readyz 503 15 '"pg":"read_only"'); then pass "/readyz 503 pg=read_only ${t}s after the primary turned read-only"
else fail "/readyz not 503 read_only within 15s: $(body /readyz)"; fi
psql_in "$PG" "ALTER SYSTEM RESET default_transaction_read_only" && psql_in "$PG" "SELECT pg_reload_conf()"
if t=$(wait_for /readyz 200 15); then pass "/readyz 200 again ${t}s after the reset"
else fail "/readyz did not recover within 15s: $(body /readyz)"; fi

echo "== C: drain (--shutdown-drain-seconds 5)"
stop_server 120
boot "$DSN" --shutdown-drain-seconds 5 || exit 1
sig_at=$(date +%s)
kill -TERM "$SERVER_PID"
if t=$(wait_for /readyz 503 3 '"draining"'); then pass "/readyz 503 draining ${t}s after SIGTERM"
else fail "/readyz not draining after SIGTERM: $(body /readyz)"; fi
sleep 2
[[ "$(code /livez)" == 200 ]] && pass "/livez 200 inside the grace window" || fail "/livez not served inside the grace window"
[[ "$(code /health)" == 200 ]] && pass "/health (an ordinary route) served inside the grace window" || fail "/health not served inside the grace window"
if wait_exit 60 "$sig_at"; then
    if (( ELAPSED >= 5 )); then pass "server exited ${ELAPSED}s after SIGTERM (grace 5s honoured)"
    else fail "server exited ${ELAPSED}s after SIGTERM — before the 5s grace"; fi
else fail "server still running 60s after SIGTERM"; fi

echo "== F: drain x frozen primary (--shutdown-drain-seconds 10)"
boot "$DSN" --shutdown-drain-seconds 10 || exit 1
docker pause "$PG" >/dev/null
wait_for /readyz 503 20 '"pg":"' >/dev/null || fail "probe did not notice the frozen primary before SIGTERM"
sig_at=$(date +%s)
kill -TERM "$SERVER_PID"
if t=$(wait_for /readyz 503 3 '"draining"'); then pass "/readyz 503 draining ${t}s after SIGTERM (draining wins over pg=)"
else fail "/readyz not draining after SIGTERM: $(body /readyz)"; fi
sleep 2
lt=$(curl -s -o /dev/null -w '%{time_total}' --max-time 5 "http://127.0.0.1:${WEB}/livez")
if python3 -c "import sys; sys.exit(0 if float('$lt') < 1.0 else 1)"; then pass "/livez answered in ${lt}s inside the grace, database frozen"
else fail "/livez took ${lt}s inside the grace"; fi
# The EXIT time against a frozen primary is not this change's to fix: the
# background-thread joins later in stop() (schedule runner, leader election,
# policy evaluation) block in their own Postgres calls and overrun 210s with or
# without a drain grace — measured identically at --shutdown-drain-seconds 0.
# Tracked as #3706's class. So F asserts only that the grace is honoured (no
# exit before it), reports the exit time, and unpauses to let the process go.
if wait_exit 30 "$sig_at"; then
    if (( ELAPSED >= 10 )); then pass "server exited ${ELAPSED}s after SIGTERM with the database frozen (grace 10s)"
    else fail "server exited ${ELAPSED}s after SIGTERM — before the 10s grace"; fi
else
    echo "  NOTE  server still in teardown ${ELAPSED}s after SIGTERM with the database frozen —"
    echo "        pre-existing join overrun (#3706 class), not the drain grace; unpausing"
fi
docker unpause "$PG" >/dev/null
if [[ -n "$SERVER_PID" ]]; then
    if wait_exit 240 "$sig_at"; then pass "server exited ${ELAPSED}s after SIGTERM once the database thawed"
    else fail "server still running ${ELAPSED}s after SIGTERM even after the database thawed"; fi
fi

echo "== E: frozen first host of a multi-host DSN"
start_pg "$PG2" "$PG2PORT" || { echo "second postgres did not start" >&2; exit 2; }
MDSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT},127.0.0.1:${PG2PORT}/yuzu?target_session_attrs=read-write"
boot "$MDSN" || exit 1
pass "server ready on the multi-host DSN"
docker pause "$PG" >/dev/null
red=0; max_red=0
for _ in $(seq 1 40); do # 20s at 0.5s
    if [[ "$(code /readyz)" == 200 ]]; then red=0; else red=$((red + 1)); (( red > max_red )) && max_red=$red; fi
    sleep 0.5
done
if [[ "$(code /readyz)" == 200 ]] && (( max_red <= 20 )); then
    pass "/readyz 200 via the second host 20s after freezing the first (longest red run $((max_red / 2))s)"
else fail "/readyz not back to 200 via the second host: $(body /readyz) (longest red run $((max_red / 2))s)"; fi
stop_server 210
bstart=$(date +%s)
if boot "$MDSN"; then pass "a server booted with the first host frozen became ready in $(( $(date +%s) - bstart ))s"
else fail "a server booted with the first host frozen never became ready"; fi
stop_server 210
docker unpause "$PG" >/dev/null

echo "== G: multi-host DSN without target_session_attrs, a read-only second host, a primary blip"
# Regression for round-2 governance UH-R2-1: a probe that reconnected from the
# host that last CONNECTED stayed pinned to read-only B after the primary A came
# back. The probe now lets libpq walk the host list, as the pool does; with the
# multi-host guard the DSN also carries target_session_attrs=read-write, so libpq
# refuses B outright. Host A = the writable primary, host B = read-only and up.
psql_in "$PG2" "ALTER SYSTEM SET default_transaction_read_only = on" && psql_in "$PG2" "SELECT pg_reload_conf()"
GDSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT},127.0.0.1:${PG2PORT}/yuzu"
boot "$GDSN" || exit 1
pass "server ready on host A with a read-only host B listed second"
docker stop -t 2 "$PG" >/dev/null
if t=$(wait_for /readyz 503 20 '"pg":"'); then pass "/readyz 503 $(pg_reason) ${t}s after the primary stopped"
else fail "/readyz not 503 within 20s of the primary stopping: $(body /readyz)"; fi
docker start "$PG" >/dev/null && pg_up "$PG"
if t=$(wait_for /readyz 200 30); then pass "/readyz 200 again ${t}s after the primary came back (not pinned to read-only B)"
else fail "/readyz still not ready 30s after the primary came back: $(body /readyz)"; fi
stop_server 210
psql_in "$PG2" "ALTER SYSTEM RESET default_transaction_read_only" && psql_in "$PG2" "SELECT pg_reload_conf()"

echo "== H: multi-host DSN without target_session_attrs -> the server uses read-write"
# Gate 8 round 4: without target_session_attrs libpq, and so the pool, takes the first
# host that ACCEPTS a connection, standby included, and no single probe connection can
# see every pool connection. The server therefore appends target_session_attrs=read-write
# to a multi-host DSN that lacks it (pg/multi_host_dsn.hpp) and says so in its log.
: > "$RIG/server.log"
boot "$GDSN" || exit 1
if grep -q 'using target_session_attrs=read-write' "$RIG/server.log"; then
    pass "the server logged that it added target_session_attrs=read-write"
else fail "no target_session_attrs=read-write notice in the server log"; fi
stop_server 210

echo "== I: multi-host DSN with a weaker target_session_attrs -> refused at boot"
IDSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT},127.0.0.1:${PG2PORT}/yuzu?target_session_attrs=any"
: > "$RIG/server.log"
"$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
    --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
    --postgres-dsn "$IDSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
    --ca-dir "$RIG/certs" >> "$RIG/server.log" 2>&1 &
SERVER_PID=$!
if wait_exit 20 "$(date +%s)"; then
    if grep -q "Invalid --postgres-dsn: .*'any'" "$RIG/server.log" && ! grep -q "$PG_PASS" "$RIG/server.log"; then
        pass "refused to start ${ELAPSED}s in, naming the value and not the password"
    else fail "exited, but without the expected refusal message (or with the password in it)"; fi
else fail "server did not refuse a multi-host DSN with target_session_attrs=any"; kill -KILL "$SERVER_PID" 2>/dev/null; SERVER_PID=""; fi

echo "== J: load_balance_hosts=random -> refused at boot"
JDSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT},127.0.0.1:${PG2PORT}/yuzu?target_session_attrs=read-write&load_balance_hosts=random"
: > "$RIG/server.log"
"$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
    --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
    --postgres-dsn "$JDSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
    --ca-dir "$RIG/certs" >> "$RIG/server.log" 2>&1 &
SERVER_PID=$!
if wait_exit 20 "$(date +%s)"; then
    if grep -q "Invalid --postgres-dsn: load_balance_hosts=random" "$RIG/server.log" && ! grep -q "$PG_PASS" "$RIG/server.log"; then
        pass "refused to start ${ELAPSED}s in, naming load_balance_hosts and not the password"
    else fail "exited, but without the expected refusal message (or with the password in it)"; fi
else fail "server did not refuse load_balance_hosts=random"; kill -KILL "$SERVER_PID" 2>/dev/null; SERVER_PID=""; fi

echo "== K: load_balance_hosts=random from a service file -> refused at boot"
cat > "$RIG/pg_service.conf" <<SVC
[yzsvc]
host=127.0.0.1,127.0.0.1
port=${PGPORT},${PG2PORT}
target_session_attrs=read-write
load_balance_hosts=random
SVC
KDSN="service=yzsvc user=yuzu password=${PG_PASS} dbname=yuzu"
: > "$RIG/server.log"
PGSERVICEFILE="$RIG/pg_service.conf" "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
    --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
    --postgres-dsn "$KDSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
    --ca-dir "$RIG/certs" >> "$RIG/server.log" 2>&1 &
SERVER_PID=$!
if wait_exit 30 "$(date +%s)"; then
    if grep -q "Invalid Postgres connection settings: load_balance_hosts=random" "$RIG/server.log" && ! grep -q "$PG_PASS" "$RIG/server.log"; then
        pass "refused to start ${ELAPSED}s in on the service file's load_balance_hosts, password not logged"
    else fail "exited, but without the expected refusal message (or with the password in it)"; fi
else fail "server did not refuse load_balance_hosts from a service file"; kill -KILL "$SERVER_PID" 2>/dev/null; SERVER_PID=""; fi

echo "== L: CPU-starved primary under load (#4944) -> red while starved, back within a probe"
boot "$DSN" || exit 1
docker exec "$PG" pgbench -q -i -s 5 -U yuzu -d yuzu >/dev/null 2>&1 || fail "pgbench -i failed"
docker exec -d "$PG" pgbench -S -c 64 -j 8 -T 150 -U yuzu -d yuzu >/dev/null 2>&1
sleep 1   # let load ramp up before starving it (empirically calibrated: 0.01 cpu + 64 clients
          # reliably reds /readyz around t=12s; 0.02 cpu + 32 clients, tried first, did not
          # reliably starve the probe's own trivial no-table query even over 60s)
docker update --cpus 0.01 "$PG" >/dev/null
if t=$(wait_for /readyz 503 40 '"pg":"'); then pass "/readyz 503 $(pg_reason) ${t}s after the database was starved to 1% of a CPU under a 64-client load"
else fail "/readyz stayed 200 for 40s on a CPU-starved, loaded database: $(body /readyz)"; fi
docker update --cpus "$(nproc)" "$PG" >/dev/null   # --cpus 0 does NOT clear a limit; the host's full count does
if t=$(wait_for /readyz 200 20); then pass "/readyz 200 again ${t}s after the CPU limit was lifted (one successful probe recovers; no server-side hysteresis)"
else fail "/readyz did not recover within 20s of lifting the CPU limit: $(body /readyz)"; fi
docker exec "$PG" bash -c 'kill $(pidof pgbench)' >/dev/null 2>&1 || true

echo "== M: 3s stall (#4944) -> never red (one failed probe is a blip)"
docker pause "$PG" >/dev/null
red=0
for _ in $(seq 1 6); do [[ "$(code /readyz)" == 503 ]] && red=1; sleep 0.5; done
docker unpause "$PG" >/dev/null
for _ in $(seq 1 10); do [[ "$(code /readyz)" == 503 ]] && red=1; sleep 0.5; done
if (( red == 0 )); then pass "/readyz stayed 200 through a 3s stall and its recovery"
else fail "/readyz went 503 on a 3s stall: $(body /readyz)"; fi
stop_server 120

echo "== N: max_connections exhaustion (#4943) -> reserved slots keep the probe (and the pool) connecting"
# A third database, small enough to fill by hand: 20 slots, 3 superuser-only,
# 8 reserved for pg_use_reserved_connections members -> 9 for everyone else. The
# server's own footprint is pinned to --postgres-pool-size 2 (+1 leader +1
# probe = 4), all privileged (granted below), so exactly 9-4=5 ordinary slots
# remain for foreign_client to fill before being refused.
start_pg "$PG3" "$PG3PORT" -c max_connections=20 -c reserved_connections=8 -c superuser_reserved_connections=3 \
    || { echo "third postgres did not start" >&2; exit 2; }
APP_PASS="$(openssl rand -hex 16)"
psql_in "$PG3" "CREATE ROLE app LOGIN PASSWORD '${APP_PASS}'"
psql_in "$PG3" "GRANT pg_use_reserved_connections TO app"
psql_in "$PG3" "CREATE DATABASE appdb OWNER app"
psql_in "$PG3" "CREATE ROLE foreign_client LOGIN PASSWORD 'x'"
NDSN="postgresql://app:${APP_PASS}@127.0.0.1:${PG3PORT}/appdb"
boot "$NDSN" --postgres-pool-size 2 || exit 1
# Foreign clients take every unreserved slot: open sessions until one is refused.
# The refusal is asserted on THIS SAME attempt's own output, not a later, separate
# connection — the app role's own pool can shrink an idle connection between two
# checks, transiently freeing an ordinary slot, so a second, later probe connection
# can go through even though the loop's own attempt was genuinely refused.
foreign_burst() { docker exec -d "$PG3" psql -U foreign_client -d postgres -c "SELECT pg_sleep(300)" 2>/dev/null || true; }
held=0
refusal=""
for _ in $(seq 1 20); do
    foreign_burst
    sleep 0.3
    out=$(docker exec "$PG3" psql -U foreign_client -d postgres -tAc "SELECT 1" 2>&1)
    if [[ "$out" != "1" ]]; then refusal="$out"; break; fi
done
held=$(docker exec "$PG3" psql -U yuzu -d postgres -tAc "SELECT count(*) FROM pg_stat_activity WHERE usename='foreign_client'")
if [[ -n "$refusal" ]] && grep -q "remaining connection slots are reserved" <<<"$refusal"; then
    pass "foreign clients hold ${held} sessions; a further foreign connect is refused (slots reserved)"
else fail "could not fill the unreserved slots (foreign sessions: ${held}; last attempt: ${refusal:-succeeded, no refusal in 20 tries})"; fi
# Kill the probe's backend, and have a foreign client burst for the freed slot at
# once (the realistic shape: foreign demand is continuous, the probe ticks every
# 2 s). The probe must still reconnect — into the reserve — and /readyz stay 200.
kill_probe() { docker exec "$PG3" psql -U yuzu -d postgres -tAc "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name='yuzu-readyz-probe'"; }
[[ "$(kill_probe)" == 1 ]] || fail "did not find exactly one probe backend to terminate"
foreign_burst
red=0
for _ in $(seq 1 16); do [[ "$(code /readyz)" == 503 ]] && red=1; sleep 0.5; done
if (( red == 0 )) && [[ "$(docker exec "$PG3" psql -U yuzu -d postgres -tAc "SELECT count(*) FROM pg_stat_activity WHERE application_name='yuzu-readyz-probe'")" == 1 ]]; then
    pass "/readyz stayed 200: the probe reconnected into the reserved slots with every unreserved slot held"
else fail "/readyz went 503 (or the probe never reconnected) with reserved slots available: $(body /readyz)"; fi
# Negative control: without the grant the app role is an ordinary client and the
# same kill leaves the probe refused — the #4943 failure shape.
psql_in "$PG3" "REVOKE pg_use_reserved_connections FROM app"
[[ "$(kill_probe)" == 1 ]] || fail "did not find exactly one probe backend to terminate (control)"
foreign_burst
if t=$(wait_for /readyz 503 20 '"pg":"unreachable"'); then pass "/readyz 503 pg=unreachable ${t}s after the same kill WITHOUT the grant (probe refused at max_connections; log shows 53300)"
else fail "/readyz did not go 503 without the grant: $(body /readyz)"; fi
grep -q "remaining connection slots are reserved" "$RIG/server.log" && pass "server log names the refusal (slots reserved), not the password" || fail "server log lacks the slots-reserved refusal"
grep -q "$APP_PASS" "$RIG/server.log" && fail "server log contains the app password" || true
psql_in "$PG3" "GRANT pg_use_reserved_connections TO app"
if t=$(wait_for /readyz 200 20); then pass "/readyz 200 again ${t}s after re-granting (probe admitted into the reserve)"
else fail "/readyz did not recover after re-grant: $(body /readyz)"; fi
stop_server 120

echo
if (( FAILS == 0 )); then echo "ha-readyz-scenarios: ALL PASS"; exit 0; fi
echo "ha-readyz-scenarios: $FAILS FAILURE(S) — server log tail:"; tail -30 "$RIG/server.log"
exit 1
