#!/usr/bin/env bash
# ha-leader-epoch-lossy-promotion.sh -- WS-9 failover scenario for #6535 (HA WS-3, ADR-2002 s3).
#
# Demonstrates, in one manual run, that the fenced leader epoch is higher after a
# LOSSY promotion of a streaming standby: a promoted standby that never received
# the latest leader election must not re-mint the epoch a paused former leader
# still holds. It was run once, against the first (timeline-only) form of the mint
# and before the previous-epoch floor was added; re-run it before relying on it. It is
# evidence of one scenario on one rig, not a CI gate, and not
# a proof for every promotion path (ADR-2002 s3 lists what is not covered). It drives a REAL
# yuzu-server (its LeaderElector, the unmodified mint) against the 3-node
# Patroni rig in deploy/docker/docker-compose.ha-postgres.yml under
# YUZU_PG_DURABILITY=async.
#
#   1. a server leads: it mints E1 on timeline T1; both standbys catch up.
#   2. the server is killed and BOTH standbys are cut off the network
#      (`docker network disconnect`, so they cannot receive any further WAL --
#      a `docker pause` would not do: the walsender's output sits in the
#      standby's socket buffer and is read on unpause, so nothing is lost).
#   3. a new server leads on the isolated primary: it mints E2 -- committed on the
#      primary only. (Postgres WAL-logs a sequence 32 values ahead, so a standby
#      normally does NOT repeat a lost value; the script resets the pre-logged
#      count first so this mint is guaranteed to write a sequence WAL record that
#      the isolated standbys lose -- the case where a bare sequence collides.)
#   4. the primary is killed, the standbys are reconnected (same static IPs)
#      and Patroni promotes one: timeline T2 > T1, and the promoted node does
#      NOT have E2 (asserted; otherwise the run is INCONCLUSIVE, never a
#      silent pass -- the loss is the precondition, not the claim).
#   5. a new server leads on the promoted primary and mints E3. The assertions:
#      E3 > E2 (monotonic across the loss) and the equality fence the claim
#      sites use REJECTS E2 (the paused ex-leader) and ADMITS E3.
#
# Without the #6535 timeline-packed epoch the promoted standby re-mints the same
# sequence value, E3 == E2, and the fence admits the ex-leader: that is the
# failure this script exists to catch. The script asserts the sequence value
# DID repeat (low 32 bits of E2 and E3), so a PASS is a discriminating one.
#
# Requires: docker, docker compose, curl, python3, openssl, and a built
# yuzu-server. Container names, IPs and the network are FIXED (not salted) like
# ha-pg-failover-cycles.sh: this is a MANUAL harness (no workflow runs it), it
# runs `docker compose down -v` on that fixed project when it finishes, and it
# REFUSES to start if any yuzu-ha-* container already exists, so it cannot
# destroy another HA rig. No bash 4 features are needed (no associative arrays).
#
# usage: ha-leader-epoch-lossy-promotion.sh [--server-bin PATH]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/docker-compose.ha-postgres.yml"
if [[ "$(uname -s)" == "Darwin" ]]; then BUILD_DIR=build-macos; else BUILD_DIR=build-linux; fi
SERVER_BIN="${REPO_ROOT}/${BUILD_DIR}/server/core/yuzu-server"
NODES=(yuzu-ha-pg1 yuzu-ha-pg2 yuzu-ha-pg3)
NETWORK="yuzu-ha-pg"
LOCK_NAME="server_background_leader" # LeaderElector kServerBackgroundLeaderLock
export BUILDX_BUILDER="${YUZU_HA_BUILDER:-default}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        -h|--help) awk 'NR>1 && /^#/ {print; next} NR>1 {exit}' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -x "$SERVER_BIN" ]] || { echo "no server binary at $SERVER_BIN -- build it, or pass --server-bin" >&2; exit 2; }

APP_USER="${YUZU_DB_USER:-yuzu}"; APP_DB="${YUZU_DB_NAME:-yuzu}"; APP_PASS="${YUZU_DB_PASSWORD:-yuzu-app-dev}"
SUPER="${YUZU_SUPERUSER_NAME:-postgres}"
export YUZU_SUPERUSER_PASSWORD="${YUZU_SUPERUSER_PASSWORD:-yuzu-super-dev}"
export YUZU_PG_REPLICATION_PASSWORD="${YUZU_PG_REPLICATION_PASSWORD:-yuzu-repl-dev}"
export YUZU_DB_PASSWORD="${APP_PASS}"
export YUZU_PG_DURABILITY=async YUZU_PG_SYNC_STRICT=false

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
WEB="$(free_port)"; GRPC="$(free_port)"; MGMT="$(free_port)"; PGPORT="$(free_port)"
RIG="$(mktemp -d -t yuzu_ha_epoch.XXXXXX)"
SERVER_PID=""
FAILS=0
INCONCLUSIVE=0
NODE_IPS=("" "" "") # parallel to NODES (indexed arrays: stock macOS bash 3.2 has no `declare -A`)

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }
inconclusive() { echo "  INCONCLUSIVE  $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }

stop_server() { [[ -n "$SERVER_PID" ]] && { kill -KILL "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""; }; }
reconnect_nodes() { # idempotent: `network connect` on an already-connected node just fails, which we ignore
    local i
    for i in 0 1 2; do
        [[ -n "${NODE_IPS[$i]}" ]] && docker network connect --ip "${NODE_IPS[$i]}" "${NETWORK}" "${NODES[$i]}" >/dev/null 2>&1
    done
    return 0
}
cleanup() {
    stop_server
    reconnect_nodes
    docker compose -f "${COMPOSE_FILE}" -f "${RIG}/port-override.yml" down -v >/dev/null 2>&1 || true
    rm -rf "$RIG"
}
trap cleanup EXIT

CLIENT_IMAGE="yuzu-postgres:local"
appsql() { # <sql> -- through the `postgres` (HAProxy) alias, app credentials: whichever node is primary
    timeout 20 docker run --rm --network "${NETWORK}" \
        -e PGPASSWORD="${APP_PASS}" -e PGCONNECT_TIMEOUT=5 --entrypoint psql \
        "${CLIENT_IMAGE}" -h postgres -U "${APP_USER}" -d "${APP_DB}" -v ON_ERROR_STOP=1 -tAc "$1"
}
supersql() { # <container> <sql> [db] -- superuser over the container's local socket (works while network-isolated)
    timeout 20 docker exec "$1" psql -U "${SUPER}" -d "${3:-postgres}" -v ON_ERROR_STOP=1 -tAc "$2"
}
find_primary() {
    local n code
    for n in "${NODES[@]}"; do
        code="$(timeout 10 docker exec "$n" curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:8008/primary 2>/dev/null || echo 000)"
        [[ "${code}" == "200" ]] && { echo "$n"; return 0; }
    done
    return 1
}
wait_full_health() { # <primary> <standbys-expected>
    local p="$1" want="$2" i s
    for i in $(seq 1 90); do
        s="$(supersql "$p" "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'" 2>/dev/null || echo 0)"
        [[ "${s:-0}" -ge "${want}" ]] && return 0
        sleep 2
    done
    return 1
}
wait_new_primary() { # <old-primary-container> <timeout-s>
    local old="$1" limit="$2" start now new
    start=$(date +%s)
    while :; do
        if new="$(find_primary 2>/dev/null)" && [[ -n "$new" && "$new" != "$old" ]]; then echo "$new"; return 0; fi
        now=$(date +%s); (( now - start >= limit )) && return 1
        sleep 2
    done
}
# The first 8 hex digits of the current WAL file name are the insertion timeline.
timeline_of() { supersql "$1" "SELECT ('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::bigint"; }
leader_epoch() { # <container> -- the stored epoch on that node (hot standby reads work)
    supersql "$1" "SELECT current_leader_epoch FROM leader_elector.leader_state WHERE lock_key = '${LOCK_NAME}'" "${APP_DB}" 2>/dev/null
}
# The equality predicate the claim sites embed (a hand copy of LeaderElector::epoch_fence_sql; keep in sync).
fence_admits() { # <epoch> -- through HAProxy, so it runs on whichever node is primary
    appsql "SELECT COALESCE((SELECT current_leader_epoch FROM leader_elector.leader_state WHERE lock_key = '${LOCK_NAME}') = $1, false)"
}

cat > "${RIG}/port-override.yml" <<EOF
services:
  haproxy:
    ports:
      - "127.0.0.1:${PGPORT}:5432"
EOF
python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/yuzu-server.cfg"
chmod 600 "$RIG/yuzu-server.cfg"

DSN="postgresql://${APP_USER}:${APP_PASS}@127.0.0.1:${PGPORT}/${APP_DB}"
# Sets EPOCH_OUT (and SERVER_PID) -- never call it in a command substitution: the subshell would
# swallow SERVER_PID, stop_server could not kill the server, and it would keep the leader lock.
EPOCH_OUT=""
boot_and_lead() { # <epoch-to-differ-from> -- boots a server and waits until it leads at a new epoch
    "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
        --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
        --postgres-dsn "$DSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
        --ca-dir "$RIG/certs" >> "$RIG/server.log" 2>&1 &
    SERVER_PID=$!
    local before="$1" i e
    for i in $(seq 1 120); do
        e="$(appsql "SELECT current_leader_epoch FROM leader_elector.leader_state WHERE lock_key = '${LOCK_NAME}'" 2>/dev/null || true)"
        if [[ -n "$e" && "$e" != "$before" ]]; then EPOCH_OUT="$e"; return 0; fi
        kill -0 "$SERVER_PID" 2>/dev/null || { echo "server exited early" >&2; tail -20 "$RIG/server.log" >&2; return 1; }
        sleep 1
    done
    echo "server never minted an epoch; tail of its log:" >&2; tail -20 "$RIG/server.log" >&2
    return 1
}

# The container names are fixed; refuse to adopt (and later `down -v`) another HA rig.
if [[ -n "$(docker ps -a --filter 'name=yuzu-ha-' -q 2>/dev/null)" ]]; then
    echo "a yuzu-ha-* container already exists; stop that rig first (this script runs 'docker compose down -v'; to clear leftovers of an aborted run: docker compose -f deploy/docker/docker-compose.ha-postgres.yml down -v)" >&2
    trap - EXIT
    rm -rf "$RIG"
    exit 2
fi
echo "== bring up the 3-node cluster (YUZU_PG_DURABILITY=async)"
docker compose -f "${COMPOSE_FILE}" -f "${RIG}/port-override.yml" up -d --build >/dev/null || { echo "compose up failed" >&2; exit 2; }
PRIMARY=""
for i in $(seq 1 60); do
    if PRIMARY="$(find_primary)" && [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]]; then break; fi
    sleep 2; [[ "$i" -eq 60 ]] && { echo "cluster not write-ready within 120s" >&2; exit 2; }
done
wait_full_health "$PRIMARY" 2 || { echo "standbys never caught up" >&2; exit 2; }
for i in 0 1 2; do
    NODE_IPS[$i]="$(docker inspect -f '{{ (index .NetworkSettings.Networks "'"${NETWORK}"'").IPAddress }}' "${NODES[$i]}")"
done
STANDBYS=(); for c in "${NODES[@]}"; do [[ "$c" != "$PRIMARY" ]] && STANDBYS+=("$c"); done
echo "  primary=$PRIMARY standbys=${STANDBYS[*]}"

echo "== 1: a server leads and mints E1 on timeline T1"
boot_and_lead '' || { fail "first server never led"; exit 1; }
E1="$EPOCH_OUT"
T1="$(timeline_of "$PRIMARY")"
if [[ $(( E1 >> 32 )) -eq "$T1" && "$E1" -gt 4294967295 ]]; then pass "E1=$E1 carries timeline T1=$T1"; else fail "E1=$E1 does not carry timeline $T1 (is this a pre-#6535 build?)"; fi
wait_full_health "$PRIMARY" 2 || { echo "standbys not streaming" >&2; exit 2; }
stop_server

# Postgres WAL-logs a sequence 32 values AHEAD (SEQ_LOG_VALS), so a standby that lost a mint
# usually resumes the sequence from that pre-logged horizon and does NOT repeat the lost value:
# a bare sequence collides only when the lost mint was the one that crossed a 32-value boundary.
# setval() resets the pre-logged count, so the NEXT mint is guaranteed to write (and, under the
# isolation below, lose) a fresh sequence WAL record -- the collision case, made deterministic.
appsql "SELECT setval('leader_elector.leader_epoch_seq', (SELECT last_value FROM leader_elector.leader_epoch_seq), true)" >/dev/null \
    || { echo "cannot reset the sequence's pre-logged count" >&2; exit 2; }
wait_full_health "$PRIMARY" 2 || { echo "standbys not streaming after setval" >&2; exit 2; }

echo "== 2: cut BOTH standbys off the network, then a new server leads (E2 is committed on the primary only)"
for c in "${STANDBYS[@]}"; do docker network disconnect "${NETWORK}" "$c" >/dev/null || { echo "cannot isolate $c" >&2; exit 2; }; done
sleep 3
boot_and_lead "$E1" || { fail "second server never led on the isolated primary"; exit 1; }
E2="$EPOCH_OUT"
stop_server
echo "  E2=$E2"
for c in "${STANDBYS[@]}"; do
    SE="$(leader_epoch "$c")"
    if [[ "$SE" == "$E1" ]]; then pass "standby $c still holds E1 ($SE): the E2 election never reached it"; else inconclusive "standby $c holds '$SE', expected E1=$E1: the isolation did not hold"; fi
done

echo "== 3: kill the primary, reconnect the standbys, wait for Patroni to promote one"
docker kill "$PRIMARY" >/dev/null
reconnect_nodes
NEWP="$(wait_new_primary "$PRIMARY" 180)" || { echo "no standby was promoted within 180s" >&2; docker logs --tail 20 "${STANDBYS[0]}" >&2; exit 2; }
T2="$(timeline_of "$NEWP")"
echo "  promoted=$NEWP timeline T2=$T2"
[[ "$T2" -gt "$T1" ]] && pass "timeline advanced across the promotion (T1=$T1 -> T2=$T2)" || fail "timeline did NOT advance (T1=$T1, T2=$T2): the premise of the fix does not hold on this rig"
LOST="$(leader_epoch "$NEWP")"
if [[ "$LOST" == "$E1" ]]; then pass "the promotion was LOSSY: the promoted node holds E1 ($LOST), not E2 ($E2)"
else inconclusive "the promoted node holds '$LOST' (E1=$E1, E2=$E2): the E2 election was not lost, so this run proves nothing about a lossy promotion"; fi

# HAProxy re-points to the promoted node only after its own health check passes; a server
# started before that fails its boot-time PostgreSQL check. Wait for write-readiness through it.
for i in $(seq 1 60); do
    [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]] && break
    sleep 2; [[ "$i" -eq 60 ]] && { echo "HAProxy never routed to the promoted primary" >&2; exit 2; }
done
echo "== 4: a new server leads on the promoted primary and mints E3"
boot_and_lead "$LOST" || { fail "no server led after the promotion"; exit 1; }
E3="$EPOCH_OUT"
echo "  E3=$E3"
if [[ "$E3" -gt "$E2" ]]; then pass "E3 ($E3) > E2 ($E2): the epoch stayed monotonic across the lossy promotion"; else fail "E3 ($E3) <= E2 ($E2): a re-minted epoch collides with the paused ex-leader's"; fi
if (( (E3 & 0xFFFFFFFF) == (E2 & 0xFFFFFFFF) )); then
    pass "the lossy promotion re-minted the SAME sequence value (low 32 bits equal): a bare sequence would have given E3 == E2; only the timeline separates them"
else
    inconclusive "the sequence did NOT repeat (E2 low bits $((E2 & 0xFFFFFFFF)), E3 low bits $((E3 & 0xFFFFFFFF))): the assertions above hold but this run did not discriminate the fix from a bare sequence"
fi
if [[ "$(fence_admits "$E2")" == "f" ]]; then pass "the epoch fence REJECTS the paused ex-leader's E2"; else fail "the epoch fence ADMITS the paused ex-leader's E2 (split-brain window)"; fi
if [[ "$(fence_admits "$E3")" == "t" ]]; then pass "the epoch fence admits the current leader's E3"; else fail "the epoch fence rejects the current leader's E3"; fi
stop_server

echo
if (( FAILS > 0 )); then echo "RESULT: FAIL ($FAILS failed, $INCONCLUSIVE inconclusive)"; exit 1; fi
if (( INCONCLUSIVE > 0 )); then echo "RESULT: INCONCLUSIVE ($INCONCLUSIVE) -- the loss precondition did not hold; nothing is proven"; exit 3; fi
echo "RESULT: PASS"
