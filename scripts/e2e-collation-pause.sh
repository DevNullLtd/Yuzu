#!/usr/bin/env bash
# e2e-collation-pause.sh - the production yuzu-server binary, a real PostgreSQL, and the whole
# chain behind the device-CI collation gate (#7730): boot check -> gate -> write pause and read
# refusal -> the documented repair -> automatic resume.
#
#   1. boot against a healthy database: GET /api/v1/hardware-ci answers 200 with the stored rows,
#      GET /api/v1/hardware/<id> shows the CI block, the mismatch gauge reads 0 and no write has
#      been deferred;
#   2. stop, force a collation version mismatch (the one faked step), boot again: the boot check
#      sets the gate. The bulk read answers 503 (retry_after_ms 60000, Retry-After 60), the per-id
#      CI block degrades and the gauge reads 1;
#   3. WRITE PAUSE: a decommission (DELETE /api/v1/sle/agents/{id}, the one device_ci write that
#      can be driven over HTTP without an agent) is refused with 500 and details.write_paused, the
#      device_ci row is byte-unchanged and yuzu_device_ci_writes_deferred_total{op="delete"} grew;
#   4. with the server still running, run the documented repair (REINDEX DATABASE CONCURRENTLY,
#      ALTER DATABASE ... REFRESH COLLATION VERSION): within the 60 s unsettled recheck interval
#      the bulk read answers 200 again, the gauge reads 0 and the same decommission now succeeds,
#      with no restart.
#
# It covers what the unit tests cannot: that ServerImpl passes the one gate to the boot report, the
# recheck loop, the store and the read closures, that the recheck uses the 60 s cadence in a real
# process, and that the pause and the refusal reach a real HTTP client and a real table.
#
# What is NOT driven for real: the agent ingest path (ReportInventory over gRPC) needs an agent or
# a gRPC client, and neither is part of this rig; the device_ci rows are seeded with SQL INSERTs
# and the write exercised is the decommission cascade's device_ci delete. The ingest pause itself
# is covered by the hermetic [collation_gate] unit tests.
#
# Needs a PostgreSQL superuser (to force the mismatch and to create its own throwaway database) and
# takes about two minutes. Required environment:
#   YUZU_E2E_PG_DSN   libpq keyword/value DSN of a superuser on the cluster, WITHOUT dbname
#                     (e.g. "host=127.0.0.1 port=5432 user=postgres password=..."). Falls back
#                     to YUZU_TEST_POSTGRES_DSN, whose own dbname (if any) is removed.
# Optional environment:
#   YUZU_SERVER_BIN   path to yuzu-server (default: build-linux/server/core/yuzu-server)
#   YUZU_E2E_PSQL     command that runs psql against that cluster as the superuser, accepting extra
#                     psql arguments (default: psql with YUZU_E2E_PG_DSN). Use it when psql is not
#                     installed on the host, e.g. YUZU_E2E_PSQL="docker exec -i <container> psql -U postgres".
#                     The script appends -d <database> itself.
#
# Never point it at a shared or production cluster: it creates and drops a database named
# yuzu_e2e_coll_<pid> and forces a (harmless but alarming) mismatch on it. Start a throwaway one:
#   docker run -d --name yuzu_e2e_coll_pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:<port>:5432 postgres:18.4-bookworm
set -euo pipefail

: "${YUZU_E2E_PG_DSN:=${YUZU_TEST_POSTGRES_DSN:-}}"
: "${YUZU_E2E_PG_DSN:?set YUZU_E2E_PG_DSN (or YUZU_TEST_POSTGRES_DSN) to a superuser DSN on a throwaway cluster}"
# The script picks the database itself: drop any dbname the caller's DSN carries.
YUZU_E2E_PG_DSN="$(sed -E 's/(^| )dbname=[^ ]+//g' <<< "$YUZU_E2E_PG_DSN")"
BIN="${YUZU_SERVER_BIN:-build-linux/server/core/yuzu-server}"
[ -x "$BIN" ] || { echo "FAIL: $BIN is not executable" >&2; exit 1; }
for tool in curl jq python3; do
    command -v "$tool" >/dev/null || { echo "FAIL: $tool is required" >&2; exit 1; }
done

DB="yuzu_e2e_coll_$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_e2e_coll.XXXXXX")"
SERVER_PID=""
PASS=0
FAILS=0

# psql_on <database> <psql args...>: the superuser on the named database of the throwaway cluster.
psql_on() {
    local db="$1"
    shift
    if [ -n "${YUZU_E2E_PSQL:-}" ]; then
        # shellcheck disable=SC2086 # the wrapper command is deliberately word-split
        $YUZU_E2E_PSQL -X -q -v ON_ERROR_STOP=1 -d "$db" "$@"
    else
        psql "$YUZU_E2E_PG_DSN dbname=$db" -X -q -v ON_ERROR_STOP=1 "$@"
    fi
}
psql_admin() { psql_on postgres "$@"; }
psql_db() { psql_on "$DB" "$@"; }

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { PASS=$((PASS + 1)); echo "  ok   $*"; }
fail() { FAILS=$((FAILS + 1)); echo "  FAIL $*" >&2; }

stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=""
}
cleanup() {
    stop_server
    psql_admin -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" >/dev/null 2>&1 || true
    if [ "$FAILS" -ne 0 ]; then
        echo "kept $WORK (server logs) for inspection" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# One allocation call: the sockets are all held until the list is printed, so no two are equal.
read -r WEB_PORT GRPC_PORT MGMT_PORT < <(python3 -c '
import socket
s = [socket.socket() for _ in range(3)]
for x in s:
    x.bind(("127.0.0.1", 0))
print(*[x.getsockname()[1] for x in s])
')
BASE="http://127.0.0.1:$WEB_PORT"
# A per-run random admin password, handed to python through the environment rather than argv.
ADMIN_PASS="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

mkdir -p "$WORK/data" "$WORK/ca"
YUZU_E2E_ADMIN_PASS="$ADMIN_PASS" python3 -c '
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha256", os.environ["YUZU_E2E_ADMIN_PASS"].encode(), salt, 100000, dklen=32)
print(f"admin:admin:{salt.hex()}:{dk.hex()}")
' > "$WORK/yuzu-server.cfg"
chmod 600 "$WORK/yuzu-server.cfg"

# The server's own DSN: the superuser DSN pointed at the throwaway database.
SERVER_DSN="$YUZU_E2E_PG_DSN dbname=$DB"
BOOT_N=0

start_server() {
    BOOT_N=$((BOOT_N + 1))
    SERVER_LOG="$WORK/server.boot$BOOT_N.log"
    "$BIN" \
        --no-tls --no-https \
        --web-address 127.0.0.1 --web-port "$WEB_PORT" \
        --listen "127.0.0.1:$GRPC_PORT" --management "127.0.0.1:$MGMT_PORT" \
        --config "$WORK/yuzu-server.cfg" --data-dir "$WORK/data" --ca-dir "$WORK/ca" \
        --postgres-dsn "$SERVER_DSN" \
        --metrics-no-auth --log-level info \
        > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    # A cold start walks every migration and routinely takes 12+ s.
    for _ in $(seq 1 240); do
        if curl -sf -m 5 -o /dev/null "$BASE/livez" 2>/dev/null; then
            log "  boot $BOOT_N: server ready (pid $SERVER_PID)"
            return 0
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || { echo "FAIL: server exited early; tail of $SERVER_LOG:" >&2; tail -30 "$SERVER_LOG" >&2; exit 1; }
        sleep 0.5
    done
    echo "FAIL: server not live within 120 s; tail of $SERVER_LOG:" >&2
    tail -30 "$SERVER_LOG" >&2
    exit 1
}

# Mint an API token from a cookie session (the password goes in on stdin, never on argv).
TOKEN=""
mint_token() {
    local jar="$WORK/cookies.$BOOT_N.txt" code
    code="$(printf '%s' "$ADMIN_PASS" | curl -s -m 10 -o /dev/null -w '%{http_code}' -c "$jar" -H "Origin: $BASE" \
        "$BASE/login" --data-urlencode "username=admin" --data-urlencode "password@-" || echo 000)"
    [ "$code" = "200" ] || { echo "FAIL: admin login returned $code" >&2; exit 1; }
    TOKEN="$(curl -s -m 10 -b "$jar" -H "Origin: $BASE" -H 'Content-Type: application/json' \
        -X POST "$BASE/api/v1/tokens" -d '{"name":"e2e-collation-pause"}' | jq -r '.token // .data.token // empty')"
    [ -n "$TOKEN" ] || { echo "FAIL: could not mint an API token" >&2; tail -20 "$SERVER_LOG" >&2; exit 1; }
}

# http <METHOD> <path>: sets HTTP_STATUS, HTTP_BODY and HTTP_HDRS for an authenticated request.
HTTP_STATUS=""; HTTP_BODY=""; HTTP_HDRS=""
http() {
    local out
    out="$(curl -s -m 30 -D "$WORK/hdrs.txt" -o "$WORK/body.txt" -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" -X "$1" "$BASE$2" || echo 000)"
    HTTP_STATUS="$out"
    HTTP_BODY="$(cat "$WORK/body.txt")"
    HTTP_HDRS="$(tr -d '\r' < "$WORK/hdrs.txt")"
}

# metric_sum <name>: the sum over every series of that name (labelled or not); empty when absent.
metric_sum() {
    curl -s -m 10 "$BASE/metrics" |
        awk -v n="$1" '$1 == n || index($1, n "{") == 1 { s += $NF; found = 1 } END { if (found) printf "%.0f\n", s }'
}
# metric_series <series, exactly as exposed>: its value; empty when absent.
metric_series() {
    curl -s -m 10 "$BASE/metrics" | awk -v n="$1" '$1 == n { printf "%.0f\n", $NF; exit }'
}
gauge() { metric_sum yuzu_pg_collation_version_mismatch; }
deferred_all() { metric_sum yuzu_device_ci_writes_deferred_total; }
deferred_delete() { metric_series 'yuzu_device_ci_writes_deferred_total{op="delete"}'; }

device_ids() { jq -r '[.data.devices[].agent_id] | sort | join(",")' <<< "$HTTP_BODY" 2>/dev/null; }
row_sum() { # md5 of the whole device_ci row, or ROW-ABSENT
    local out
    out="$(psql_db -At -c "SELECT md5(t::text) FROM \"$SCHEMA\".device_ci t WHERE agent_id = '$1'")"
    echo "${out:-ROW-ABSENT}"
}

log "server $BIN; throwaway database $DB; web :$WEB_PORT grpc :$GRPC_PORT mgmt :$MGMT_PORT"
psql_admin -c "CREATE DATABASE \"$DB\""

# ── 1. healthy ────────────────────────────────────────────────────────────────
log "1. boot 1: healthy database"
start_server
mint_token

SCHEMA="$(psql_db -At -c "SELECT table_schema FROM information_schema.tables WHERE table_name = 'device_ci' AND table_schema NOT IN ('pg_catalog','information_schema') LIMIT 1")"
[ -n "$SCHEMA" ] || { echo "FAIL: no device_ci table after boot" >&2; exit 1; }
log "  seeding three device_ci rows by SQL INSERT into $SCHEMA.device_ci (no gRPC ingest client in this rig)"
for id in agent-c agent-a agent-b; do
    psql_db -c "INSERT INTO \"$SCHEMA\".device_ci (agent_id, hostname, manufacturer, model, serial, first_seen, last_seen) VALUES ('$id', 'host-$id', 'E2E', 'model-$id', 'serial-$id', 1, 1)"
done

http GET /api/v1/hardware-ci
if [ "$HTTP_STATUS" = "200" ] && [ "$(device_ids)" = "agent-a,agent-b,agent-c" ]; then
    pass "healthy: bulk read 200 with the three rows in agent_id order"
else
    fail "healthy: bulk read expected 200 with 3 rows, got $HTTP_STATUS: $HTTP_BODY"
fi
http GET /api/v1/hardware/agent-b
if [ "$HTTP_STATUS" = "200" ] && [ "$(jq -r '.data.ci_state + "/" + .data.ci.model' <<< "$HTTP_BODY" 2>/dev/null)" = "found/model-agent-b" ]; then
    pass "healthy: per-id record shows the CI block (ci_state found)"
else
    fail "healthy: per-id record expected ci_state found, got $HTTP_STATUS: $HTTP_BODY"
fi
G="$(gauge)"
{ [ -z "$G" ] || [ "$G" = "0" ]; } && pass "healthy: mismatch gauge is '${G:-absent}' (0 or absent)" || fail "healthy: mismatch gauge is '$G', expected 0 or absent"
D="$(deferred_all)"
[ "$D" = "0" ] && pass "healthy: yuzu_device_ci_writes_deferred_total is 0" || fail "healthy: deferred writes counter is '${D:-absent}', expected 0"
stop_server

# ── 2. forced mismatch, then reboot ───────────────────────────────────────────
log "2. forcing a collation version mismatch (superuser catalog UPDATE), boot 2"
psql_admin -c "UPDATE pg_database SET datcollversion = 'e2e-forced-mismatch' WHERE datname = '$DB'"
start_server
mint_token

http GET /api/v1/hardware-ci
RETRY_MS="$(jq -r '.error.retry_after_ms // empty' <<< "$HTTP_BODY" 2>/dev/null)"
HAS_DATA="$(jq -r 'has("data")' <<< "$HTTP_BODY" 2>/dev/null)"
if [ "$HTTP_STATUS" = "503" ] && [ "$RETRY_MS" = "60000" ] && [ "$HAS_DATA" = "false" ] &&
   grep -qi '^Retry-After: 60$' <<< "$HTTP_HDRS"; then
    pass "mismatch: bulk read 503, retry_after_ms 60000, Retry-After: 60, no data"
else
    fail "mismatch: bulk read expected 503/60000/Retry-After 60/no data, got $HTTP_STATUS retry_ms='$RETRY_MS' data='$HAS_DATA' headers: $HTTP_HDRS body: $HTTP_BODY"
fi
http GET /api/v1/hardware/agent-b
if [ "$HTTP_STATUS" = "200" ] && [ "$(jq -r '.data.ci_state + "/" + (.data.ci | tostring)' <<< "$HTTP_BODY" 2>/dev/null)" = "degraded/null" ]; then
    pass "mismatch: per-id CI block is degraded (ci_state degraded, ci null), not absent"
else
    fail "mismatch: per-id record expected ci_state degraded, got $HTTP_STATUS: $HTTP_BODY"
fi
G="$(gauge)"
[ "$G" = "1" ] && pass "mismatch: gauge reads 1" || fail "mismatch: gauge is '${G:-absent}', expected 1"
grep -q "e2e-forced-mismatch" "$WORK/server.boot$BOOT_N.log" &&
    pass "mismatch: the boot log names the recorded version" || fail "mismatch: boot log has no mismatch line naming the recorded version"

# ── 3. write pause ────────────────────────────────────────────────────────────
log "3. write pause: decommission agent-b while the gate reads Mismatch"
BEFORE_ROW="$(row_sum agent-b)"
BEFORE_ALL="$(deferred_all)"
BEFORE_DEL="$(deferred_delete)"
http DELETE /api/v1/sle/agents/agent-b
PAUSED="$(jq -r '.error.details.write_paused // [] | join(",")' <<< "$HTTP_BODY" 2>/dev/null)"
if [ "$HTTP_STATUS" = "500" ] && [ "$PAUSED" = "device_inventory" ]; then
    pass "pause: decommission refused with 500 and details.write_paused=[$PAUSED]"
else
    fail "pause: decommission expected 500 with details.write_paused=[device_inventory], got $HTTP_STATUS: $HTTP_BODY"
fi
AFTER_ROW="$(row_sum agent-b)"
if [ "$BEFORE_ROW" != "ROW-ABSENT" ] && [ "$BEFORE_ROW" = "$AFTER_ROW" ]; then
    pass "pause: the device_ci row is byte-unchanged (md5 $AFTER_ROW)"
else
    fail "pause: row checksum before='$BEFORE_ROW' after='$AFTER_ROW'"
fi
AFTER_ALL="$(deferred_all)"
AFTER_DEL="$(deferred_delete)"
if [ -n "$AFTER_ALL" ] && [ "$AFTER_ALL" -gt "${BEFORE_ALL:-0}" ] && [ -n "$AFTER_DEL" ] && [ "$AFTER_DEL" -gt "${BEFORE_DEL:-0}" ]; then
    pass "pause: yuzu_device_ci_writes_deferred_total grew ($BEFORE_ALL -> $AFTER_ALL; op=delete ${BEFORE_DEL:-absent} -> $AFTER_DEL)"
else
    fail "pause: deferred counter did not grow (all ${BEFORE_ALL:-absent} -> ${AFTER_ALL:-absent}; op=delete ${BEFORE_DEL:-absent} -> ${AFTER_DEL:-absent})"
fi

# ── 4. the documented repair, server still running ────────────────────────────
log "4. running the documented repair; waiting for the server's own recheck (<= 60 s)"
psql_db -c "REINDEX DATABASE CONCURRENTLY \"$DB\""
INVALID="$(psql_db -At -c "SELECT count(*) FROM pg_index WHERE NOT indisvalid")"
[ "$INVALID" = "0" ] && pass "repair: no invalid index after the reindex" || fail "repair: $INVALID invalid index(es) after the reindex"
psql_admin -c "ALTER DATABASE \"$DB\" REFRESH COLLATION VERSION"
REPAIRED_AT="$(date +%s)"
CLEARED=""
for _ in $(seq 1 150); do
    http GET /api/v1/hardware-ci
    if [ "$HTTP_STATUS" = "200" ]; then CLEARED="$(( $(date +%s) - REPAIRED_AT ))"; break; fi
    sleep 1
done
if [ -n "$CLEARED" ] && [ "$CLEARED" -le 75 ]; then
    pass "repair: the bulk read answered 200 again ${CLEARED}s after the repair (limit 60 s + slack)"
else
    fail "repair: still $HTTP_STATUS after 150 s (cleared='${CLEARED}'): $HTTP_BODY"
fi
[ "$(device_ids)" = "agent-a,agent-b,agent-c" ] && pass "repair: the same three rows are served again" || fail "repair: rows not served after recovery: $HTTP_BODY"
G="$(gauge)"
[ "$G" = "0" ] && pass "repair: gauge reads 0" || fail "repair: gauge is '${G:-absent}', expected 0"
http GET /api/v1/hardware/agent-b
[ "$(jq -r '.data.ci_state' <<< "$HTTP_BODY" 2>/dev/null)" = "found" ] &&
    pass "repair: per-id CI block is found again" || fail "repair: per-id record not found again: $HTTP_STATUS $HTTP_BODY"

PAUSED_TOTAL="$(deferred_all)"
http DELETE /api/v1/sle/agents/agent-b
if [ "$HTTP_STATUS" = "200" ] && [ "$(row_sum agent-b)" = "ROW-ABSENT" ]; then
    pass "repair: the same decommission now succeeds (200) and the device_ci row is gone, no restart"
else
    fail "repair: decommission expected 200 and the row removed, got $HTTP_STATUS: $HTTP_BODY (row now $(row_sum agent-b))"
fi
[ "$(deferred_all)" = "$PAUSED_TOTAL" ] && pass "repair: the deferred counter did not move on the resumed write" || fail "repair: deferred counter moved on a resumed write ($PAUSED_TOTAL -> $(deferred_all))"

echo
echo "passed=$PASS failed=$FAILS"
[ "$FAILS" -eq 0 ]
