#!/usr/bin/env bash
# e2e-crl-freshness-test.sh - real-stack check of the CA CRL freshness gauges (#6527, #7098).
#
# Boots a REAL yuzu-server against a REAL Postgres (server + Postgres only: no gateway, no
# agent) and asserts, on /metrics, the two gauges the YuzuCaCrl* alerts are built on:
#   yuzu_server_ca_crl_next_update_timestamp_seconds   the latest CRL's nextUpdate
#   yuzu_server_ca_crl_published_timestamp_seconds     the latest CRL row's published_at
#
# Scenarios, in order (each is a separate server boot or action on the same database):
#   A. Fresh install, boot publish: both gauges PRESENT, nextUpdate about 48 h ahead,
#      published about now. (The served CRL's thisUpdate is the publish time minus 300 s.)
#      An operator revoke republishes: both gauges MOVE.
#   B. No CRL: the series are ABSENT, not 0. The server publishes its first CRL at boot,
#      BEFORE the web listener binds, so a healthy boot can never be scraped without one; the
#      scenario therefore restarts against a database whose ca_crl_versions is emptied and has
#      an INSERT trigger that refuses, so the boot publish fails ("PKI: initial CRL publish
#      failed") and the gauges are scraped while no CRL row exists.
#   C. The trigger is dropped and an operator revoke publishes: both gauges become PRESENT.
#   D. Re-root while the server keeps running (docs/pki-architecture.md "CRL near expiry or
#      expired" and docs/user-manual/metrics.md "Not covered"): after the CA tables are emptied
#      the running server's gauges are STALE (still the old values); only a restart that
#      re-roots (stop, empty the tables, remove the on-disk default-* material, start) moves
#      them to the new CRL.
#
# Isolation: every identifier is salted per run (database, work dir, ports allocated by the OS),
# so it can run beside another rig or a second copy of itself. It does NOT use 8080 / 50051.
#
# Usage:
#   YUZU_TEST_POSTGRES_DSN=postgresql://user:pw@host:5433/db ./scripts/e2e-crl-freshness-test.sh
#   YUZU_BUILDDIR=/path/to/build-linux ./scripts/e2e-crl-freshness-test.sh
#   YUZU_KEEP_WORK_DIR=1 keeps the work dir (server logs) after a passing run.
#
# Prerequisites: build-<os>/server/core/yuzu-server, psql, curl, python3 on PATH, and a
# Postgres superuser DSN in YUZU_TEST_POSTGRES_DSN (a uniquely named database is created and
# dropped). openssl is optional: with it the served CRL's thisUpdate is cross-checked too.
# A missing prerequisite fails the script (exit 1); it never reports a skip.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -n "${YUZU_BUILDDIR:-}" ]]; then
    BUILDDIR="$YUZU_BUILDDIR"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    BUILDDIR="$PROJECT_ROOT/build-macos"
else
    BUILDDIR="$PROJECT_ROOT/build-linux"
fi
SERVER_BIN="$BUILDDIR/server/core/yuzu-server"

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { echo "  PASS $*"; }
fail() { echo "  FAIL $*"; FAILURES=$((FAILURES + 1)); }
FAILURES=0
TESTS=0

NEXT_G="yuzu_server_ca_crl_next_update_timestamp_seconds"
PUB_G="yuzu_server_ca_crl_published_timestamp_seconds"

# ── Preflight ───────────────────────────────────────────────────────────
for tool in psql curl python3; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "FAIL: $tool not on PATH (required by this script)" >&2
        exit 1
    fi
done
if [[ ! -x "$SERVER_BIN" ]]; then
    echo "FAIL: $SERVER_BIN not found or not executable (build it, or set YUZU_BUILDDIR)" >&2
    exit 1
fi
if [[ -z "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
    echo "FAIL: YUZU_TEST_POSTGRES_DSN is unset (the server fails closed without Postgres)" >&2
    exit 1
fi
HAVE_OPENSSL=false
command -v openssl > /dev/null 2>&1 && HAVE_OPENSSL=true

RUN_SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# Lowercase [a-z0-9_] with an epoch right after the prefix, so the test-database sweepers can
# reclaim a database this run leaked (SIGKILL, runner loss).
RUN_DB="yuzu_test_$(date +%s)_crlfresh_${RUN_SALT}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_crlfresh_${RUN_SALT}.XXXXXX")"
SERVER_PID=""
DB_CREATED=false

# ── Cleanup ─────────────────────────────────────────────────────────────
stop_server() {
    [[ -n "$SERVER_PID" ]] || return 0
    kill -TERM "$SERVER_PID" 2> /dev/null || true
    local i
    for i in $(seq 1 60); do
        kill -0 "$SERVER_PID" 2> /dev/null || break
        sleep 0.5
    done
    kill -9 "$SERVER_PID" 2> /dev/null || true
    wait "$SERVER_PID" 2> /dev/null || true
    SERVER_PID=""
}
cleanup() {
    local rc=$?
    stop_server
    if $DB_CREATED; then
        psql "$YUZU_TEST_POSTGRES_DSN" -qtAc "DROP DATABASE IF EXISTS \"$RUN_DB\" WITH (FORCE);" \
            > /dev/null 2>&1 || true
    fi
    if [[ -z "${YUZU_KEEP_WORK_DIR:-}" && $rc -eq 0 && $FAILURES -eq 0 ]]; then
        rm -rf "$WORK_DIR"
    else
        log "Preserving work dir: $WORK_DIR"
    fi
}
trap cleanup EXIT

# ── Database, config, ports ─────────────────────────────────────────────
psql "$YUZU_TEST_POSTGRES_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"$RUN_DB\";" > /dev/null
DB_CREATED=true
dsn_base="${YUZU_TEST_POSTGRES_DSN%%\?*}"
dsn_query=""
[[ "$dsn_base" != "$YUZU_TEST_POSTGRES_DSN" ]] && dsn_query="?${YUZU_TEST_POSTGRES_DSN#*\?}"
RUN_DSN="${dsn_base%/*}/${RUN_DB}${dsn_query}"
# Prove the DSN really lands in the per-run database before the server is booted on it (a
# dbname= or options= override in the DSN query would otherwise hit another database).
_early_db="$(psql "$RUN_DSN" -v ON_ERROR_STOP=1 -qtAc 'SELECT current_database()' 2> /dev/null || true)"
if [[ "$_early_db" != "$RUN_DB" ]]; then
    echo "FAIL: DSN resolves to database '$_early_db', expected the per-run database '$RUN_DB'" >&2
    exit 1
fi

# One allocation call: the sockets are all held until the list is printed, so no two are equal.
read -r AGENT_PORT MGMT_PORT WEB_PORT < <(python3 -c '
import socket
s = [socket.socket() for _ in range(3)]
for x in s:
    x.bind(("127.0.0.1", 0))
print(*[x.getsockname()[1] for x in s])
')
BASE="http://127.0.0.1:$WEB_PORT"
DATA_DIR="$WORK_DIR/server-data"
CA_DIR="$WORK_DIR/ca"
mkdir -p "$DATA_DIR" "$CA_DIR"
SERVER_CFG="$DATA_DIR/yuzu-server.cfg"
# A per-run random admin password (never a fixed one), handed to python through the environment
# rather than argv. Note: the Postgres DSN (with its password) is on argv for psql and for
# --postgres-dsn, as scripts/integration-test.sh also does; this rig targets a throwaway local
# test database, not a shared host.
ADMIN_PASS="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
YUZU_RIG_ADMIN_PASS="$ADMIN_PASS" python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', os.environ['YUZU_RIG_ADMIN_PASS'].encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$SERVER_CFG"
chmod 600 "$SERVER_CFG"
log "Run salt $RUN_SALT: database $RUN_DB, web :$WEB_PORT, agent :$AGENT_PORT, mgmt :$MGMT_PORT"

# Every statement the rig runs against its own database goes through here, and the connection is
# first proven to be the salted per-run database: the TRUNCATEs below must never reach another one
# (a DSN with a different database name in its query string, a pooler remapping, a typo).
psql_run() {
    local db
    db="$(psql "$RUN_DSN" -v ON_ERROR_STOP=1 -qtAc 'SELECT current_database()')"
    if [[ "$db" != "$RUN_DB" ]]; then
        echo "FAIL: refusing to run SQL: connected to '$db', expected the per-run database '$RUN_DB'" >&2
        exit 1
    fi
    PGOPTIONS='-c lock_timeout=10s' psql "$RUN_DSN" -v ON_ERROR_STOP=1 -qtAc "$1"
}

# ── Server lifecycle ────────────────────────────────────────────────────
BOOT_N=0
start_server() {
    BOOT_N=$((BOOT_N + 1))
    SERVER_LOG="$WORK_DIR/server-boot${BOOT_N}.log"
    "$SERVER_BIN" --config "$SERVER_CFG" --data-dir "$DATA_DIR" --ca-dir "$CA_DIR" \
        --postgres-dsn "$RUN_DSN" \
        --listen "127.0.0.1:$AGENT_PORT" --management "127.0.0.1:$MGMT_PORT" \
        --web-address 127.0.0.1 --web-port "$WEB_PORT" --no-https --metrics-no-auth \
        > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    # A cold start walks every migration and routinely takes 12+ s.
    local i
    for i in $(seq 1 120); do
        if curl --max-time 10 -sf -o /dev/null "$BASE/livez" 2> /dev/null; then
            log "  boot $BOOT_N: server ready (pid $SERVER_PID)"
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2> /dev/null; then
            echo "FAIL: server exited during boot $BOOT_N; tail of $SERVER_LOG:" >&2
            tail -n 30 "$SERVER_LOG" >&2
            exit 1
        fi
        sleep 0.5
    done
    echo "FAIL: server not ready within 60 s on boot $BOOT_N; tail of $SERVER_LOG:" >&2
    tail -n 30 "$SERVER_LOG" >&2
    exit 1
}

# ── Assertions ──────────────────────────────────────────────────────────
scrape() { curl --max-time 10 -sf "$BASE/metrics"; }
# The integer value of one unlabelled series, or empty when absent. printf %.0f copes with the
# exponent form a large double may be serialised in.
series() {
    awk -v n="$1" '$1 == n { printf "%.0f\n", $2; exit }' <<< "$2"
}
assert_absent() { # desc, scrape-body
    TESTS=$((TESTS + 1))
    local n p
    n="$(series "$NEXT_G" "$2")"
    p="$(series "$PUB_G" "$2")"
    if [[ -z "$n" && -z "$p" ]]; then pass "$1"; else fail "$1 (next='$n' published='$p')"; fi
}
# Both gauges present and plausible for a CRL published at about now.
assert_fresh() { # desc, scrape-body
    TESTS=$((TESTS + 1))
    local n p now
    n="$(series "$NEXT_G" "$2")"
    p="$(series "$PUB_G" "$2")"
    now="$(date +%s)"
    if [[ -z "$n" || -z "$p" ]]; then
        fail "$1 (gauge missing: next='$n' published='$p')"
        return
    fi
    # published = the publish time (the CRL's thisUpdate is 300 s earlier); nextUpdate = build
    # time + 48 h. 120 s of slack each way for a loaded box.
    local d_pub=$((p - now)) d_next=$((n - now - 172800))
    if ((d_pub < 0)); then d_pub=$((-d_pub)); fi
    if ((d_next < 0)); then d_next=$((-d_next)); fi
    if ((d_pub <= 120 && d_next <= 120)); then
        pass "$1 (published-now=$((p - now)) s, nextUpdate-now-48h=$((n - now - 172800)) s)"
    else
        fail "$1 (published-now=$((p - now)) s, nextUpdate-now-48h=$((n - now - 172800)) s)"
    fi
}

admin_login() {
    JAR="$WORK_DIR/cookies-boot${BOOT_N}.txt"
    local code
    # The password goes in on stdin (password@-), so it is never on curl's argv.
    code="$(printf '%s' "$ADMIN_PASS" | curl --max-time 10 -s -o /dev/null -w '%{http_code}' -c "$JAR" -H "Origin: $BASE" \
        "$BASE/login" --data-urlencode "username=admin" --data-urlencode "password@-" || echo 000)"
    if [[ "$code" != "200" ]]; then
        echo "FAIL: admin login returned $code" >&2
        exit 1
    fi
}
api() { # method path [body]
    curl --max-time 10 -s -b "$JAR" -H "Origin: $BASE" -H "Content-Type: application/json" \
        -X "$1" "$BASE$2" ${3:+-d "$3"} -w '\n%{http_code}'
}
# Revoke the next not-yet-revoked non-server certificate (the server leaf is the one this
# process's own TLS identity could be, so it is left alone). Prints the HTTP status.
REVOKED_SERIALS=" "
revoke_next() {
    local issued serial resp
    issued="$(api GET '/api/v1/ca/issued?limit=100')"
    serial="$(printf '%s\n' "$issued" | python3 -c '
import json, sys
body = sys.stdin.read().rsplit("\n", 2)[0]  # drop the trailing status line the api() helper adds
skip = set(sys.argv[1].split())
for r in json.loads(body).get("items", []):
    # The server leaf is left alone; the "https" and "gateway" leaves are the revocable ones.
    if r["serial_hex"] not in skip and r.get("status") == "active" and r.get("purpose") != "server":
        print(r["serial_hex"])
        break
' "$REVOKED_SERIALS" || true)"
    if [[ -z "$serial" ]]; then
        echo "FAIL: no revocable certificate found in /api/v1/ca/issued: $issued" >&2
        exit 1
    fi
    resp="$(api POST /api/v1/ca/revoke "{\"serial_hex\":\"$serial\",\"reason\":\"e2e-crl-freshness $RUN_SALT\"}")"
    REVOKED_SERIALS="$REVOKED_SERIALS$serial "
    REVOKE_BODY="${resp%$'\n'*}"
    REVOKE_CODE="${resp##*$'\n'}"
}

# ══════════════════════════════════════════════════════════════════════
# A. Fresh install: the boot publish makes both gauges present
# ══════════════════════════════════════════════════════════════════════
log "A. fresh install, boot publish"
start_server
M="$(scrape)"
assert_fresh "gauges present and fresh after the boot publish" "$M"
A_NEXT="$(series "$NEXT_G" "$M")"
A_PUB="$(series "$PUB_G" "$M")"
TESTS=$((TESTS + 1))
if (( A_NEXT > A_PUB )) && (( A_NEXT - A_PUB >= 172800 - 5 )) && (( A_NEXT - A_PUB <= 172800 + 5 )); then
    pass "nextUpdate - published is 48 h to within 5 s ($((A_NEXT - A_PUB)) s)"
else
    fail "nextUpdate - published is not 48 h ($((A_NEXT - A_PUB)) s)"
fi
if $HAVE_OPENSSL; then
    curl --max-time 10 -sf -o "$WORK_DIR/crl-a.der" "$BASE/api/v1/ca/crl" || true
    LU="$(openssl crl -inform DER -in "$WORK_DIR/crl-a.der" -noout -lastupdate 2> /dev/null | sed 's/^lastUpdate=//' || true)"
    LU_EPOCH="$(date -d "$LU" +%s 2> /dev/null || true)"
    TESTS=$((TESTS + 1))
    if [[ -n "$LU_EPOCH" ]] && (( A_PUB - LU_EPOCH >= 295 && A_PUB - LU_EPOCH <= 310 )); then
        pass "served CRL thisUpdate is the published gauge minus 300 s ($((A_PUB - LU_EPOCH)) s)"
    else
        fail "served CRL thisUpdate '$LU' is not published-300 s (published=$A_PUB, lastUpdate epoch='$LU_EPOCH')"
    fi
fi

log "A. operator revoke republishes: both gauges move"
admin_login
sleep 2 # published_at has 1 s resolution; the revoke must land in a later second
revoke_next
TESTS=$((TESTS + 1))
if [[ "$REVOKE_CODE" == "200" ]]; then pass "POST /api/v1/ca/revoke returned 200"; else fail "POST /api/v1/ca/revoke returned $REVOKE_CODE: $REVOKE_BODY"; fi
M="$(scrape)"
assert_fresh "gauges present and fresh after the revoke publish" "$M"
B_NEXT="$(series "$NEXT_G" "$M")"
B_PUB="$(series "$PUB_G" "$M")"
TESTS=$((TESTS + 1))
if [[ -n "$B_NEXT" && -n "$B_PUB" ]] && (( B_NEXT > A_NEXT && B_PUB > A_PUB )); then
    pass "both gauges moved forward ($A_NEXT -> $B_NEXT, $A_PUB -> $B_PUB)"
else
    fail "gauges did not move after the revoke publish (next $A_NEXT -> '$B_NEXT', published $A_PUB -> '$B_PUB')"
fi
stop_server

# ══════════════════════════════════════════════════════════════════════
# B. No CRL: the series are absent, never 0
# ══════════════════════════════════════════════════════════════════════
log "B. no CRL published: refuse the boot publish at the database"
psql_run "CREATE OR REPLACE FUNCTION public.yuzu_test_block_crl() RETURNS trigger LANGUAGE plpgsql AS \$f\$ BEGIN RAISE EXCEPTION 'yuzu_test: CRL publish blocked'; END \$f\$;"
psql_run "TRUNCATE ca_store.ca_crl_versions;"
psql_run "CREATE TRIGGER yuzu_test_block_crl BEFORE INSERT ON ca_store.ca_crl_versions FOR EACH ROW EXECUTE FUNCTION public.yuzu_test_block_crl();"
TESTS=$((TESTS + 1))
if [[ "$(psql_run 'SELECT count(*) FROM ca_store.ca_crl_versions;')" == "0" ]]; then
    pass "precondition: ca_crl_versions is empty"
else
    fail "precondition: ca_crl_versions is not empty"
fi
start_server
M="$(scrape)"
assert_absent "both gauges ABSENT while no CRL row exists (not 0)" "$M"
TESTS=$((TESTS + 1))
# Any yuzu_ series other than the two under test: the preceding check cannot be satisfied by a body
# that is simply empty or wrong.
OTHER_SERIES="$(grep '^yuzu_' <<< "$M" | grep -v -e "^$NEXT_G" -e "^$PUB_G" || true)"
if [[ -n "$OTHER_SERIES" ]]; then # (a captured variable: a `grep -q` pipeline trips pipefail)
    pass "the scrape itself works (other series present), so absent is not a failed scrape"
else
    fail "scrape returned no recognisable series"
fi
TESTS=$((TESTS + 1))
if grep -q "initial CRL publish failed" "$SERVER_LOG"; then
    pass "boot log records 'PKI: initial CRL publish failed' (the precondition held)"
else
    fail "boot log lacks 'initial CRL publish failed'"
fi
sleep 5
M="$(scrape)"
assert_absent "still absent on a later scrape" "$M"

# ══════════════════════════════════════════════════════════════════════
# C. The first CRL appears: absent -> present
# ══════════════════════════════════════════════════════════════════════
log "C. clear the fault; an operator revoke publishes the first CRL"
psql_run "DROP TRIGGER yuzu_test_block_crl ON ca_store.ca_crl_versions;"
admin_login
revoke_next
TESTS=$((TESTS + 1))
if [[ "$REVOKE_CODE" == "200" ]]; then pass "POST /api/v1/ca/revoke returned 200"; else fail "POST /api/v1/ca/revoke returned $REVOKE_CODE: $REVOKE_BODY"; fi
M="$(scrape)"
assert_fresh "both gauges PRESENT after the first CRL (absent -> present)" "$M"
C_NEXT="$(series "$NEXT_G" "$M")"
C_PUB="$(series "$PUB_G" "$M")"

# ══════════════════════════════════════════════════════════════════════
# D. Re-root: stale until restart
# ══════════════════════════════════════════════════════════════════════
log "D. re-root while the server keeps running: the gauges stay stale"
psql_run "TRUNCATE ca_store.ca_root, ca_store.ca_issued, ca_store.ca_crl_versions;"
TESTS=$((TESTS + 1))
if [[ "$(psql_run 'SELECT count(*) FROM ca_store.ca_crl_versions;')" == "0" ]]; then
    pass "precondition: the CRL table is empty while the server runs"
else
    fail "precondition: the CRL table is not empty"
fi
sleep 3
M="$(scrape)"
# Let a few scrapes and any background republish attempt run. This is not what keeps the gauges
# stale: a successful read that finds no row leaves the gauges at their last value by design.
sleep 5
M2="$(scrape)"
D_NEXT="$(series "$NEXT_G" "$M2")"
D_PUB="$(series "$PUB_G" "$M2")"
TESTS=$((TESTS + 1))
if [[ "$D_NEXT" == "$C_NEXT" && "$D_PUB" == "$C_PUB" ]]; then
    pass "gauges still hold the pre-re-root values with no CRL row ($D_NEXT / $D_PUB): stale until restart"
else
    fail "gauges changed without a restart (next $C_NEXT -> '$D_NEXT', published $C_PUB -> '$D_PUB')"
fi
log "D. restart as the runbook says: stop, empty tables (done), remove default-* material, start"
stop_server
rm -f "$CA_DIR"/default-*.pem "$CA_DIR"/default-*.key "$CA_DIR"/default-marker.json
psql_run "TRUNCATE ca_store.ca_root, ca_store.ca_issued, ca_store.ca_crl_versions;"
sleep 2
start_server
M="$(scrape)"
assert_fresh "after the re-rooting restart the gauges are fresh again" "$M"
E_NEXT="$(series "$NEXT_G" "$M")"
E_PUB="$(series "$PUB_G" "$M")"
TESTS=$((TESTS + 1))
if [[ -n "$E_NEXT" && -n "$E_PUB" ]] && (( E_NEXT > D_NEXT && E_PUB > D_PUB )); then
    pass "the restart moved both gauges ($D_NEXT -> $E_NEXT, $D_PUB -> $E_PUB)"
else
    fail "restart did not move the gauges (next $D_NEXT -> '$E_NEXT', published $D_PUB -> '$E_PUB')"
fi
TESTS=$((TESTS + 1))
if [[ "$(psql_run 'SELECT count(*) FROM ca_store.ca_crl_versions;')" == "1" ]]; then
    pass "the re-rooting restart left exactly one CRL row"
else
    fail "unexpected CRL row count after the re-root"
fi

# ── Summary ─────────────────────────────────────────────────────────────
echo
log "Result: $((TESTS - FAILURES)) passed, $FAILURES failed (of $TESTS checks)"
if [[ $FAILURES -ne 0 ]]; then
    exit 1
fi
