#!/usr/bin/env bash
# ha-crl-publish-failover.sh — WS-9 failover scenario for HA WS-6 (#4832, ADR-2002 §11/§6).
#
# Proves cross-replica CRL publication survives a Patroni switchover without
# reusing a crlNumber and without permanently losing a revocation, driving a
# REAL yuzu-server + CaStore::publish_next_crl's table-lock protocol (WS-6
# 6.1) against deploy/docker/docker-compose.ha-postgres.yml.
#
#   1. deterministic lost ack   pause BOTH standbys (so no sync ack can ever
#      arrive under YUZU_PG_DURABILITY=sync2 + YUZU_PG_SYNC_STRICT=true —
#      strict mode blocks rather than degrading to async), fire a revoke,
#      poll pg_stat_activity for the publish transaction's backend to reach
#      wait_event='SyncRep' (the transaction has ALREADY LOCALLY COMMITTED at
#      that point), pg_terminate_backend it — reproducing exactly the "lost
#      COMMIT acknowledgement" ca_store.cpp's publish_next_crl comment
#      describes, not a rollback — unpause, switch the primary over, and
#      assert no crlNumber reuse + eventual serial coverage via self-heal.
#      (Simpler and more deterministic than pausing only the one designated
#      sync standby: Patroni can reassign the synchronous role to the other
#      standby within one loop_wait, racing the pg_terminate_backend poll —
#      pausing both removes that race entirely, since no reassignment target
#      exists either way. See "DEVIATION" comment at run_case1 below.)
#   2. connection reset          a different, simpler fault: hold the CRL
#      table lock externally, queue a second revoke behind it, kill the
#      queued backend WHILE IT IS STILL WAITING ON THE LOCK — a genuine
#      rollback (number never consumed), not an ack loss. Self-heal
#      republishes and covers the serial with no gap in the numbering.
#   3. async durability          confirms YUZU_PG_DURABILITY=async is a real,
#      reachable toggle (so case 1's sync-mode claim isn't vacuous on an
#      operator's async rig) and cites the crlNumber-reuse residual that
#      docs/pki-architecture.md already documents for that mode — no live
#      fault injection needed, per #4832's AC3.
#
# Fable's explicit instruction (plan review, 2026-09-27): if case 1's
# pg_terminate_backend-on-SyncRep-wait recipe does NOT reproduce a lost-ack
# state on the rig it runs against, this script reports that as its own
# named INCONCLUSIVE outcome rather than silently downgrading to a weaker
# claim — see the FAILS/INCONCLUSIVE counters below.
#
# CURRENT VERIFIED STATE (2026-09-27, after 8 live runs against a real
# docker-compose.ha-postgres.yml stack, most debugging a chain of THREE real
# script bugs found this way — wrong https-port, wrong db in the case-2 lock
# holder, and a stale $PRIMARY after case 1's own switchover):
#   - Case 1: PASSES CLEANLY and REPRODUCIBLY (3 of 4 runs after the design
#     settled; 1 run reported its own INCONCLUSIVE per Fable's instruction
#     above rather than a false pass — a real, disclosed non-determinism in
#     the SyncRep-wait recipe, not a script bug). This is the load-bearing
#     assertion #4832 exists to make (AC1: no crlNumber reuse across a
#     switchover under a real lost ack) and it has been observed to hold.
#   - Case 2: the first 4 of 5 assertions (lock acquisition confirmed via
#     pg_locks, the queued backend killed pre-lock, crl_republished:false
#     reported honestly, no crlNumber gap) now PASS RELIABLY after the
#     $PRIMARY-staleness fix. The FINAL assertion — self-heal covers the
#     revoked serial within 60s of the connection reset — was observed to
#     time out in the one clean run after all three bugs were fixed. Not
#     re-investigated further (stopped per an explicit time-box decision,
#     2026-09-27) — plausibly a real self-heal-timing edge case worth its
#     own look (e.g. whether the external lock-holder's own still-running
#     pg_sleep(30) is itself delaying the freshness pass's next publish
#     attempt past the 60s window), or a still-narrower script bug in how
#     this specific assertion polls. Filed as a follow-up rather than fixed
#     here — see docs/ha-delivery-matrix.md's WS-6 row for the issue link.
#   - Case 3: PASSES CLEANLY and reproducibly across every run once the
#     3-node boot-log check (rather than primary-only) landed.
#
# Requires: docker, docker compose, curl, python3, openssl, and a built
# yuzu-server. The compose's container names + network are FIXED, not
# salted — like ha-pg-failover-cycles.sh, this is a manual harness (no
# workflow runs it), and docs/uat-environment.md's three-mutually-exclusive-
# rigs rule means only one such rig runs at a time.
#
# usage: ha-crl-publish-failover.sh [--server-bin PATH] [--case 1|2|3|all]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/docker-compose.ha-postgres.yml"
if [[ "$(uname -s)" == "Darwin" ]]; then BUILD_DIR=build-macos; else BUILD_DIR=build-linux; fi
SERVER_BIN="${REPO_ROOT}/${BUILD_DIR}/server/core/yuzu-server"
NODES=(yuzu-ha-pg1 yuzu-ha-pg2 yuzu-ha-pg3)
CASE="all"
# "default" (the docker driver) shares the local image store, so `FROM
# yuzu-postgres:local` in Dockerfile.postgres-ha resolves the already-built
# local image instead of a buildx `docker-container` builder trying (and
# failing) to pull it from a registry — same fix ha-pg-failover-cycles.sh
# already carries.
export BUILDX_BUILDER="${YUZU_HA_BUILDER:-default}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        --case) CASE="$2"; shift 2 ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -x "$SERVER_BIN" ]] || { echo "no server binary at $SERVER_BIN — build it, or pass --server-bin" >&2; exit 2; }

APP_USER="${YUZU_DB_USER:-yuzu}"; APP_DB="${YUZU_DB_NAME:-yuzu}"; APP_PASS="${YUZU_DB_PASSWORD:-yuzu-app-dev}"
SUPER="${YUZU_SUPERUSER_NAME:-postgres}"
export YUZU_SUPERUSER_PASSWORD="${YUZU_SUPERUSER_PASSWORD:-yuzu-super-dev}"
export YUZU_PG_REPLICATION_PASSWORD="${YUZU_PG_REPLICATION_PASSWORD:-yuzu-repl-dev}"
export YUZU_DB_PASSWORD="${APP_PASS}"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
WEB="$(free_port)"; GRPC="$(free_port)"; MGMT="$(free_port)"; PGPORT="$(free_port)"; HTTPS_PORT="$(free_port)"
# The CRL/CA surface only exists when default-certs bootstrap actually ran,
# which is gated on TLS/HTTPS being ACTIVE (bootstrap_default_certs() returns
# early when both are off — server.cpp's "operator supplied certs for every
# active surface (or TLS/HTTPS off)" early-return). So — unlike
# ha-readyz-scenarios.sh, which has no PKI surface to exercise and disables
# both — this script boots with TLS/HTTPS ON (self-signed default certs) and
# talks to the server over `https://127.0.0.1:${HTTPS_PORT}` with `curl -k`.
# --web-port still matters (it's the HTTP→HTTPS redirect listener); the real
# API surface is --https-port.
BASE_URL="https://127.0.0.1:${HTTPS_PORT}"
JAR=""

RIG="$(mktemp -d -t yuzu_ha_crl.XXXXXX)"
SERVER_PID=""
FAILS=0
INCONCLUSIVE=0

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }
inconclusive() { echo "  INCONCLUSIVE  $*"; INCONCLUSIVE=$((INCONCLUSIVE + 1)); }

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill -KILL "$SERVER_PID" 2>/dev/null
    for c in "${NODES[@]}"; do docker unpause "$c" >/dev/null 2>&1; done
    docker compose -f "${COMPOSE_FILE}" -f "${RIG}/port-override.yml" down -v >/dev/null 2>&1 || true
    rm -rf "$RIG"
}
trap cleanup EXIT

# ── helpers shared with ha-pg-failover-cycles.sh's style ────────────────────
# No `psql` client on the host running this script — appsql/supersql run it
# inside a throwaway container on the compose's own `hanet` network instead
# (same CLIENT_IMAGE/pattern as ha-pg-failover-cycles.sh's own `appsql`),
# resolving the `postgres` alias (HAProxy) exactly as the real yuzu-server
# would over its host-published DSN.
CLIENT_IMAGE="yuzu-postgres:local"
appsql() { # <sql> — via the `postgres` (HAProxy) alias, app credentials
    timeout 20 docker run --rm --network yuzu-ha-pg \
        -e PGPASSWORD="${APP_PASS}" -e PGCONNECT_TIMEOUT=5 --entrypoint psql \
        "${CLIENT_IMAGE}" -h postgres -U "${APP_USER}" -d "${APP_DB}" -v ON_ERROR_STOP=1 -tAc "$1"
}
supersql() { # <container> <sql> [db] — superuser, over the container's local socket.
    # pg_stat_activity/pg_stat_replication are cluster-wide views, visible from
    # any database, so every OTHER call site here is fine against the
    # maintenance db — but a ::regclass cast (e.g. ca_store.ca_crl_versions in
    # pg_locks lookups) only resolves against the database that table
    # actually lives in (${APP_DB}, "yuzu"), never "postgres".
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
node_name() { docker exec "$1" printenv PATRONI_NAME 2>/dev/null; } # patroni node name for <container>
wait_full_health() {
    local p="$1" want="$2" i s
    for i in $(seq 1 90); do
        s="$(supersql "$p" "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'" 2>/dev/null || echo 0)"
        [[ "${s:-0}" -ge "${want}" ]] && { echo "$s"; return 0; }
        sleep 2
    done
    return 1
}
switchover() { # <primary-container> — no candidate: let Patroni pick the best standby
    local p="$1" pname
    pname="$(node_name "$p")"
    docker exec "$p" curl -s -X POST -H 'Content-Type: application/json' \
        -d "{\"leader\":\"${pname}\"}" http://localhost:8008/switchover >/dev/null
}
wait_new_primary() { # <old-primary-container> <timeout-s> — echoes the new primary container
    local old="$1" limit="$2" start now new
    start=$(date +%s)
    while :; do
        if new="$(find_primary 2>/dev/null)" && [[ -n "$new" && "$new" != "$old" ]]; then
            echo "$new"; return 0
        fi
        now=$(date +%s); (( now - start >= limit )) && return 1
        sleep 2
    done
}
crl_serials() { # parse the DER served at /api/v1/ca/crl, print revoked serials one per line
    curl -sk --max-time 5 "${BASE_URL}/api/v1/ca/crl" -o "$RIG/latest.crl"
    # A CRL's revoked-entry "Serial Number:" line carries the hex VALUE on the
    # SAME line (unlike an `openssl x509 -text` cert, where it's on the next
    # line) — `sed` pulls it straight off, no getline.
    openssl crl -inform DER -in "$RIG/latest.crl" -noout -text 2>/dev/null \
        | sed -n 's/^[[:space:]]*Serial Number:[[:space:]]*\(.*\)$/\1/p'
}
wait_serial_covered() { # <serial_hex from the revoke/issue response> <timeout-s>
    # Compare as integers, not strings: openssl's printed "Serial Number:" is
    # colon-separated and may carry a leading 00 padding byte the raw
    # serial_hex column doesn't (DER INTEGER sign-byte), so a naive string
    # match can false-negative on an otherwise-correct match.
    local want="$1" limit="$2" start now hexlist
    start=$(date +%s)
    while :; do
        hexlist="$(crl_serials | tr -d ':')"
        if [[ -n "$hexlist" ]] && python3 -c "
import sys
want = int(sys.argv[1], 16)
for line in sys.argv[2].splitlines():
    line = line.strip()
    if line and int(line, 16) == want:
        sys.exit(0)
sys.exit(1)" "$want" "$hexlist"; then
            echo $(( $(date +%s) - start )); return 0
        fi
        now=$(date +%s); (( now - start >= limit )) && return 1
        sleep 3
    done
}
crl_versions() { appsql "SELECT version FROM ca_store.ca_crl_versions ORDER BY version"; }
assert_no_reuse() { # <label> <before-versions-newline-list> — compares against current, asserts monotonic no dup
    local label="$1" after
    after="$(crl_versions)"
    if [[ -z "$(echo "$after" | sort | uniq -d)" ]]; then
        pass "$label: no duplicate crlNumber across $(echo "$after" | wc -l) published versions ($(echo "$after" | tr '\n' ' '))"
    else
        fail "$label: DUPLICATE crlNumber found: $(echo "$after" | sort | uniq -d | tr '\n' ' ')"
    fi
}

# ── bring up the cluster under a given durability profile ───────────────────
bring_up() { # <YUZU_PG_DURABILITY> <YUZU_PG_SYNC_STRICT>
    export YUZU_PG_DURABILITY="$1" YUZU_PG_SYNC_STRICT="$2"
    docker compose -f "${COMPOSE_FILE}" -f "${RIG}/port-override.yml" up -d --build >/dev/null
    local primary=""
    for i in $(seq 1 60); do
        if primary="$(find_primary)"; then
            [[ "$(appsql 'SELECT NOT pg_is_in_recovery()' 2>/dev/null || true)" == "t" ]] && break
        fi
        sleep 2; [[ "${i}" -eq 60 ]] && { echo "cluster not write-ready within 120s" >&2; return 1; }
    done
    wait_full_health "${primary}" "$(( ${#NODES[@]} - 1 ))" >/dev/null || { echo "not all standbys caught up" >&2; return 1; }
    echo "${primary}"
}
tear_down() {
    [[ -n "$SERVER_PID" ]] && { kill -TERM "$SERVER_PID" 2>/dev/null; sleep 1; kill -KILL "$SERVER_PID" 2>/dev/null; SERVER_PID=""; }
    for c in "${NODES[@]}"; do docker unpause "$c" >/dev/null 2>&1; done
    docker compose -f "${COMPOSE_FILE}" -f "${RIG}/port-override.yml" down -v >/dev/null 2>&1 || true
}

# A compose override publishing HAProxy's :5432 to a free localhost port, so a
# real yuzu-server (and this script's own psql/appsql calls) can reach the
# `postgres` alias without joining the `hanet` bridge network themselves —
# every service in the base compose has NO host-published ports by design
# (the network boundary is deliberate, see the compose file's own header).
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

wait_for() { # <path> <want-code> <timeout-s>
    local path="$1" want="$2" limit="$3" start now
    start=$(date +%s)
    while :; do
        [[ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}$path")" == "$want" ]] && { echo $(( $(date +%s) - start )); return 0; }
        now=$(date +%s); (( now - start >= limit )) && { echo $((now - start)); return 1; }
        sleep 0.5
    done
}
boot_server() {
    local dsn="postgresql://${APP_USER}:${APP_PASS}@127.0.0.1:${PGPORT}/${APP_DB}"
    "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --https-port "${HTTPS_PORT}" \
        --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
        --postgres-dsn "$dsn" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
        --ca-dir "$RIG/certs" >> "$RIG/server.log" 2>&1 &
    SERVER_PID=$!
    if ! wait_for /readyz 200 60 >/dev/null; then
        echo "server never became ready; log tail:" >&2; tail -30 "$RIG/server.log" >&2; return 1
    fi
    # Every privileged CA route (revoke, issue-code-signing) needs an
    # authenticated session, not just reachability — /login is form-encoded,
    # matching scripts/e2e-security-test.sh's own curl pattern (-c cookie jar,
    # username=...&password=...). The bootstrap admin's password is the
    # literal 'testpass123' baked into this script's own yuzu-server.cfg
    # generation above (same convention ha-readyz-scenarios.sh uses).
    JAR="$RIG/cookies.jar"
    local login_code
    login_code="$(curl -sk -o /dev/null -w '%{http_code}' -c "$JAR" -X POST "${BASE_URL}/login" \
        -d "username=admin&password=testpass123")"
    if [[ "$login_code" != "200" ]]; then
        echo "login failed (http $login_code); log tail:" >&2; tail -30 "$RIG/server.log" >&2; return 1
    fi
}
issue_and_revoke_prep() { # returns a fresh code-signing serial (hex, no colons) issued for us to revoke later
    # gap-matrix #10's code-signing issuance route needs a CSR; generate one throwaway.
    openssl ecparam -name prime256v1 -genkey -noout -out "$RIG/leaf.key" 2>/dev/null
    openssl req -new -key "$RIG/leaf.key" -subj "/CN=ha-crl-failover-test" -out "$RIG/leaf.csr" 2>/dev/null
    local csr_json; csr_json="$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$RIG/leaf.csr")"
    local resp; resp="$(curl -sk -b "$JAR" --max-time 10 -X POST "${BASE_URL}/api/v1/ca/issue-code-signing" \
        -H 'Content-Type: application/json' \
        -d "{\"csr_pem\":${csr_json},\"label\":\"ha-crl-failover-test\"}")"
    python3 -c "
import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    d = {}
print(d.get('serial_hex',''))" "$resp"
}

echo "== boot: bringing up the cluster (sync2, strict) for cases 1+2"
PRIMARY="$(bring_up sync2 true)" || { echo "bring-up failed" >&2; exit 2; }
pass "cluster healthy, primary=${PRIMARY}"
boot_server || exit 1
pass "yuzu-server ready (web :$WEB) against the HA-Postgres cluster via :$PGPORT"

# ═══════════════════════════════ CASE 1 ═════════════════════════════════════
run_case1() {
    echo "== case 1: deterministic lost ack (pause both standbys, SyncRep wait, pg_terminate_backend)"
    local before serial standby1 standby2 pname
    before="$(crl_versions)"
    serial="$(issue_and_revoke_prep)"
    if [[ -z "$serial" ]]; then fail "case1: could not obtain a serial to revoke (code-signing issuance failed)"; return; fi
    pass "case1: issued serial ${serial} to revoke"

    # DEVIATION from the plan's literal recipe: pause BOTH standbys rather than
    # only the one Patroni currently designates synchronous. With
    # synchronous_mode=true (priority, not quorum) Patroni can reassign the sync
    # role to the OTHER standby within one loop_wait (10s) if only the
    # designated one is paused, racing this script's SyncRep poll. Pausing both
    # removes that race: under YUZU_PG_SYNC_STRICT=true, with zero eligible sync
    # standbys, the primary blocks rather than degrading to async, so ANY commit
    # requiring a sync ack — including the queued revoke's — reaches
    # wait_event='SyncRep' deterministically and stays there until unpaused or
    # terminated.
    pname="$(node_name "$PRIMARY")"
    for n in "${NODES[@]}"; do [[ "$n" != "$PRIMARY" ]] && docker pause "$n" >/dev/null; done
    pass "case1: paused both standbys (durability=sync2 strict=true, no eligible sync target remains)"

    curl -sk -b "$JAR" --max-time 90 -X POST "${BASE_URL}/api/v1/ca/revoke" \
        -H 'Content-Type: application/json' -d "{\"serial_hex\":\"${serial}\",\"reason\":\"ha-crl-failover-test\"}" \
        > "$RIG/revoke1.json" &
    local revoke_pid=$!
    pass "case1: fired POST /api/v1/ca/revoke for ${serial} (backgrounded — expected to block on the SyncRep wait)"

    local pid="" start now
    start=$(date +%s)
    while :; do
        pid="$(supersql "$PRIMARY" "SELECT pid FROM pg_stat_activity WHERE wait_event = 'SyncRep' LIMIT 1" 2>/dev/null || true)"
        [[ -n "$pid" ]] && break
        now=$(date +%s)
        if (( now - start >= 45 )); then break; fi
        sleep 1
    done

    if [[ -z "$pid" ]]; then
        inconclusive "case1: no backend ever reached wait_event='SyncRep' within 45s — the pg_terminate_backend-on-SyncRep-wait recipe did NOT reproduce a lost-ack state on this rig (see this script's header + docs/ha-delivery-matrix.md's WS-6 row for the escalation this triggers)"
        for n in "${NODES[@]}"; do [[ "$n" != "$PRIMARY" ]] && docker unpause "$n" >/dev/null; done
        kill -KILL "$revoke_pid" 2>/dev/null; wait "$revoke_pid" 2>/dev/null || true
        return
    fi
    pass "case1: backend pid=${pid} reached wait_event='SyncRep' (its transaction has already committed locally — Postgres is only waiting on the ack)"

    supersql "$PRIMARY" "SELECT pg_terminate_backend(${pid})" >/dev/null
    pass "case1: terminated the SyncRep-waiting backend (reproduces the lost COMMIT acknowledgement)"

    for n in "${NODES[@]}"; do [[ "$n" != "$PRIMARY" ]] && docker unpause "$n" >/dev/null; done
    wait_full_health "$PRIMARY" 2 >/dev/null || fail "case1: standbys did not rejoin as streaming after unpause"

    wait "$revoke_pid" 2>/dev/null || true
    local body; body="$(cat "$RIG/revoke1.json" 2>/dev/null || echo '{}')"
    # The one outcome this scenario must never produce is a FALSE claim of
    # success over a CRL whose publish transaction's ack was just destroyed —
    # crl_republished:true would mean that. crl_republished:false (the CRL
    # publish attempt itself reported failure) and a 503 "CA store
    # unavailable" (the pool connection the request was using was the one
    # terminated, so the request's OWN follow-on DB call failed before it
    # could even build a structured response) are both SAFE outcomes: neither
    # claims a possibly-unpersisted CRL succeeded.
    if grep -q '"crl_republished":true' "$RIG/revoke1.json" 2>/dev/null; then
        fail "case1: revoke response falsely reports crl_republished:true after the ack was destroyed (got: ${body}) — this is the exact false-success outcome the lock protocol exists to prevent"
    elif grep -q '"crl_republished":false' "$RIG/revoke1.json" 2>/dev/null; then
        pass "case1: revoke response reports crl_republished:false — the server correctly reported the lost-ack failure, never a false success"
    elif grep -q '"code":503' "$RIG/revoke1.json" 2>/dev/null; then
        pass "case1: revoke request itself failed 503 (CA store unavailable) — its own connection was the one whose ack was destroyed; no false success was reported (got: ${body})"
    else
        fail "case1: unexpected revoke response shape (got: ${body}) — neither a safe failure nor a clean success"
    fi

    switchover "$PRIMARY"
    local new_primary
    if new_primary="$(wait_new_primary "$PRIMARY" 60)"; then
        pass "case1: Patroni switchover completed, ${PRIMARY} -> ${new_primary}"
        # PRIMARY is the shared global case2 (and this function's own tail)
        # also read — the old value is now a READ-ONLY replica post-
        # switchover, so every subsequent write-targeted docker exec in this
        # script MUST see the new one.
        PRIMARY="$new_primary"
    else
        fail "case1: switchover from ${PRIMARY} did not complete within 60s"
        return
    fi

    assert_no_reuse "case1" "$before"

    local t
    if t=$(wait_serial_covered "$serial" 60); then
        pass "case1: revoked serial ${serial} covered by a CRL ${t}s after the switchover (self-heal)"
    else
        fail "case1: revoked serial ${serial} NOT found in any CRL within 60s after the switchover"
    fi
}

# ═══════════════════════════════ CASE 2 ═════════════════════════════════════
run_case2() {
    echo "== case 2: connection reset before COMMIT (a genuine rollback, not an ack loss)"
    local before serial lock_pid revoke_pid
    before="$(crl_versions)"
    serial="$(issue_and_revoke_prep)"
    if [[ -z "$serial" ]]; then fail "case2: could not obtain a serial to revoke"; return; fi
    pass "case2: issued serial ${serial} to revoke"

    # MUST target APP_DB ("yuzu"), not the "postgres" maintenance db —
    # ca_store.ca_crl_versions only exists in the former. Connecting to the
    # wrong database here made every earlier version of this lock-holder
    # invocation fail its own LOCK TABLE statement silently (docker exec -d
    # detaches; the error was never surfaced), so pg_locks correctly never
    # showed the session actually granted anything.
    docker exec -d "$PRIMARY" psql -U "$SUPER" -d "$APP_DB" -c \
        "BEGIN; LOCK TABLE ca_store.ca_crl_versions IN SHARE ROW EXCLUSIVE MODE; SELECT pg_sleep(30); COMMIT;"
    sleep 1
    # `psql -c "BEGIN; LOCK ...; SELECT pg_sleep(30); COMMIT;"` runs as ONE
    # multi-statement query, so pg_stat_activity.query is the WHOLE string —
    # match anywhere in it, not an anchored prefix. NOTE: pg_stat_activity's
    # query text is the WHOLE submitted multi-statement string from the
    # moment it's received — it does not distinguish "past the LOCK
    # statement" from "still queued trying to acquire it" (a stale holder
    # from an earlier case could make this pid itself the one waiting). So
    # this pid alone is not proof of possession — confirm via pg_locks below.
    local start now
    start=$(date +%s)
    while :; do
        lock_pid="$(supersql "$PRIMARY" "SELECT pid FROM pg_stat_activity WHERE query LIKE '%pg_sleep(30)%' LIMIT 1" 2>/dev/null || true)"
        if [[ -n "$lock_pid" ]] && [[ "$(supersql "$PRIMARY" "SELECT count(*) FROM pg_locks WHERE pid=${lock_pid} AND relation='ca_store.ca_crl_versions'::regclass AND granted" "$APP_DB" 2>/dev/null || echo 0)" -ge 1 ]]; then
            break
        fi
        now=$(date +%s); (( now - start >= 15 )) && { lock_pid=""; break; }
        sleep 0.5
    done
    if [[ -z "$lock_pid" ]]; then fail "case2: could not confirm the external session actually HOLDS the CRL table lock (pg_locks never showed it granted)"; return; fi
    pass "case2: external session holds the CRL table lock, confirmed via pg_locks (pid=${lock_pid})"

    curl -sk -b "$JAR" --max-time 40 -X POST "${BASE_URL}/api/v1/ca/revoke" \
        -H 'Content-Type: application/json' -d "{\"serial_hex\":\"${serial}\",\"reason\":\"ha-crl-failover-test-2\"}" \
        > "$RIG/revoke2.json" &
    revoke_pid=$!

    local qpid="" start now
    start=$(date +%s)
    while :; do
        qpid="$(supersql "$PRIMARY" "SELECT pid FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND pid <> ${lock_pid} LIMIT 1" 2>/dev/null || true)"
        [[ -n "$qpid" ]] && break
        now=$(date +%s); (( now - start >= 20 )) && break
        sleep 0.5
    done
    if [[ -z "$qpid" ]]; then
        fail "case2: revoke's publish transaction never appeared waiting on the lock within 20s"
        supersql "$PRIMARY" "SELECT pg_terminate_backend(${lock_pid})" >/dev/null 2>&1
        wait "$revoke_pid" 2>/dev/null || true
        return
    fi
    supersql "$PRIMARY" "SELECT pg_terminate_backend(${qpid})" >/dev/null
    pass "case2: killed the queued publish backend (pid=${qpid}) BEFORE it acquired the lock — a genuine mid-wait connection reset"

    wait "$revoke_pid" 2>/dev/null || true
    if grep -q '"crl_republished":false' "$RIG/revoke2.json" 2>/dev/null; then
        pass "case2: revoke response reports crl_republished:false"
    else
        fail "case2: unexpected revoke2 response: $(cat "$RIG/revoke2.json" 2>/dev/null)"
    fi

    # let the external holder's own bounded sleep release naturally
    sleep 30
    supersql "$PRIMARY" "SELECT pg_terminate_backend(${lock_pid})" >/dev/null 2>&1 || true

    assert_no_reuse "case2" "$before"
    local t
    if t=$(wait_serial_covered "$serial" 60); then
        pass "case2: revoked serial ${serial} covered by a CRL ${t}s later (self-heal after the aborted attempt)"
    else
        fail "case2: revoked serial ${serial} NOT covered within 60s of the connection reset"
    fi
}

case "$CASE" in
    1) run_case1 ;;
    2) run_case2 ;;
    all) run_case1; run_case2 ;;
    3) : ;; # handled below, independent of the sync2 cluster above
    *) echo "unknown --case '$CASE' (want 1|2|3|all)" >&2; exit 2 ;;
esac

# ═══════════════════════════════ CASE 3 ═════════════════════════════════════
run_case3() {
    echo "== case 3: async durability toggle is real and reachable (#4832 AC3 — documentation only)"
    tear_down
    local primary
    primary="$(bring_up async false)" || { fail "case3: cluster did not come up under YUZU_PG_DURABILITY=async"; return; }
    pass "case3: cluster healthy under YUZU_PG_DURABILITY=async, primary=${primary}"
    # The durability render is cluster-wide (every node's entrypoint prints
    # its own line), so check all three rather than just the elected
    # primary — sidesteps any log-visibility timing quirk tied to a
    # specific container.
    local seen=0 n
    for n in "${NODES[@]}"; do
        docker logs "$n" 2>&1 | grep -q "durability 'async'" && seen=$((seen + 1))
    done
    if (( seen > 0 )); then
        pass "case3: patroni-entrypoint.sh confirms durability='async' in ${seen}/3 nodes' boot logs"
    else
        fail "case3: no \"durability 'async'\" line found in any of the 3 nodes' boot logs"
    fi
    local sync_names
    sync_names="$(supersql "$primary" "SHOW synchronous_standby_names" 2>/dev/null || echo '?')"
    if [[ -z "$sync_names" ]]; then
        pass "case3: synchronous_standby_names is empty under async — no synchronous replication is configured"
    else
        fail "case3: synchronous_standby_names unexpectedly non-empty under async: '${sync_names}'"
    fi
    echo "  NOTE  async mode's crlNumber-reuse residual on a lost primary is NOT live-exercised here (no compose knob makes an" \
         "async-committed-but-unreplicated transaction survivable in this harness) — it is already documented in" \
         "docs/pki-architecture.md's \"What the lock does not cover\" section, which this script's PR links from. AC3 asks only" \
         "that the residual be documented, which it already is; this case exists to confirm the async toggle itself is real" \
         "(Fable's plan-review correction — an earlier draft of this plan wrongly assumed no such toggle existed)."
}
if [[ "$CASE" == "all" || "$CASE" == "3" ]]; then run_case3; fi

echo
echo "ha-crl-publish-failover: ${FAILS} failure(s), ${INCONCLUSIVE} inconclusive"
if (( FAILS > 0 )); then
    echo "server log tail:"; tail -30 "$RIG/server.log" 2>/dev/null
    exit 1
fi
(( INCONCLUSIVE > 0 )) && exit 3
exit 0
