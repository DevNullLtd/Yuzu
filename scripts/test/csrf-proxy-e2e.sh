#!/usr/bin/env bash
# csrf-proxy-e2e.sh — prove the CSRF same-site gate behaves correctly behind a
# reverse proxy that rewrites Host (#2537).
#
# WHY THIS EXISTS AS AN E2E AND NOT A UNIT TEST
#
# #2537 was a "works on the developer's laptop, 403s at the customer" defect:
# every CSRF-gated dashboard action failed behind nginx/Envoy/ALB, and nothing
# in the unit suite could see it. It cannot be caught at the unit layer for a
# structural reason — `TestRouteSink` mirrors a route HANDLER, not the
# pre/post-routing pipeline in front of it, so a unit test reaches the gate by a
# path no real request takes. This script drives a REAL server over a REAL
# socket instead.
#
# The gate observes only headers, so curl setting Host + Origin presents exactly
# what a Host-rewriting proxy presents. Standing up nginx would add a moving
# part without changing a single byte the server sees.
#
# THREE HARNESS TRAPS, ALL MEASURED, ALL LOAD-BEARING — do not "simplify" these:
#
#   1. The session cookie is sent as an EXPLICIT header. curl's cookie jar keys
#      on the URL host and silently stops sending the cookie once Host is
#      overridden, which surfaces as a 401 that reads convincingly like a
#      server-side Host allowlist. It is not one.
#   2. boot() WAITS for the previous listener to disappear before starting the
#      next. Without that wait, `pkill` races the restart and every probe hits
#      the PREVIOUS server — the with-flag cases silently test the without-flag
#      binary and report the bug as unfixed.
#   3. --ca-dir must point somewhere writable. The secrets-KEK fail-closed tries
#      /etc/yuzu/certs and refuses to boot as a non-root user (#2582).
#
# Requires: docker, curl, python3, a built yuzu-server, and the yuzu-postgres
# image. Exits 0 only when all four cases behave as specified.
#
# usage: csrf-proxy-e2e.sh [--server-bin PATH] [--web-port N] [--pg-port N]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

SERVER_BIN="${YUZU_ROOT}/build-linux/server/core/yuzu-server"
WEB=8123; PGPORT=15499; GRPC=50099; MGMT=50100
PG_IMAGE="${YUZU_CSRF_E2E_PG_IMAGE:-yuzu-postgres:local}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        --web-port)   WEB="$2"; shift 2 ;;
        --pg-port)    PGPORT="$2"; shift 2 ;;
        -h|--help)    sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "no server binary at $SERVER_BIN — build it, or pass --server-bin" >&2
    exit 2
fi
if ! docker image inspect "$PG_IMAGE" >/dev/null 2>&1; then
    echo "postgres image $PG_IMAGE not present — build deploy/docker/Dockerfile.postgres" >&2
    exit 2
fi

RIG="$(mktemp -d -t yuzu_csrf_e2e.XXXXXX)"
PG="yuzu-csrf-e2e-pg-$$"
EXT="https://yuzu.customer.example"   # what the browser sends
PROXIED="yuzu-server:8080"            # what the proxy substitutes as Host

cleanup() {
    pkill -f "yuzu-server.*--web-port $WEB" 2>/dev/null
    docker rm -f "$PG" >/dev/null 2>&1
    rm -rf "$RIG"
}
trap cleanup EXIT

PG_APP="$(openssl rand -hex 24)"
docker run -d --name "$PG" -e POSTGRES_PASSWORD="$(openssl rand -hex 24)" \
    -e YUZU_DB_PASSWORD="$PG_APP" -p "127.0.0.1:${PGPORT}:5432" "$PG_IMAGE" >/dev/null || exit 2
for _ in $(seq 1 60); do
    docker exec -e PGPASSWORD="$PG_APP" "$PG" sh -c \
        'pg_isready -h 127.0.0.1 -U yuzu -d yuzu >/dev/null 2>&1' 2>/dev/null && break
    sleep 1
done
DSN="postgresql://yuzu:${PG_APP}@127.0.0.1:${PGPORT}/yuzu"

python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/yuzu-server.cfg"
chmod 600 "$RIG/yuzu-server.cfg"

LOGTAG=x
COOKIE=""

boot() { # $@ = extra server flags
    pkill -f "yuzu-server.*--web-port $WEB" 2>/dev/null
    # Trap 2: wait the OLD listener out. Skipping this makes every probe hit the
    # previous server, which reports the previous configuration as the result.
    for _ in $(seq 1 30); do
        curl -sf "http://127.0.0.1:${WEB}/health" >/dev/null 2>&1 || break
        sleep 1
    done
    if curl -sf "http://127.0.0.1:${WEB}/health" >/dev/null 2>&1; then
        echo "  previous server still listening on :$WEB — refusing to run a misleading test" >&2
        return 1
    fi
    "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
        --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
        --postgres-dsn "$DSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
        --ca-dir "$RIG/certs" "$@" > "$RIG/server-${LOGTAG}.log" 2>&1 &
    for _ in $(seq 1 60); do
        curl -sf "http://127.0.0.1:${WEB}/health" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "  server did not become ready; last lines:" >&2
    tail -5 "$RIG/server-${LOGTAG}.log" >&2
    return 1
}

login() {
    local jar="$RIG/cookies-${LOGTAG}.txt"
    rm -f "$jar"
    curl -s -c "$jar" -o /dev/null -X POST "http://127.0.0.1:${WEB}/login" \
        --data-urlencode "username=admin" --data-urlencode "password=testpass123"
    COOKIE="yuzu_session=$(awk '/yuzu_session/ {print $NF}' "$jar" | head -1)"
    [[ "$COOKIE" != "yuzu_session=" ]] || { echo "  login produced no session" >&2; return 1; }
}

# Trap 1: explicit Cookie header, NOT -b/--cookie.
probe() { # $1 = Origin header -> CSRF-REFUSED | REACHED-HANDLER
    local body
    body=$(curl -s -H "Cookie: ${COOKIE}" -H "Host: ${PROXIED}" -H "Origin: $1" \
        --max-time 10 -X POST "http://127.0.0.1:${WEB}/api/settings/ca/revoke" \
        -d 'serial=deadbeef' 2>/dev/null)
    if grep -qi "Cross-origin request refused" <<<"$body"; then
        echo "CSRF-REFUSED"
    else
        echo "REACHED-HANDLER"
    fi
}

fail=0
check() { # $1=label $2=got $3=want $4=meaning
    if [[ "$2" == "$3" ]]; then
        printf '  PASS  %-38s %s\n' "$1" "$4"
    else
        printf '  FAIL  %-38s got %s, want %s\n' "$1" "$2" "$3"; fail=1
    fi
}

echo "== A: without --csrf-trusted-origin (must still refuse: this is #2537) =="
LOGTAG=noflag; boot || exit 1; login || exit 1
check "proxied browser POST" "$(probe "$EXT")" "CSRF-REFUSED" "the defect, reproduced"

echo "== B-D: with --csrf-trusted-origin $EXT =="
LOGTAG=withflag; boot --csrf-trusted-origin "$EXT" || exit 1; login || exit 1
check "proxied browser POST" "$(probe "$EXT")" "REACHED-HANDLER" "the fix"
check "attacker Origin"      "$(probe "https://evil.example")" "CSRF-REFUSED" "allowlist is not a relaxation"
check "http:// vs https:// entry" "$(probe "http://yuzu.customer.example")" "CSRF-REFUSED" "scheme is pinned"

if [[ $fail -eq 0 ]]; then
    echo "csrf-proxy-e2e: PASS (4/4)"
else
    echo "csrf-proxy-e2e: FAIL" >&2
fi
exit $fail
