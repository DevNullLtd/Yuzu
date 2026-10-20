#!/usr/bin/env bash
# csrf-proxy-e2e.sh - prove that cookie-session writes require a same-site Origin
# or Referer, including behind a reverse proxy that rewrites Host (#2537).
#
# WHY THIS EXISTS AS AN E2E AND NOT A UNIT TEST
#
# #2537 was a "works on the developer's laptop, 403s at the customer" defect:
# every CSRF-gated dashboard action failed behind nginx/Envoy/ALB, and nothing
# in the unit suite could see it. It cannot be caught at the unit layer for a
# structural reason - `TestRouteSink` mirrors a route HANDLER, not the
# pre/post-routing pipeline in front of it, so a unit test reaches the gate by a
# path no real request takes. This script drives a REAL server over a REAL
# socket instead.
#
# The gate observes only headers, so curl setting Host + Origin presents exactly
# what a Host-rewriting proxy presents. Standing up nginx would add a moving
# part without changing a single byte the server sees.
#
# THE ASSERTIONS ARE EXACT. Every probe is classified from the HTTP status AND
# the parsed body, into one of:
#
#   CENTRAL-REFUSED  403 whose JSON body is the pre-routing gate's error envelope
#                    (message, remediation, correlation id, and NO permission
#                    field), with an X-Correlation-Id header
#   TWIN-REFUSED     403 with the dashboard handler's own HTML refusal text
#   HANDLER-<code>   any other status: the request reached a route handler
#   TRANSPORT-ERROR  curl failed, or no HTTP status came back
#
# A 403 that is not CENTRAL-REFUSED is therefore never mistaken for the gate, and
# a transport error is never mistaken for a handler answer: it FAILS the check.
#
# FOUR HARNESS TRAPS, ALL MEASURED, ALL LOAD-BEARING - do not "simplify" these:
#
#   1. The session cookie is sent as an EXPLICIT header. curl's cookie jar keys
#      on the URL host and silently stops sending the cookie once Host is
#      overridden, which surfaces as a 401 that reads convincingly like a
#      server-side Host allowlist. It is not one.
#   2. boot() WAITS for the previous listener to disappear before starting the
#      next. Without that wait the next probes can hit the PREVIOUS server, and
#      the with-flag cases silently test the without-flag binary.
#   3. --ca-dir must point somewhere writable. The secrets-KEK fail-closed tries
#      /etc/yuzu/certs and refuses to boot as a non-root user (#2582).
#   4. EVERY probe carries Host: $PROXIED, the rewritten backend Host. That is the
#      point of the exercise. The only probes whose Origin host equals that Host
#      are the labelled positive controls; a negative case must never match it.
#
# PORTS: every listener (web, agent gRPC, management, Postgres) is an ephemeral
# high port picked at start, so this never collides with a rig on the default
# ports (see docs/uat-environment.md). Override with --web-port / --pg-port.
#
# Requires: docker, curl, python3, openssl, a built yuzu-server, and the
# yuzu-postgres image. Exits 0 only when every check behaves as specified.
#
# usage: csrf-proxy-e2e.sh [--server-bin PATH] [--web-port N] [--pg-port N]
#        --server-bin defaults to build-linux/server/core/yuzu-server (the Linux build dir)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

SERVER_BIN="${YUZU_ROOT}/build-linux/server/core/yuzu-server"
WEB=0; PGPORT=0; GRPC=0; MGMT=0
PG_IMAGE="${YUZU_CSRF_E2E_PG_IMAGE:-yuzu-postgres:local}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        --web-port)   WEB="$2"; shift 2 ;;
        --pg-port)    PGPORT="$2"; shift 2 ;;
        -h|--help)    sed -n '2,55p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "no server binary at $SERVER_BIN - build it, or pass --server-bin" >&2
    exit 2
fi
if ! docker image inspect "$PG_IMAGE" >/dev/null 2>&1; then
    echo "postgres image $PG_IMAGE not present - build deploy/docker/Dockerfile.postgres" >&2
    exit 2
fi

free_port() { # prints a currently-free ephemeral TCP port on loopback
    python3 -I -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}
[[ "$WEB" == 0 ]]    && WEB="$(free_port)"
[[ "$PGPORT" == 0 ]] && PGPORT="$(free_port)"
GRPC="$(free_port)"
MGMT="$(free_port)"
for p in "$WEB" "$GRPC" "$MGMT" "$PGPORT"; do
    # Never bind a default rig port; those belong to a long-lived stack.
    case "$p" in
        8080|8443|50051|50052|50055|9568) echo "refusing to use rig port $p" >&2; exit 2 ;;
    esac
done

RIG="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_csrf_e2e.XXXXXX")" || exit 2
PG="yuzu-csrf-e2e-pg-$$"
EXT="https://yuzu.customer.example"   # what the browser sends
PROXIED="yuzu-server:8080"            # what the proxy substitutes as Host
BASE="http://127.0.0.1:${WEB}"
SERVER_PID=""

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        SERVER_PID=""
    fi
}

cleanup() {
    stop_server
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

python3 -I -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/yuzu-server.cfg"
chmod 600 "$RIG/yuzu-server.cfg"

LOGTAG=x
COOKIE=""

boot() { # $@ = extra server flags
    stop_server
    # Trap 2: wait the OLD listener out. Skipping this makes probes hit the
    # previous server, which reports the previous configuration as the result.
    for _ in $(seq 1 30); do
        curl -sf "${BASE}/health" >/dev/null 2>&1 || break
        sleep 1
    done
    if curl -sf "${BASE}/health" >/dev/null 2>&1; then
        echo "  previous server still listening on :$WEB - refusing to run a misleading test" >&2
        return 1
    fi
    "$SERVER_BIN" --listen "127.0.0.1:${GRPC}" --no-tls --no-https --no-default-certs \
        --web-address 127.0.0.1 --web-port "$WEB" --management "127.0.0.1:${MGMT}" \
        --postgres-dsn "$DSN" --config "$RIG/yuzu-server.cfg" --data-dir "$RIG" \
        --ca-dir "$RIG/certs" "$@" > "$RIG/server-${LOGTAG}.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 60); do
        curl -sf "${BASE}/health" >/dev/null 2>&1 && return 0
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 1
    done
    echo "  server did not become ready; last lines:" >&2
    tail -5 "$RIG/server-${LOGTAG}.log" >&2
    return 1
}

login() {
    local jar="$RIG/cookies-${LOGTAG}.txt"
    rm -f "$jar"
    curl -s -c "$jar" -o /dev/null -X POST "${BASE}/login" \
        --data-urlencode "username=admin" --data-urlencode "password=testpass123"
    COOKIE="yuzu_session=$(awk '/yuzu_session/ {print $NF}' "$jar" | head -1)"
    [[ "$COOKIE" != "yuzu_session=" ]] || { echo "  login produced no session" >&2; return 1; }
}

# Does the body parse as the pre-routing gate's error envelope? Prints OK or WHY.
# Exact, not a substring match: the code, the message, a non-empty remediation and
# correlation id must all be present, and no `permission` field may be.
central_shape() { # $1 = body file
    python3 -I - "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))
except Exception as exc:
    print("not-json:%s" % type(exc).__name__)
    sys.exit(0)
err = doc.get("error") if isinstance(doc, dict) else None
if not isinstance(err, dict):
    print("no-error-object")
elif err.get("code") != 403:
    print("code=%r" % (err.get("code"),))
elif err.get("message") != "cross-site request refused":
    print("message=%r" % (err.get("message"),))
elif not isinstance(err.get("remediation"), str) or not err.get("remediation"):
    print("no-remediation")
elif "permission" in err or "permission" in doc:
    print("has-permission-field")
elif not (err.get("correlation_id") or doc.get("correlation_id")):
    print("no-correlation-id")
else:
    print("OK")
PY
}

# Trap 1: explicit Cookie header, NOT -b/--cookie. Trap 4: Host is always the
# rewritten backend Host. "-" means "send no such header".
# Sets R_RC (curl exit), R_STATUS, R_KIND, R_WHY and leaves the body in $RIG/body.
probe() { # $1=method $2=path $3=Origin|- $4=Referer|- [$5=body]
    local method="$1" path="$2" origin="$3" referer="$4" data="${5:-}"
    local -a args
    args=(-s --max-time 10 -o "$RIG/body" -D "$RIG/headers" -w '%{http_code}'
          -X "$method" -H "Cookie: ${COOKIE}" -H "Host: ${PROXIED}")
    [[ "$origin" != "-" ]]  && args+=(-H "Origin: ${origin}")
    [[ "$referer" != "-" ]] && args+=(-H "Referer: ${referer}")
    [[ -n "$data" ]]        && args+=(-d "$data")
    rm -f "$RIG/body" "$RIG/headers"
    R_STATUS="$(curl "${args[@]}" "${BASE}${path}" 2>/dev/null)"
    R_RC=$?
    R_WHY=""
    if [[ $R_RC -ne 0 || ! "$R_STATUS" =~ ^[1-5][0-9][0-9]$ ]]; then
        R_KIND="TRANSPORT-ERROR"; R_WHY="curl exit ${R_RC}, status '${R_STATUS}'"
        return
    fi
    if [[ "$R_STATUS" == 403 ]]; then
        local shape
        shape="$(central_shape "$RIG/body")"
        if [[ "$shape" == OK ]]; then
            if grep -qi '^X-Correlation-Id:' "$RIG/headers"; then
                R_KIND="CENTRAL-REFUSED"
            else
                R_KIND="HANDLER-403"; R_WHY="gate body without X-Correlation-Id header"
            fi
        elif grep -q "Cross-origin request refused" "$RIG/body"; then
            R_KIND="TWIN-REFUSED"
        else
            R_KIND="HANDLER-403"; R_WHY="$shape"
        fi
        return
    fi
    R_KIND="HANDLER-${R_STATUS}"
}

fail=0; total=0
check() { # $1=label $2=got $3=want $4=meaning
    total=$((total + 1))
    if [[ "$2" == "$3" ]]; then
        printf '  PASS  %-44s %s\n' "$1" "$4"
    else
        printf '  FAIL  %-44s got %s, want %s\n' "$1" "$2" "$3"; fail=1
    fi
}
expect() { # $1=label $2=want-kind $3=meaning ; classifies the LAST probe()
    local got="$R_KIND"
    [[ -n "$R_WHY" ]] && got="${R_KIND} (${R_WHY})"
    if [[ "$R_KIND" == "$2" ]]; then got="$R_KIND"; fi
    check "$1" "$got" "$2" "$3"
}

# The route used for the proxy cases: a dashboard form POST authorised by the
# session cookie that keeps its own copy of the check. The unknown serial makes
# the handler answer 404 without changing any state, so HANDLER-404 means "the
# gate admitted this and the handler ran to completion".
WRITE_PATH="/api/settings/ca/revoke"
WRITE_BODY='serial_hex=deadbeef'
# A read-only path for the safe-method control.
READ_PATH="/api/v1/agents"
# The agent-facing protocol endpoint: refused by the same gate for any method.
MCP_PATH="/mcp/v1/"
MCP_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

log_has() { grep -q "$2" "$RIG/server-${1}.log"; }
# spdlog may flush a moment after the response; poll briefly before judging.
log_wait() { # $1=logtag $2=fixed string
    for _ in $(seq 1 10); do
        grep -qF "$2" "$RIG/server-${1}.log" && return 0
        sleep 1
    done
    return 1
}

common_cases() {
    probe POST "$WRITE_PATH" - - "$WRITE_BODY"
    expect "no Origin, no Referer" CENTRAL-REFUSED "header-less cookie write refused"
    probe POST "$WRITE_PATH" "https://evil.example" - "$WRITE_BODY"
    expect "foreign Origin" CENTRAL-REFUSED "another site is refused"
    probe POST "$WRITE_PATH" "null" - "$WRITE_BODY"
    expect "Origin: null" CENTRAL-REFUSED "opaque origin is refused"
    probe POST "$WRITE_PATH" - "https://evil.example/page" "$WRITE_BODY"
    expect "foreign Referer" CENTRAL-REFUSED "Referer is judged like Origin"
    probe POST "$WRITE_PATH" "http://${PROXIED}" - "$WRITE_BODY"
    expect "control: Origin matches rewritten Host" HANDLER-404 "same-site Origin is admitted"
    probe POST "$WRITE_PATH" - "http://${PROXIED}/page" "$WRITE_BODY"
    expect "control: Referer matches rewritten Host" HANDLER-404 "same-site Referer is admitted"
    probe DELETE "$MCP_PATH" - -
    expect "DELETE, no headers" CENTRAL-REFUSED "any non-safe method is gated"
    probe POST "$MCP_PATH" - - "$MCP_BODY"
    expect "JSON-RPC POST, no headers" CENTRAL-REFUSED "the JSON-RPC endpoint is gated too"
    probe POST "$MCP_PATH" - "http://${PROXIED}/" "$MCP_BODY"
    expect "control: JSON-RPC POST, same-site Referer" HANDLER-200 "gate admits, endpoint answers"
    probe GET "$READ_PATH" - -
    if [[ "$R_KIND" == CENTRAL-REFUSED || "$R_KIND" == TRANSPORT-ERROR ]]; then
        check "GET, no headers" "$R_KIND" "not CENTRAL-REFUSED" "safe methods are never gated"
    else
        check "GET, no headers" "not CENTRAL-REFUSED" "not CENTRAL-REFUSED" "safe methods are never gated"
    fi
    # A header line over httplib's 8192-byte cap is answered 400 by the HTTP
    # parser before pre-routing runs: this is NOT a gate decision, and the body
    # is not the gate's envelope.
    local big
    big="$(head -c 61440 /dev/zero | tr '\0' 'a')"
    probe POST "$WRITE_PATH" "$big" - "$WRITE_BODY"
    if [[ "$R_KIND" == "HANDLER-400" ]]; then
        check "oversized Origin (parser, not the gate)" "HANDLER-400" "HANDLER-400" "refused at header parsing"
    else
        check "oversized Origin (parser, not the gate)" "$R_KIND" "HANDLER-400" "refused at header parsing"
    fi
}

echo "== A: without --csrf-trusted-origin (must still refuse: this is #2537) =="
LOGTAG=noflag; boot || exit 1; login || exit 1
log_has noflag "CSRF same-site gate" || check "boot log names the gate" "absent" "present" "operator-visible"
probe POST "$WRITE_PATH" "$EXT" - "$WRITE_BODY"
expect "proxied browser POST" CENTRAL-REFUSED "reproduces the proxy symptom"
probe POST "$WRITE_PATH" - "${EXT}/page" "$WRITE_BODY"
expect "proxied browser Referer" CENTRAL-REFUSED "no flag, no relaxation"
common_cases
log_wait noflag "same-site gate refused" \
    && check "first refusal is logged" "present" "present" "warn names the flag" \
    || check "first refusal is logged" "absent" "present" "warn names the flag"

echo "== B: with --csrf-trusted-origin $EXT =="
LOGTAG=withflag; boot --csrf-trusted-origin "$EXT" || exit 1; login || exit 1
log_has withflag "CSRF same-site gate: accepting 1" \
    && check "boot log lists the accepted origin" "present" "present" "operator-visible" \
    || check "boot log lists the accepted origin" "absent" "present" "operator-visible"
probe POST "$WRITE_PATH" "$EXT" - "$WRITE_BODY"
expect "proxied browser POST" HANDLER-404 "the fix"
probe POST "$WRITE_PATH" - "${EXT}/page" "$WRITE_BODY"
expect "proxied browser Referer" HANDLER-404 "the fix covers Referer"
probe POST "$WRITE_PATH" "http://yuzu.customer.example" - "$WRITE_BODY"
expect "http:// vs https:// entry" CENTRAL-REFUSED "scheme is pinned"
probe POST "$WRITE_PATH" "https://yuzu.customer.example:8443" - "$WRITE_BODY"
expect "same host, other port" CENTRAL-REFUSED "port is pinned"
# The trusted origin satisfies the gate only. The endpoint keeps its own Origin
# allowlist, so this is a 403 from the ENDPOINT, never the gate's envelope.
probe POST "$MCP_PATH" "$EXT" - "$MCP_BODY"
expect "JSON-RPC POST, trusted Origin" HANDLER-403 "gate admits, endpoint allowlist refuses"
common_cases

if [[ $fail -eq 0 ]]; then
    echo "csrf-proxy-e2e: PASS (${total}/${total})"
else
    echo "csrf-proxy-e2e: FAIL" >&2
fi
exit $fail
