#!/usr/bin/env bash
# ha-enrollment-concurrent-register.sh — WS-9 scenario for HA WS-6 slice 6.2
# (ADR-2002 §8, docs/ha-delivery-matrix.md WS-9 row).
#
# WS-6 6.2 moved enrollment tokens + pending-agent approvals off per-replica
# .cfg files and into Postgres (auth.enrollment_tokens / auth.pending_agents),
# specifically so every server replica shares one authoritative view. This is
# the WS-9 evidence that the claim actually holds ACROSS PROCESSES, not just
# across connections in one process (commit 2's Catch2 race tests already
# proved the latter — same-process, N threads, N pooled connections; this
# proves the former, the shape an actual second replica takes): two REAL,
# SEPARATE `yuzu-server` OS processes, sharing nothing but one Postgres
# database, race concurrent Register RPCs presenting the SAME max_uses=1
# enrollment token — exactly one is accepted, the rest get the uniform
# rejection, and Postgres itself shows use_count=1, never 2, never 0.
#
# Sequencing matters: node 1 boots ALONE first and fully migrates the schema,
# THEN node 2 joins the ALREADY-migrated database — booting both at once
# against a brand-new, empty database races AuthDB's (and every other store's)
# own migration runner and fails closed with "schema already contains tables"
# (measured empirically writing this script — a real defect this ordering
# avoids, not a hypothetical one). This mirrors how a genuine second replica
# always joins a running fleet, never a schema race with the first.
#
# Requires: docker, curl, python3, openssl, grpcurl (github.com/fullstorydev/
# grpcurl) and a built yuzu-server. grpcurl is NOT a repo-standard dependency —
# unlike every other tool this script needs, it is not guaranteed present on
# every dev box or CI runner, so its absence is a SKIP (exit 0), not a FAIL,
# matching this directory's `docker_available`-style graceful-skip convention
# (test-upgrade-stack.sh). The server has no gRPC reflection service
# registered, so grpcurl is driven off this repo's own .proto sources
# (-import-path proto -proto yuzu/agent/v1/agent.proto) rather than reflection.
#
# Ports and container/database names are salted per run — the self-hosted CI
# runners share one OS identity across four runner agents (#1871). Manual
# today, like every other scripts/ha/ harness (no workflow runs it) — see the
# WS-9 row in docs/ha-delivery-matrix.md.
#
# usage: ha-enrollment-concurrent-register.sh [--server-bin PATH] [--racers N]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"
if [[ "$(uname -s)" == "Darwin" ]]; then BUILD_DIR=build-macos; else BUILD_DIR=build-linux; fi
SERVER_BIN="${YUZU_ROOT}/${BUILD_DIR}/server/core/yuzu-server"
PG_IMAGE="${YUZU_HA_ENROLL_PG_IMAGE:-postgres:18.4-bookworm@sha256:efef99e1558f86089bc84bece29208c0777a185ff717ec7fa288a652ce2d0adf}"
RACERS=8   # concurrent Register attempts, split evenly across the two nodes

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        --racers)     RACERS="$2"; shift 2 ;;
        -h|--help)    sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -x "$SERVER_BIN" ]] || { echo "no server binary at $SERVER_BIN — build it, or pass --server-bin" >&2; exit 2; }
[[ "$RACERS" =~ ^[0-9]+$ && "$RACERS" -ge 2 ]] || { echo "--racers must be an integer >= 2 (got '$RACERS')" >&2; exit 2; }

if ! command -v docker >/dev/null 2>&1; then
    echo "ha-enrollment-concurrent-register: docker not available — SKIP" >&2
    exit 0
fi
GRPCURL="$(command -v grpcurl || true)"
if [[ -z "$GRPCURL" ]]; then
    echo "ha-enrollment-concurrent-register: grpcurl not on PATH — SKIP (see the file header: this is an optional, non-repo-standard dependency, not a failure)" >&2
    exit 0
fi

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
WEB1="$(free_port)"; GRPC1="$(free_port)"; MGMT1="$(free_port)"
WEB2="$(free_port)"; GRPC2="$(free_port)"; MGMT2="$(free_port)"
PGPORT="$(free_port)"

RIG="$(mktemp -d -t yuzu_ha_enroll.XXXXXX)"
mkdir -p "$RIG/n1" "$RIG/n2" "$RIG/certs"
# ca-dir is SHARED between the two nodes (never per-node): the secrets KEK
# private-key material lives in files under --ca-dir, while auth.secrets.
# kek_meta in the shared database only stores a WRAPPED reference to it — this
# mirrors production HA, where every replica points --ca-dir at the same
# shared/replicated volume. A per-node --ca-dir was tried first and found to
# fail closed exactly as designed: node 2 could not resolve node 1's KEK
# ("registered KEK ... does not resolve through the KekProvider" /
# ADR-0010 §2) — the correct behaviour for that misconfiguration, not a bug
# this script works around.
SALT="$$-$RANDOM"
PG="yuzu-ha-enroll-pg-$SALT"
PG_PASS="$(openssl rand -hex 24)"
N1_PID=""
N2_PID=""
FAILS=0

cleanup() {
    [[ -n "$N1_PID" ]] && kill -KILL "$N1_PID" 2>/dev/null
    [[ -n "$N2_PID" ]] && kill -KILL "$N2_PID" 2>/dev/null
    docker rm -f "$PG" >/dev/null 2>&1
    rm -rf "$RIG"
}
trap cleanup EXIT

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }

wait_ready() { # <web-port> <timeout-s>
    local port="$1" limit="$2" start now
    start=$(date +%s)
    while :; do
        if curl -sf --max-time 2 "http://127.0.0.1:${port}/readyz" 2>/dev/null | grep -q '"ready"'; then
            return 0
        fi
        now=$(date +%s)
        (( now - start >= limit )) && return 1
        sleep 0.5
    done
}

echo "== starting throwaway Postgres ($PG :$PGPORT)"
docker run -d --name "$PG" -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB=yuzu \
    -p "127.0.0.1:$PGPORT:5432" "$PG_IMAGE" -c fsync=off >/dev/null || { echo "postgres did not start" >&2; exit 2; }
for _ in $(seq 1 60); do
    docker exec "$PG" pg_isready -h 127.0.0.1 -U yuzu -d yuzu >/dev/null 2>&1 && break
    sleep 1
done
DSN="postgresql://yuzu:${PG_PASS}@127.0.0.1:${PGPORT}/yuzu"

python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'testpass123', salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')" > "$RIG/n1/yuzu-server.cfg"
cp "$RIG/n1/yuzu-server.cfg" "$RIG/n2/yuzu-server.cfg"
chmod 600 "$RIG/n1/yuzu-server.cfg" "$RIG/n2/yuzu-server.cfg"

boot() { # <data-dir> <web-port> <grpc-port> <mgmt-port> <log-file>
    "$SERVER_BIN" --listen "127.0.0.1:$3" --no-tls --no-https --no-default-certs \
        --web-address 127.0.0.1 --web-port "$2" --management "127.0.0.1:$4" \
        --postgres-dsn "$DSN" --config "$1/yuzu-server.cfg" --data-dir "$1" \
        --ca-dir "$RIG/certs" >> "$5" 2>&1 &
    echo $!
}

echo "== node 1: booting alone (must fully migrate before node 2 joins)"
N1_PID=$(boot "$RIG/n1" "$WEB1" "$GRPC1" "$MGMT1" "$RIG/n1/server.log")
if ! wait_ready "$WEB1" 60; then
    echo "node 1 never became ready" >&2; tail -30 "$RIG/n1/server.log" >&2; exit 1
fi
pass "node 1 ready (web :$WEB1, grpc :$GRPC1)"

echo "== node 2: joining the already-migrated database"
N2_PID=$(boot "$RIG/n2" "$WEB2" "$GRPC2" "$MGMT2" "$RIG/n2/server.log")
if ! wait_ready "$WEB2" 60; then
    echo "node 2 never became ready" >&2; tail -30 "$RIG/n2/server.log" >&2; exit 1
fi
pass "node 2 ready (web :$WEB2, grpc :$GRPC2)"

echo "== minting a max_uses=1 enrollment token via node 1's --generate-tokens"
# The stdout of --generate-tokens can carry interleaved log lines ahead of its
# JSON (a pre-existing, separately-tracked defect — see the WS-6 6.2 commit-6
# report; NOT fixed here, deliberately out of scope for this script) — scan
# for the balanced {...} object by brace depth rather than assuming a clean
# stream, same technique tests/shell/test_generate_tokens.sh uses.
GEN_OUT=$("$SERVER_BIN" --postgres-dsn "$DSN" --config "$RIG/n1/yuzu-server.cfg" --data-dir "$RIG/n1" \
    --ca-dir "$RIG/certs" --generate-tokens 1 --token-max-uses 1 --token-label "ws9-race-$SALT" \
    2>"$RIG/gen.log")
TOKEN=$(printf '%s' "$GEN_OUT" | python3 -c '
import sys, json
s = sys.stdin.read()
start = s.find("{")
depth = 0
end = -1
for i in range(start, len(s)):
    if s[i] == "{":
        depth += 1
    elif s[i] == "}":
        depth -= 1
        if depth == 0:
            end = i
            break
d = json.loads(s[start:end + 1])
print(d["tokens"][0])
' 2>/dev/null)
if [[ -z "$TOKEN" || ! "$TOKEN" =~ ^[0-9a-f]{64}$ ]]; then
    echo "could not mint/parse the enrollment token (see $RIG/gen.log)" >&2
    exit 1
fi
pass "token minted (sha256 prefix $(echo -n "$TOKEN" | sha256sum | cut -c1-8)...)"

echo "== firing $RACERS concurrent Register attempts across both nodes"
PROTO_ROOT="$YUZU_ROOT/proto"
declare -a PIDS=()
for i in $(seq 1 "$RACERS"); do
    ADDR="127.0.0.1:$GRPC1"
    (( i % 2 == 0 )) && ADDR="127.0.0.1:$GRPC2"
    (
        "$GRPCURL" -plaintext -import-path "$PROTO_ROOT" -proto yuzu/agent/v1/agent.proto \
            -d "{\"info\":{\"agent_id\":\"ws9-race-agent-$i\",\"hostname\":\"h$i\",\"platform\":{\"os\":\"linux\",\"arch\":\"x86_64\"},\"agent_version\":\"1\"},\"enrollment_token\":\"$TOKEN\"}" \
            "$ADDR" yuzu.agent.v1.AgentService/Register > "$RIG/reg_$i.json" 2>"$RIG/reg_$i.err"
    ) &
    PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p"; done

ACCEPTED=0
REJECTED=0
OTHER=0
for i in $(seq 1 "$RACERS"); do
    if grep -q '"accepted": true' "$RIG/reg_$i.json" 2>/dev/null; then
        ACCEPTED=$((ACCEPTED + 1))
    elif grep -q 'invalid, expired, or exhausted enrollment token' "$RIG/reg_$i.json" 2>/dev/null; then
        REJECTED=$((REJECTED + 1))
    else
        OTHER=$((OTHER + 1))
        echo "    unexpected response for racer $i: $(cat "$RIG/reg_$i.json" 2>/dev/null) $(cat "$RIG/reg_$i.err" 2>/dev/null)" >&2
    fi
done

if (( ACCEPTED == 1 )); then
    pass "exactly one Register was accepted ($ACCEPTED of $RACERS)"
else
    fail "expected exactly 1 accepted, got $ACCEPTED (never a double-accept, never zero) — this is the WS-9 claim this script exists to prove"
fi
if (( REJECTED == RACERS - 1 )); then
    pass "every other Register got the uniform rejection ($REJECTED of $RACERS)"
else
    fail "expected $((RACERS - 1)) uniform rejections, got $REJECTED (and $OTHER unexpected responses)"
fi
(( OTHER == 0 )) || fail "$OTHER racer(s) got neither accepted nor the uniform rejection — see stderr above"

echo "== cross-checking against Postgres directly (independent of grpcurl's JSON)"
USE_COUNT=$(docker exec "$PG" psql -U yuzu -d yuzu -tAc "SELECT use_count FROM auth.enrollment_tokens WHERE label='ws9-race-$SALT-1'" | tr -d ' ')
PENDING_COUNT=$(docker exec "$PG" psql -U yuzu -d yuzu -tAc "SELECT count(*) FROM auth.pending_agents WHERE agent_id LIKE 'ws9-race-agent-%' AND status='approved'" | tr -d ' ')
if [[ "$USE_COUNT" == "1" ]]; then
    pass "Postgres use_count=1 (not 2, not 0) — the shared row genuinely serialised across two OS processes"
else
    fail "Postgres use_count=$USE_COUNT (want exactly 1)"
fi
if [[ "$PENDING_COUNT" == "1" ]]; then
    pass "exactly one agent landed in auth.pending_agents as approved"
else
    fail "auth.pending_agents has $PENDING_COUNT approved race-agent rows (want exactly 1)"
fi

echo
if (( FAILS == 0 )); then
    echo "ha-enrollment-concurrent-register: ALL PASS"
    exit 0
fi
echo "ha-enrollment-concurrent-register: $FAILS FAILURE(S)"
echo "-- node 1 log tail --"; tail -30 "$RIG/n1/server.log"
echo "-- node 2 log tail --"; tail -30 "$RIG/n2/server.log"
exit 1
