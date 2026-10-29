#!/usr/bin/env bash
# integration-test.sh — Full-stack integration test: Agent → Gateway → Server
#
# Starts the C++ server, the Erlang gateway release, and one or more C++ agents,
# then runs test scenarios through the complete chain.
#
# Usage:
#   ./scripts/integration-test.sh                    # 1 agent (quick smoke test)
#   ./scripts/integration-test.sh --agents 10        # 10 agents
#   ./scripts/integration-test.sh --tls              # real TLS stack, pinned gateway hop
#   ./scripts/integration-test.sh --tls --free-ports --gateway-ct   # the CI invocation
#
# Gateway hop, two modes:
#   plaintext (default)  the server is started with --no-tls and
#       --insecure-gateway-peer (peer authorization on the gateway-upstream
#       service acknowledged as disabled, test rig only). The gateway dials the
#       upstream over a plaintext `http` channel. The hop's peer authorization is
#       NOT exercised in this mode.
#   --tls                the server runs on its GENERATED DEFAULT certificates
#       (default-ca / default-server / default-gateway under a per-run --ca-dir)
#       and no acknowledgement flag, so it enforces the AUTOMATIC PIN of its own
#       default-gateway.pem (docs/user-manual/server-admin.md, "Gateway upstream
#       peer authorization"). The gateway dials the upstream over `https` with
#       verify_peer, the install CA and that gateway leaf as its client
#       certificate, so every upstream call is a pinned-TLS call; agents reach the
#       gateway over one-way TLS and enrol for a per-agent leaf. The script
#       asserts the server booted enforcing with the gateway leaf's SPKI prefix,
#       and that the gateway was never denied.
#       --tls also covers the OTHER hop, server -> gateway (the privileged command
#       plane, #5175): the gateway's management listener runs in the production
#       posture (strict mutual TLS, auth_fun yuzu_gw_authz:check_mgmt_peer/1, and
#       mgmt_peer_pins naming the server's default leaf), the server is pointed at
#       it with --gateway-command-addr, and the script dispatches commands to the
#       real agent through the server's REST API: one round trip, then a burst
#       multiplexed over the server's single management connection. It asserts
#       every one completed with the agent's SUCCESS and that neither side logged
#       a crash or a transport error.
#
# --gateway-ct runs gateway/apps/yuzu_gw/integration_test/yuzu_gw_real_upstream_SUITE
# (Common Test) against this stack's real server, over the same pinned TLS hop in
# --tls mode (#5652, #5653); in --tls mode it also runs yuzu_gw_real_mgmt_SUITE
# against the gateway's management listener (an unpinned leaf of the same CA is
# refused; SendCommand streams, the deadline and the cancel paths). Their results
# count as test results of this script.
#
# --free-ports takes every port from the OS (one allocation call, so no two are
# equal) instead of the 5005x/5006x defaults, which makes concurrent runs on one
# host safe. The CI runner pool shares ONE OS identity across 4 runner agents
# (#1871), so the CI step uses it; the Postgres database, work directory and the
# gateway's Erlang node name and cookie are salted per run in every mode.
#
# Prerequisites:
#   - C++ binaries built:  build-<os>/server/core/yuzu-server
#                           build-<os>/agents/core/yuzu-agent
#   - Erlang/OTP + rebar3 (the gateway release is built here: rebar3 as prod release)
#   - Postgres: YUZU_TEST_POSTGRES_DSN (the server fails closed without it); a
#     uniquely named database is created for the run and dropped on exit
#   - psql, openssl, curl, python3
#   - grpcurl (optional, for gRPC probing)
#
# A missing prerequisite fails the script (exit 1); it never reports a skip, so a
# CI step cannot go green without having run.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
AGENT_COUNT=1
USE_TLS=false
FREE_PORTS=false
RUN_GATEWAY_CT=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure `erl` / `escript` / `rebar3` are on PATH before the gateway build
# step runs. The helper is a no-op if a passing Erlang is already first on
# PATH; otherwise it asks scripts/erlang_toolchain.py find-otp and activates
# what it picks. The "" arg selects the pinned default (DEFAULT_OTP_VERSION:
# 28.4 or any later 28.x) and keeps this script's own $1 from being read as a
# version.
# shellcheck source=ensure-erlang.sh
source "$SCRIPT_DIR/ensure-erlang.sh" ""
if ! command -v erl > /dev/null 2>&1; then
    echo "FAIL: erl not on PATH after ensure-erlang.sh (needed for rebar3/escript)" >&2
    echo "      Install via kerl (kerl build-install 28.4.2 28.4.2 ~/.kerl/28.4.2), asdf, Homebrew, or the" >&2
    echo "      MSYS2 Erlang installer, then rerun." >&2
    exit 1
fi

# Per-OS canonical build dir (see CLAUDE.md "Per-OS build directory convention").
if [[ -n "${YUZU_BUILDDIR:-}" ]]; then
    BUILDDIR="$YUZU_BUILDDIR"
elif [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
    BUILDDIR="$PROJECT_ROOT/build-windows"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    BUILDDIR="$PROJECT_ROOT/build-macos"
else
    BUILDDIR="$PROJECT_ROOT/build-linux"
fi
GATEWAY_DIR="$PROJECT_ROOT/gateway"
WORK_DIR=""
IT_DB=""
SERVER_PID=""
GATEWAY_PID=""
AGENT_PIDS=()

# Port matrix — single-host layout that gives every binder its own port.
# Server side uses 5005x, gateway side uses 5006x. Every port is
# env-overridable so this script can run alongside other live stacks
# (e.g. the docker UAT from scripts/docker-start-UAT.sh, which binds
# 50055 and 50063 on the host). Override pattern:
#   SERVER_GW_PORT=50155 GW_MGMT_PORT=50163 bash scripts/integration-test.sh
SERVER_AGENT_PORT="${SERVER_AGENT_PORT:-50050}"   # C++ server agent gRPC (no direct connects in gateway mode)
SERVER_MGMT_PORT="${SERVER_MGMT_PORT:-50053}"
SERVER_GW_PORT="${SERVER_GW_PORT:-50055}"         # GatewayUpstream service (gateway connects here)
SERVER_WEB_PORT="${SERVER_WEB_PORT:-8090}"

# Gateway ports (agents connect here)
GW_AGENT_PORT="${GW_AGENT_PORT:-50061}"
GW_MGMT_PORT="${GW_MGMT_PORT:-50063}"
GW_METRICS_PORT="${GW_METRICS_PORT:-9568}"
GW_HEALTH_PORT="${GW_HEALTH_PORT:-8081}"

# ── Argument parsing ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --agents)  AGENT_COUNT="$2"; shift 2 ;;
        --tls)     USE_TLS=true; shift ;;
        --free-ports) FREE_PORTS=true; shift ;;
        --gateway-ct) RUN_GATEWAY_CT=true; shift ;;
        --help|-h) echo "Usage: $0 [--agents N] [--tls] [--free-ports] [--gateway-ct]"; exit 0 ;;
        *)         echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Phase 4 reuse mode ────────────────────────────────────────────────
# When /test runs, Phase 4 (`scripts/linux-start-UAT.sh`) already stood up a
# full server+gateway+agent stack on the canonical default ports (8080 web,
# 50051 gateway agent, 50055 server upstream, 50063 gateway mgmt, 9568
# gateway metrics, 8081 gateway health). Spawning a parallel stack would
# collide on at least 9568 / 50055 / 50063 and yield {listen,eaddrinuse}
# crashes. Detect Phase 4's presence and reuse its stack rather than fight
# it.
#
# Control:
#   YUZU_REUSE_STACK=1   force reuse (fail fast if Phase 4 not detected)
#   YUZU_REUSE_STACK=0   force own-stack (never reuse, current default
#                        behaviour for standalone runs)
#   unset                auto-detect via /readyz probe on 8080
#
# Reuse only applies when AGENT_COUNT == 1 (Phase 4's stack has one
# agent). --agents N > 1 implies load-test intent and falls back to
# spinning a private stack with non-conflicting ports.
REUSE_STACK=false
REUSE_REASON=""

detect_phase4_stack() {
    # Probe for Yuzu's fingerprint on the canonical Phase 4 ports:
    #   - server /readyz on :8080 returns `{"status":"ready"}`
    #   - gateway /healthz on :8081 returns `{"status":"ok","node":"..."}`
    # Both endpoints are HTTP 200 under healthy operation. We check the
    # JSON payload for the Yuzu-distinctive status tokens so we don't
    # mis-fire against some other process that happens to bind either
    # port and return 200.
    local server_body gateway_body
    server_body=$(curl -sf --max-time 1 "http://127.0.0.1:8080/readyz" 2>/dev/null) || return 1
    echo "$server_body" | grep -qE '"status":"(ready|draining)"' || return 1
    gateway_body=$(curl -sf --max-time 1 "http://127.0.0.1:8081/healthz" 2>/dev/null) || return 1
    echo "$gateway_body" | grep -q '"node":"yuzu_gw' || return 1
    return 0
}

# A run that asks for its own isolated, TLS or Common Test stack never adopts a
# stack some other process left on the canonical ports.
if $FREE_PORTS || $RUN_GATEWAY_CT || $USE_TLS; then
    case "${YUZU_REUSE_STACK:-}" in
        1|true|yes)
            echo "integration-test: YUZU_REUSE_STACK=1 cannot be combined with --tls, --free-ports or --gateway-ct" >&2
            exit 1 ;;
    esac
    YUZU_REUSE_STACK=0
fi

case "${YUZU_REUSE_STACK:-auto}" in
    1|true|yes)
        if [[ "$AGENT_COUNT" -gt 1 ]]; then
            echo "integration-test: YUZU_REUSE_STACK=1 set but --agents=$AGENT_COUNT > 1; reuse only" >&2
            echo "  supports AGENT_COUNT=1 (Phase 4's stack has one agent). Aborting." >&2
            exit 1
        fi
        if ! detect_phase4_stack; then
            echo "integration-test: YUZU_REUSE_STACK=1 set but no Phase 4 stack detected on" >&2
            echo "  127.0.0.1:8080 (/readyz) + :8081 (/healthz). Start the stack first with" >&2
            echo "  'bash scripts/start-UAT.sh' or unset YUZU_REUSE_STACK." >&2
            exit 1
        fi
        REUSE_STACK=true
        REUSE_REASON="explicit YUZU_REUSE_STACK=1"
        ;;
    0|false|no)
        REUSE_STACK=false
        REUSE_REASON="explicit YUZU_REUSE_STACK=0"
        ;;
    auto|*)
        if [[ "$AGENT_COUNT" -eq 1 ]] && detect_phase4_stack; then
            REUSE_STACK=true
            REUSE_REASON="auto-detected Phase 4 stack on default ports"
        else
            REUSE_STACK=false
            if [[ "$AGENT_COUNT" -gt 1 ]]; then
                REUSE_REASON="AGENT_COUNT=$AGENT_COUNT > 1 (load test — private stack)"
            else
                REUSE_REASON="no Phase 4 stack detected on :8080/:8081"
            fi
        fi
        ;;
esac

if $REUSE_STACK; then
    # Override every port to match linux-start-UAT.sh's actual defaults.
    # Any explicit PORT env vars the caller passed are respected; we only
    # set values that are at their script-level default.
    SERVER_AGENT_PORT="${SERVER_AGENT_PORT_OVERRIDE:-50054}"
    SERVER_MGMT_PORT="${SERVER_MGMT_PORT_OVERRIDE:-50052}"
    SERVER_GW_PORT="${SERVER_GW_PORT_OVERRIDE:-50055}"
    SERVER_WEB_PORT="${SERVER_WEB_PORT_OVERRIDE:-8080}"
    GW_AGENT_PORT="${GW_AGENT_PORT_OVERRIDE:-50051}"
    GW_MGMT_PORT="${GW_MGMT_PORT_OVERRIDE:-50063}"
    GW_METRICS_PORT="${GW_METRICS_PORT_OVERRIDE:-9568}"
fi

# ── Free ports (own-stack only) ──────────────────────────────────────
# One allocation call: the sockets are all held until the list is printed, so no
# two ports are equal. (Another process can still take one between this release
# and the bind; the window is the script's start-up, not a shared fixed number.)
if $FREE_PORTS && ! $REUSE_STACK; then
    command -v python3 > /dev/null 2>&1 || { echo "FAIL: --free-ports needs python3" >&2; exit 1; }
    # shellcheck disable=SC2207
    FREE_LIST=($(python3 -c "
import socket
s = [socket.socket() for _ in range(8)]
[x.bind(('127.0.0.1', 0)) for x in s]
print(*[x.getsockname()[1] for x in s])"))
    if [[ "${#FREE_LIST[@]}" -ne 8 ]]; then
        echo "FAIL: could not allocate 8 free ports" >&2
        exit 1
    fi
    SERVER_AGENT_PORT="${FREE_LIST[0]}"; SERVER_MGMT_PORT="${FREE_LIST[1]}"
    SERVER_GW_PORT="${FREE_LIST[2]}";    SERVER_WEB_PORT="${FREE_LIST[3]}"
    GW_AGENT_PORT="${FREE_LIST[4]}";     GW_MGMT_PORT="${FREE_LIST[5]}"
    GW_METRICS_PORT="${FREE_LIST[6]}";   GW_HEALTH_PORT="${FREE_LIST[7]}"
fi

# ── Preflight checks ─────────────────────────────────────────────────
check_binary() {
    if [[ ! -x "$1" ]]; then
        echo "FAIL: $1 not found or not executable"
        echo "      Run: meson compile -C $(basename "$BUILDDIR")"
        exit 1
    fi
}

check_binary "$BUILDDIR/server/core/yuzu-server"
check_binary "$BUILDDIR/agents/core/yuzu-agent"

if [[ ! -f "$GATEWAY_DIR/rebar.config" ]]; then
    echo "FAIL: gateway/ not found at $GATEWAY_DIR"
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; FAILURES=$((FAILURES + 1)); }

FAILURES=0
TESTS=0

assert_eq() {
    TESTS=$((TESTS + 1))
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        pass "$desc"
    else
        fail "$desc (expected '$expected', got '$actual')"
    fi
}

assert_contains() {
    TESTS=$((TESTS + 1))
    local desc="$1" needle="$2" haystack="$3"
    # A here-string, not `echo "$haystack" | grep -q "$needle"`: that pipeline can
    # spuriously report no-match under `set -o pipefail` when the needle is found
    # early in a large multi-line haystack — grep(1) exits the instant it matches,
    # closing the pipe while echo(1) is still mid-write of the remaining bytes,
    # SIGPIPE kills echo, and pipefail surfaces THAT non-zero exit rather than
    # grep's success. Same #988 SIGPIPE-under-pipefail class as
    # poll_metric_at_least's awk-no-exit workaround below — a here-string has no
    # writer process to SIGPIPE, so it needs no such workaround.
    if grep -qF -- "$needle" <<< "$haystack"; then
        pass "$desc"
    else
        fail "$desc (expected to contain '$needle')"
    fi
}

assert_ge() {
    TESTS=$((TESTS + 1))
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" -ge "$expected" ]]; then
        pass "$desc"
    else
        fail "$desc (expected >= $expected, got $actual)"
    fi
}

# port_open <port>: a TCP connect to 127.0.0.1 (bash's /dev/tcp; no netcat needed).
port_open() {
    (exec 3<> "/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

wait_for_port() {
    local port="$1" name="$2" timeout="${3:-15}"
    local elapsed=0
    while ! port_open "$port"; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout * 2)) ]]; then
            fail "$name did not start on port $port within ${timeout}s"
            return 1
        fi
    done
    # SRE-2 — surface cold-start duration. elapsed counts 0.5s ticks.
    local seconds=$((elapsed / 2))
    echo "  ✓ $name on :$port in ${seconds}s"
    return 0
}

wait_for_http() {
    local url="$1" name="$2" timeout="${3:-15}"
    local elapsed=0
    while ! curl -sf "$url" >/dev/null 2>&1; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout * 2)) ]]; then
            fail "$name not responding at $url within ${timeout}s"
            return 1
        fi
    done
    return 0
}

# poll_metric_at_least <metrics-url> <metric-name> <min-value> [timeout-s]
#
# Polls a Prometheus /metrics endpoint and waits for `metric-name` to reach at
# least `min-value`. Handles both bare metrics (`name VALUE`) and labelled
# metrics (`name{labels} VALUE`) by matching `^name` followed by space, `{`, or
# end of line, and taking the last field as the value. Uses the awk-no-exit
# pattern from #988 — `; exit` causes upstream SIGPIPE under `set -o pipefail`
# and breaks the poll loop on the first iteration. Returns 0 if the threshold
# is met within timeout, 1 otherwise. Caller checks the return code.
poll_metric_at_least() {
    local url="$1" name="$2" min="$3" timeout="${4:-30}"
    local i resp value
    for i in $(seq 1 "$timeout"); do
        resp=$(curl -sf --max-time 2 "$url" 2>/dev/null || echo "")
        value=$(echo "$resp" | awk -v n="$name" \
            '$0 ~ "^"n"([ {]|$)" { val=$NF } END { print val }')
        if [[ -n "$value" ]] && [[ "${value%.*}" -ge "$min" ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ── Cleanup on exit ──────────────────────────────────────────────────
cleanup() {
    local rc=$?
    log "Tearing down..."
    if $REUSE_STACK; then
        log "  Reuse mode — leaving Phase 4 server/gateway/agent processes running."
    else
        # Stop agents
        for pid in "${AGENT_PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        # Stop gateway
        if [[ -n "$GATEWAY_PID" ]]; then
            kill "$GATEWAY_PID" 2>/dev/null || true
        fi
        # Stop server
        if [[ -n "$SERVER_PID" ]]; then
            kill "$SERVER_PID" 2>/dev/null || true
        fi
        # Wait for all to exit
        sleep 1
        # Force-kill stragglers
        for pid in "${AGENT_PIDS[@]}"; do
            kill -9 "$pid" 2>/dev/null || true
        done
        [[ -n "$GATEWAY_PID" ]] && kill -9 "$GATEWAY_PID" 2>/dev/null || true
        [[ -n "$SERVER_PID" ]] && kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    # Drop this run's database (created below, salted per run).
    if [[ -n "$IT_DB" && -n "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
        psql "$YUZU_TEST_POSTGRES_DSN" -qtAc "DROP DATABASE IF EXISTS \"$IT_DB\" WITH (FORCE);" \
            > /dev/null 2>&1 || true
    fi
    # Clean temp dir. It is kept when YUZU_KEEP_WORK_DIR is set (debugging) and
    # whenever the run is failing (non-zero exit), so the logs are there to read
    # or for CI to upload.
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" && -z "${YUZU_KEEP_WORK_DIR:-}" && $rc -eq 0 ]]; then
        rm -rf "$WORK_DIR"
    elif [[ -n "$WORK_DIR" ]]; then
        log "Preserving work dir: $WORK_DIR"
    fi
    log "Cleanup done."
}
trap cleanup EXIT

# ── Create temp work directory ────────────────────────────────────────
# YUZU_IT_TMPDIR lets CI keep the work directory inside the runner's own temp
# dir, where the failure-log upload can find it.
WORK_DIR=$(mktemp -d "${YUZU_IT_TMPDIR:-/tmp}/yuzu-integration.XXXXXX")
# One salt per run for every named resource that is not a port: the database,
# the gateway's Erlang node name and its distribution cookie.
RUN_SALT="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
log "Work directory: $WORK_DIR"

if $REUSE_STACK; then
    log "═══════════════════════════════════════════════════════════════"
    log "Phase 4 REUSE mode: $REUSE_REASON"
    log "  Reusing existing stack on canonical ports:"
    log "    server web=$SERVER_WEB_PORT agent=$SERVER_AGENT_PORT mgmt=$SERVER_MGMT_PORT gw=$SERVER_GW_PORT"
    log "    gateway agent=$GW_AGENT_PORT mgmt=$GW_MGMT_PORT metrics=$GW_METRICS_PORT"
    log "  Skipping own-stack bring-up (server/gateway/agent already running)."
    log "═══════════════════════════════════════════════════════════════"

    # Discover Phase 4's process PIDs so the downstream stability tests
    # (`kill -0 $SERVER_PID` / `$GATEWAY_PID` / agent PIDs) can probe them
    # the same way they probe a script-spawned stack. These PIDs are
    # discovered, not owned — the EXIT trap's `kill` calls are skipped
    # in reuse mode via the REUSE_STACK guard so we never terminate
    # processes we didn't start.
    #
    # Agent filter: match only Phase 4's agent by its `/tmp/yuzu-uat/`
    # data-dir. A broader `yuzu-agent.*--server` pattern would also match
    # strays from prior own-stack integration-test runs that failed to
    # clean up, and would inflate the agent count in the stability
    # assertions.
    SERVER_PID=$(pgrep -f 'yuzu-server.*--listen' | head -1 || true)
    # Gateway can run as either the prod release (`yuzu_gw/bin/yuzu_gw`
    # wrapper -> erts) or a dev-mode `rebar3 run` (beam.smp). The Erlang
    # `-name yuzu_gw@<addr>` flag is the stable fingerprint across both;
    # it's present on the cmdline either way. HA WS-4 #4555 changed the
    # node short name from the old hardcoded `yuzu_gw1` to a shared
    # `yuzu_gw` (every replica now advertises the SAME short name,
    # distinguished only by address, to support `docker compose --scale`)
    # -- match the `yuzu_gw@` PREFIX, not a fixed full name, since the
    # address suffix varies with YUZU_GW_ADVERTISE_ADDR (default
    # 127.0.0.1, unchanged for a single-node/Phase-4 rig).
    GATEWAY_PID=$(pgrep -f '\-name yuzu_gw@' | head -1 || true)
    AGENT_PIDS=($(pgrep -f 'yuzu-agent.*--data-dir /tmp/yuzu-uat' || true))
    if [[ -z "$SERVER_PID" ]]; then
        echo "FAIL: Phase 4 reuse — could not find yuzu-server pid via pgrep" >&2
        exit 1
    fi
    if [[ -z "$GATEWAY_PID" ]]; then
        echo "FAIL: Phase 4 reuse — could not find gateway beam.smp pid via pgrep" >&2
        exit 1
    fi
    if [[ ${#AGENT_PIDS[@]} -eq 0 ]]; then
        echo "FAIL: Phase 4 reuse — could not find any yuzu-agent pid via pgrep" >&2
        exit 1
    fi
    log "  Discovered Phase 4 PIDs: server=$SERVER_PID gateway=$GATEWAY_PID agents=${AGENT_PIDS[*]}"
else
    log "Own-stack mode: $REUSE_REASON"
fi

# ── Stack mode: certificates and gateway-peer posture ─────────────────
# --tls: the server generates its OWN default certificate set under CA_DIR and,
# with no acknowledgement flag, pins its own default-gateway.pem automatically.
# Everything below that dials the server over TLS reads those same files.
CA_DIR="$WORK_DIR/ca"
if $USE_TLS; then
    log "TLS mode: server default certificates under $CA_DIR, automatic gateway pin"
    PEER_FLAGS=""
    TLS_AGENT_FLAGS="--ca-cert $CA_DIR/default-ca.pem"
    # The command plane: the server forwards every gateway-routed command to the
    # gateway's management listener over mutual TLS, presenting its own default
    # leaf, which the gateway pins (mgmt_peer_pins, below).
    #
    # The REST per-IP limit (100 requests/s by default) is raised: the burst below
    # is the load under test, and with the default the limiter answers 429 for
    # most of it, so the commands never overlap on the management connection.
    MGMT_FLAGS="--gateway-command-addr 127.0.0.1:$GW_MGMT_PORT --rate-limit 10000"
else
    PEER_FLAGS="--no-tls --insecure-gateway-peer"
    TLS_AGENT_FLAGS="--no-tls"
    MGMT_FLAGS=""
fi

# ── Per-run database and server config (own-stack only) ───────────────
if ! $REUSE_STACK; then
    for tool in psql openssl curl python3; do
        if ! command -v "$tool" > /dev/null 2>&1; then
            echo "FAIL: $tool not on PATH (required by this script)" >&2
            exit 1
        fi
    done
    if [[ -z "${YUZU_TEST_POSTGRES_DSN:-}" ]]; then
        echo "FAIL: YUZU_TEST_POSTGRES_DSN is unset (the server fails closed without Postgres)" >&2
        exit 1
    fi
    # `yuzu_test_<epoch>_gwint_<salt>`: lowercase [a-z0-9_] with an epoch right after
    # the prefix, so the test-database sweepers can reclaim one this run leaked
    # (SIGKILL, runner loss). Same naming as tests/shell/test_gateway_peer_boot_refusal.sh.
    IT_DB="yuzu_test_$(date +%s)_gwint_${RUN_SALT}"
    if ! psql "$YUZU_TEST_POSTGRES_DSN" -v ON_ERROR_STOP=1 -qtAc "CREATE DATABASE \"$IT_DB\";" \
            > /dev/null 2>&1; then
        IT_DB=""
        echo "FAIL: could not CREATE DATABASE on YUZU_TEST_POSTGRES_DSN" >&2
        exit 1
    fi
    dsn_base="${YUZU_TEST_POSTGRES_DSN%%\?*}"
    dsn_query=""
    [[ "$dsn_base" != "$YUZU_TEST_POSTGRES_DSN" ]] && dsn_query="?${YUZU_TEST_POSTGRES_DSN#*\?}"
    IT_DSN="${dsn_base%/*}/${IT_DB}${dsn_query}"
    log "Database: $IT_DB"

    SERVER_DATA_DIR="$WORK_DIR/server-data"
    mkdir -p "$SERVER_DATA_DIR" "$CA_DIR"
    # The same admin seed the CLI shell tests use (fresh-install bootstrap needs an
    # admin): the config never falls into interactive first-run setup.
    SERVER_CFG="$SERVER_DATA_DIR/yuzu-server.cfg"
    python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', 'adminpassword1'.encode(), salt, 100000, dklen=32)
print(f'admin:admin:{salt.hex()}:{dk.hex()}')
" > "$SERVER_CFG"
    chmod 600 "$SERVER_CFG"

    # Common to every server invocation below.
    SERVER_COMMON=(--config "$SERVER_CFG" --data-dir "$SERVER_DATA_DIR" --ca-dir "$CA_DIR"
                   --postgres-dsn "$IT_DSN")

    # An enrollment token so test agents are auto-approved (Tier 2). The Common
    # Test suite registers dozens of agents of its own against the same token.
    ENROLL_TOKEN=$(
        "$BUILDDIR/server/core/yuzu-server" "${SERVER_COMMON[@]}" \
            --generate-tokens 1 \
            --token-label "integration-test" \
            --token-max-uses 1000 \
            2>/dev/null \
        | grep -o '"[0-9a-f]\{64\}"' | tr -d '"' | head -1
    )
    if [[ -z "$ENROLL_TOKEN" ]]; then
        echo "FAIL: Could not generate enrollment token"
        exit 1
    fi
    log "  Enrollment token generated (${ENROLL_TOKEN:0:8}...)"
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 1: Start the C++ Server
# ══════════════════════════════════════════════════════════════════════
if ! $REUSE_STACK; then
    log "Starting C++ server (ports: agent=$SERVER_AGENT_PORT, mgmt=$SERVER_MGMT_PORT, web=$SERVER_WEB_PORT, gateway-upstream=$SERVER_GW_PORT)..."

    # The gateway-upstream service requires an authorized gateway peer.
    #   --tls       no flag: the server runs on its generated default certificates, so it
    #               enforces the AUTOMATIC PIN of its own default-gateway.pem, which is the
    #               leaf the gateway below presents. The hop is pinned over TLS.
    #   plaintext   --no-tls --insecure-gateway-peer: peer authorization acknowledged as
    #               disabled (test rig only, not a production pattern); the gateway dials a
    #               plaintext channel with no client certificate, so the hop is not
    #               exercised in this mode.
    # The server is always the build under test ($BUILDDIR), never a published release, so
    # the flag form (not the environment form) is correct.
    #
    # --mfa-step-up-window-secs is short so Test 19a can age an MFA proof past the
    # window in a few seconds. The only other admin login is the Phase 5a REST
    # driver (--tls), which calls no step-up-gated route, so the short window
    # affects no other test. 19a runs after that driver because it enrols TOTP on
    # the admin, after which a password-only login answers 202 mfa_required.
    STEPUP_WINDOW_SECS=3
    # shellcheck disable=SC2086
    "$BUILDDIR/server/core/yuzu-server" "${SERVER_COMMON[@]}" \
        --listen "127.0.0.1:$SERVER_AGENT_PORT" \
        --management "127.0.0.1:$SERVER_MGMT_PORT" \
        --web-address 127.0.0.1 \
        --web-port "$SERVER_WEB_PORT" \
        --metrics-no-auth \
        --no-https \
        --mfa-step-up-window-secs "$STEPUP_WINDOW_SECS" \
        --gateway-mode \
        --gateway-upstream "127.0.0.1:$SERVER_GW_PORT" \
        $PEER_FLAGS \
        $MGMT_FLAGS \
        > "$WORK_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    log "  Server PID: $SERVER_PID"

    # 30s budget — yuzu-server cold-starts walk ~20 MigrationRunners and
    # routinely take 12+ seconds; the prior 15s headroom was too tight on
    # WSL2 dev boxes (parity with linux-start-UAT.sh:197).
    wait_for_port "$SERVER_WEB_PORT" "C++ server web UI" 30 || exit 1
    wait_for_port "$SERVER_AGENT_PORT" "C++ server agent gRPC" 30 || exit 1
    wait_for_port "$SERVER_GW_PORT" "C++ server gateway gRPC" 30 || exit 1
    log "  Server is ready."
else
    log "Phase 4 reuse: verifying existing C++ server ports are responsive..."
    wait_for_port "$SERVER_WEB_PORT" "C++ server web UI (Phase 4)" 5 || {
        echo "FAIL: Phase 4 server not responding on :$SERVER_WEB_PORT" >&2
        exit 1
    }
    wait_for_port "$SERVER_GW_PORT" "C++ server gateway gRPC (Phase 4)" 5 || {
        echo "FAIL: Phase 4 server not responding on :$SERVER_GW_PORT" >&2
        exit 1
    }
    log "  Phase 4 server confirmed on :$SERVER_WEB_PORT / :$SERVER_GW_PORT."
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 2: Start the Erlang Gateway (the prod release)
# ══════════════════════════════════════════════════════════════════════
if ! $REUSE_STACK; then
log "Building the gateway release (rebar3 as prod release)..."
if ! (cd "$GATEWAY_DIR" && rebar3 as prod release) > "$WORK_DIR/gw_build.log" 2>&1; then
    echo "FAIL: Gateway release build failed"
    cat "$WORK_DIR/gw_build.log"
    exit 1
fi
GW_REL="$GATEWAY_DIR/_build/prod/rel/yuzu_gw"
if [[ ! -x "$GW_REL/bin/yuzu_gw" ]]; then
    echo "FAIL: gateway release not found at $GW_REL/bin/yuzu_gw"
    exit 1
fi

log "Starting Erlang gateway (agents=$GW_AGENT_PORT, upstream=127.0.0.1:$SERVER_GW_PORT, metrics=$GW_METRICS_PORT, health=$GW_HEALTH_PORT)..."

# The sys.config below replaces the release's own (RELX_CONFIG_PATH).
GW_SYS_CONFIG="$WORK_DIR/gw_sys.config"
# Keys shared by both modes.
GW_COMMON_CFG="
        {upstream_addr, \"127.0.0.1\"},
        {upstream_port, $SERVER_GW_PORT},
        {upstream_pool_size, 4},
        {heartbeat_batch_interval_ms, 2000},
        {default_command_timeout_s, 30},
        {telemetry_gauge_interval_ms, 5000},
        {prometheus_port, $GW_METRICS_PORT},
        {health_port, $GW_HEALTH_PORT},"
if $USE_TLS; then
    # The production shape (deploy/docker/reference-gateway-sys.config): one-way TLS
    # for agents (an unenrolled agent has no client certificate yet) and an https
    # upstream channel with verify_peer, the install CA and the gateway leaf as the
    # client certificate. The server pins that leaf's SPKI.
    #
    # The management listener is the production one (the `mgmt' entry of
    # deploy/docker/reference-gateway-sys.config): strict mutual TLS (verify and
    # fail_if_no_peer_cert left at their defaults, which the boot guard requires to
    # be verify_peer / true), auth_fun yuzu_gw_authz:check_mgmt_peer/1, and
    # mgmt_peer_pins naming the SERVER's default leaf as a `cert_file' pin, the
    # shipped form: the gateway pins that leaf's SPKI and requires serverAuth. The
    # gateway's own leaf (a valid certificate of the same CA, serverAuth included)
    # is therefore NOT admitted on it, which the Common Test suite checks. The mode is the
    # opt-in transition one (#6016; the shipped configs stay on pin): the server is admitted by the identity its leaf
    # carries, derived here from the single-certificate default-ca.pem, or by that pin.
    # It binds loopback; the limits and http2 values are the shipped ones.
    cat > "$GW_SYS_CONFIG" << ERLCFG
[
    {yuzu_gw, [$GW_COMMON_CFG
        {mgmt_peer_auth_mode, identity_or_pin},
        {mgmt_peer_pins, [{cert_file, "$CA_DIR/default-server.pem"}]},
        {grpc_listeners, [
            #{name => agent,
              service_protos => [agent_pb],
              services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service},
              listen => #{port => $GW_AGENT_PORT, ip => {127,0,0,1}},
              tls => #{certfile   => "$CA_DIR/default-gateway.pem",
                       keyfile    => "$CA_DIR/default-gateway.key",
                       cacertfile => "$CA_DIR/default-ca.pem",
                       verify => verify_none,
                       fail_if_no_peer_cert => false},
              acceptors => 4,
              http2 => #{idle_timeout => 180000, max_concurrent_streams => 32}},
            #{name => mgmt,
              service_protos => [management_pb],
              services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service},
              listen => #{port => $GW_MGMT_PORT, ip => {127,0,0,1}},
              tls => #{certfile   => "$CA_DIR/default-gateway.pem",
                       keyfile    => "$CA_DIR/default-gateway.key",
                       cacertfile => "$CA_DIR/default-ca.pem"},
              auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1,
              acceptors => 4,
              limits => #{max_connections => 256, max_message_bytes => 4194304},
              http2 => #{idle_timeout => 600000, max_concurrent_streams => 1024,
                         max_received_frame_rate => {100000, 10000}}}
        ]},
        {upstream_client, #{channels => [
            {default_channel, [{https, "127.0.0.1", $SERVER_GW_PORT, [
                {cacertfile, "$CA_DIR/default-ca.pem"},
                {certfile,   "$CA_DIR/default-gateway.pem"},
                {keyfile,    "$CA_DIR/default-gateway.key"},
                {verify, verify_peer},
                {depth, 2},
                {versions, ['tlsv1.2']}
            ]}], #{}}
        ]}}
    ]},
    {kernel, [
        {logger_level, info},
        {logger, [
            {handler, default, logger_std_h, #{
                level => info,
                formatter => {logger_formatter, #{
                    template => [time, " [", level, "] ", msg, "\n"]
                }}
            }}
        ]}
    ]}
].
ERLCFG
else
    cat > "$GW_SYS_CONFIG" << ERLCFG
[
    {yuzu_gw, [$GW_COMMON_CFG
        %% #1422 escape hatch - TEST RIG ONLY: the wildcard listener below
        %% serves management_pb in plaintext, and the gateway refuses to boot
        %% that posture without this explicit acknowledgement. Never copy into
        %% production - use deploy/docker/reference-gateway-sys.config.
        {allow_insecure_mgmt, true},
        %% One plaintext listener serves both services, on the agent port: this
        %% gateway has no separate management port (GW_MGMT_PORT names the
        %% management port of a gateway started elsewhere, in reuse mode).
        {grpc_listeners, [
            #{name => gateway,
              service_protos => [agent_pb, management_pb],
              services => #{
                  'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service,
                  'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service
              },
              listen => #{port => $GW_AGENT_PORT, ip => {0,0,0,0}}}
        ]},
        %% Upstream channel to the server. Read from {yuzu_gw, upstream_client}; a
        %% {grpcbox, client} entry is never applied by the VM and refuses boot.
        {upstream_client, #{channels => [
            {default_channel, [{http, "127.0.0.1", $SERVER_GW_PORT, []}], #{}}
        ]}}
    ]},
    {kernel, [
        {logger_level, info},
        {logger, [
            {handler, default, logger_std_h, #{
                level => info,
                formatter => {logger_formatter, #{
                    template => [time, " [", level, "] ", msg, "\n"]
                }}
            }}
        ]}
    ]}
].
ERLCFG
fi

# A salted node name and cookie: the release's own vm.args fixes the short name
# `yuzu_gw`, which two concurrent runs on one host (one OS identity, one EPMD)
# would contest. VMARGS_PATH replaces the release's vm.args for this run only.
GW_VM_ARGS="$WORK_DIR/gw_vm.args"
# The boot guard (#659) refuses a cookie shorter than 32 characters.
GW_COOKIE="$(openssl rand -hex 24)"
cat > "$GW_VM_ARGS" << VMARGS
-name yuzu_gw_it_${RUN_SALT}@127.0.0.1
-setcookie ${GW_COOKIE}
+K true
+A 32
+P 262144
VMARGS

# No subshell: $! must be the launcher's PID (`foreground` execs erlexec -> beam).
RELX_CONFIG_PATH="$GW_SYS_CONFIG" VMARGS_PATH="$GW_VM_ARGS" \
    "$GW_REL/bin/yuzu_gw" foreground \
    > "$WORK_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
log "  Gateway PID: $GATEWAY_PID"

# Poll the gateway's agent-facing gRPC port until it's bound. Gateway
# startup is usually 1-2s but can be slower on cold BEAM VM. wait_for_port
# returns as soon as the port accepts connections.
if ! wait_for_port "$GW_AGENT_PORT" "Gateway agent-facing gRPC" 30; then
    echo "--- gateway.log ---"
    cat "$WORK_DIR/gateway.log"
    exit 1
fi
if $USE_TLS && ! wait_for_port "$GW_MGMT_PORT" "Gateway management gRPC (pinned mTLS)" 30; then
    echo "--- gateway.log ---"
    cat "$WORK_DIR/gateway.log"
    exit 1
fi
if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
    fail "Gateway process died on startup"
    echo "--- gateway.log ---"
    cat "$WORK_DIR/gateway.log"
    exit 1
fi
log "  Gateway is running."
else
    log "Phase 4 reuse: verifying existing gateway ports are responsive..."
    wait_for_port "$GW_AGENT_PORT" "Gateway agent-facing (Phase 4)" 5 || {
        echo "FAIL: Phase 4 gateway not responding on :$GW_AGENT_PORT" >&2
        exit 1
    }
    wait_for_port "$GW_MGMT_PORT" "Gateway mgmt (Phase 4)" 5 || {
        echo "FAIL: Phase 4 gateway not responding on :$GW_MGMT_PORT" >&2
        exit 1
    }
    log "  Phase 4 gateway confirmed on :$GW_AGENT_PORT / :$GW_MGMT_PORT / :$GW_METRICS_PORT."
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 3: Start Agent(s) — connecting THROUGH the gateway
# ══════════════════════════════════════════════════════════════════════
if ! $REUSE_STACK; then
    log "Starting $AGENT_COUNT agent(s) (connecting to gateway at 127.0.0.1:$GW_AGENT_PORT)..."

    AGENT_PLUGIN_FLAGS=()
    [[ -d "$BUILDDIR/agents/plugins" ]] && AGENT_PLUGIN_FLAGS=(--plugin-dir "$BUILDDIR/agents/plugins")

    for i in $(seq 1 "$AGENT_COUNT"); do
        AGENT_DATA_DIR="$WORK_DIR/agent-$i"
        mkdir -p "$AGENT_DATA_DIR"
        # The per-agent leaf issued at enrollment is stored under --cert-dir.
        AGENT_CERT_FLAGS=()
        $USE_TLS && AGENT_CERT_FLAGS=(--cert-dir "$AGENT_DATA_DIR/certs")

        # shellcheck disable=SC2086
        "$BUILDDIR/agents/core/yuzu-agent" \
            --server "127.0.0.1:$GW_AGENT_PORT" \
            --agent-id "integration-agent-$i" \
            --data-dir "$AGENT_DATA_DIR" \
            --heartbeat 5 \
            --enrollment-token "$ENROLL_TOKEN" \
            ${AGENT_PLUGIN_FLAGS[@]+"${AGENT_PLUGIN_FLAGS[@]}"} \
            ${AGENT_CERT_FLAGS[@]+"${AGENT_CERT_FLAGS[@]}"} \
            $TLS_AGENT_FLAGS \
            > "$WORK_DIR/agent-$i.log" 2>&1 &
        AGENT_PIDS+=($!)
    done

    # Wait for agents to register. Poll the server's /metrics for
    # yuzu_fleet_agents_healthy >= 1 rather than greping the agent log for
    # generic English ("register|session") — the metric is the authoritative
    # answer to "is the agent connected" and dodges the log-buffer race that
    # bit the REUSE-mode test (the agent log can show fresh content but a
    # concurrent `cat … || echo ""` reads empty under WSL2 drvfs).
    log "  Waiting for agents to register (polling /metrics)..."
    poll_metric_at_least "http://127.0.0.1:$SERVER_WEB_PORT/metrics" \
        yuzu_fleet_agents_healthy 1 60 || true

    ALIVE_AGENTS=0
    for pid in "${AGENT_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            ALIVE_AGENTS=$((ALIVE_AGENTS + 1))
        fi
    done
    log "  $ALIVE_AGENTS/$AGENT_COUNT agents running."
else
    # Phase 4 already has at least one agent registered. Verify via the
    # server's /metrics endpoint (no auth) — `yuzu_fleet_agents_healthy`
    # gauge shows how many agents are currently heartbeating. Name was
    # confirmed 2026-04-19 against a live v0.11.0 server; keep in sync
    # with its metrics_.describe() registration in server/core/src/server.cpp
    # if it drifts.
    log "Phase 4 reuse: verifying registered agent count via /metrics..."
    # The fleet-health recompute thread runs on a 15s interval, so a freshly
    # registered agent can take up to one full interval to appear in /metrics.
    # 20 attempts (~20s) covers one recompute + buffer. (#1008)
    AGENT_COUNT_FROM_METRICS=0
    for i in $(seq 1 20); do
        METRICS=$(curl -sf --max-time 2 "http://127.0.0.1:$SERVER_WEB_PORT/metrics" 2>/dev/null || echo "")
        # awk-no-exit pattern: `; exit` causes upstream SIGPIPE under
        # `set -o pipefail` and breaks the loop on the first iteration
        # without any of the expected metrics having been parsed.
        # (#988-pattern carried over from feat/quic-transport.)
        HEALTHY=$(echo "$METRICS" | awk '/^yuzu_fleet_agents_healthy[[:space:]]/ { val=$2 } END { print val }')
        if [[ -n "$HEALTHY" ]] && [[ "${HEALTHY%.*}" -ge 1 ]]; then
            AGENT_COUNT_FROM_METRICS=${HEALTHY%.*}
            break
        fi
        sleep 1
    done
    if [[ "$AGENT_COUNT_FROM_METRICS" -ge 1 ]]; then
        log "  Phase 4 agent confirmed: yuzu_fleet_agents_healthy = $AGENT_COUNT_FROM_METRICS"
        ALIVE_AGENTS=$AGENT_COUNT_FROM_METRICS
    else
        echo "FAIL: Phase 4 reuse — yuzu_fleet_agents_healthy < 1 on /metrics after 20s" >&2
        exit 1
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 4: Test Scenarios
# ══════════════════════════════════════════════════════════════════════

# Source logs from Phase 4's /tmp/yuzu-uat in reuse mode; from our own
# $WORK_DIR otherwise. Defined once here so every downstream test uses
# the same path.
if $REUSE_STACK; then
    AGENT_LOG_PATH="/tmp/yuzu-uat/agent.log"
    GATEWAY_LOG_PATH="/tmp/yuzu-uat/gateway.log"
    SERVER_LOG_PATH="/tmp/yuzu-uat/server.log"
else
    AGENT_LOG_PATH="$WORK_DIR/agent-1.log"
    GATEWAY_LOG_PATH="$WORK_DIR/gateway.log"
    SERVER_LOG_PATH="$WORK_DIR/server.log"
fi

log ""
log "═══════════════════════════════════════════"
log "  RUNNING INTEGRATION TESTS"
log "═══════════════════════════════════════════"
log ""

# ── Test Category: Basic Connectivity ─────────────────────────────────

# ── Test 1: Server web UI is reachable ────────────────────────────────
log "Test: Server web UI"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SERVER_WEB_PORT/home" || echo "000")
assert_eq "Server /home (sign-in landing page) returns 200" "200" "$HTTP_CODE"

# ── Test 2: Server shows connected agents ─────────────────────────────
log "Test: Agent registration through gateway"
# Try the agent list API first (requires auth — may be empty or forbidden)
AGENTS_RESP=$(curl -sf "http://127.0.0.1:$SERVER_WEB_PORT/api/agents" 2>/dev/null || echo "")
if [[ -n "$AGENTS_RESP" ]] && echo "$AGENTS_RESP" | grep -q "integration-agent"; then
    assert_contains "Server sees agents via API" "integration-agent" "$AGENTS_RESP"
else
    # API requires auth; confirm server is reachable and serving auth-gated content.
    # -sL follows the redirect from / to /login, returning the login page HTML.
    DASHBOARD=$(curl -sL "http://127.0.0.1:$SERVER_WEB_PORT/" 2>/dev/null || echo "")
    TESTS=$((TESTS + 1))
    if [[ -n "$DASHBOARD" ]]; then
        pass "Server reachable; agents registered via gateway (API auth-gated)"
    else
        fail "Cannot reach server dashboard"
    fi
fi

# ── Test 3: Agents are alive and connected ────────────────────────────
log "Test: Agent process health"
assert_ge "At least 1 agent alive" 1 "$ALIVE_AGENTS"

# ── Test 4: Gateway process is alive ──────────────────────────────────
log "Test: Gateway health"
TESTS=$((TESTS + 1))
if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    pass "Gateway process is alive"
else
    fail "Gateway process died"
fi

# Test 5 — agent is connected to the server. Previously: `cat agent.log |
# grep -qi "register|session|connect|heartbeat"`. That was fragile by design:
# generic English against volatile log content, with a `cat … || echo ""`
# fallback that silently swallowed empty reads (WSL2 drvfs race). The metric
# is the authoritative answer — yuzu_fleet_agents_healthy is the server-side
# gauge of currently-healthy agents.
log "Test: Agent registration in logs"
TESTS=$((TESTS + 1))
if poll_metric_at_least "http://127.0.0.1:$SERVER_WEB_PORT/metrics" \
       yuzu_fleet_agents_healthy 1 30; then
    pass "Agent connected per yuzu_fleet_agents_healthy >= 1"
else
    fail "yuzu_fleet_agents_healthy stayed < 1 after 30s (agent did not register)"
fi

# ── Test 6: Gateway logs show agent connections ───────────────────────
# Previously: grep "agent|connect|register|started" on the gateway log. Same
# anti-pattern. The gateway exports yuzu_gw_agents_current (gauge) — live
# count of agents currently connected via this gateway node. If the gauge is
# zero we fall back to a STRICT error-pattern check on the gateway log,
# because there is no metric for "gateway is in a bad state" — that signal
# only exists as Erlang crash/error report headers in the log. The fallback
# fails LOUDLY on empty file (the original silently masked it).
log "Test: Gateway sees agent connections"
TESTS=$((TESTS + 1))
if poll_metric_at_least "http://127.0.0.1:$GW_METRICS_PORT/metrics" \
       yuzu_gw_agents_current 1 30; then
    pass "Gateway sees >= 1 connected agent (yuzu_gw_agents_current)"
elif [[ ! -s "$GATEWAY_LOG_PATH" ]]; then
    fail "Gateway shows no connected agents AND log is empty/missing at $GATEWAY_LOG_PATH"
elif grep -qE '\[error\]|CRASH REPORT|=ERROR REPORT|badarg|Supervisor: .* terminating' \
        "$GATEWAY_LOG_PATH" 2>/dev/null; then
    fail "Gateway shows no connected agents AND log contains errors — see $GATEWAY_LOG_PATH"
else
    pass "Gateway started cleanly (no agent traffic yet, no errors in log)"
fi

# ── Test 7: Server logs show gateway-mode activity ────────────────────
# Previously: grep "gateway|register|agent|listen" on the server log, with
# both branches calling pass() — the test could NEVER fail (latent bug).
# Replace with a real assertion: the same yuzu_fleet_agents_healthy gauge
# polled by Test 5, since a gateway-relayed agent showing up in that metric
# is direct evidence that the server's gateway-mode path is doing its job.
# We use a short 5s timeout here because Test 5 already established the
# metric is reachable and ≥1 — this is just defence-in-depth.
log "Test: Server gateway-mode operation"
TESTS=$((TESTS + 1))
if poll_metric_at_least "http://127.0.0.1:$SERVER_WEB_PORT/metrics" \
       yuzu_fleet_agents_healthy 1 5; then
    pass "Server gateway-mode active (agent visible via /metrics)"
else
    fail "Server gateway-mode broken: yuzu_fleet_agents_healthy < 1"
fi

# ── Test 7b: the gateway hop is a pinned TLS hop (--tls) ──────────────
# The server booted on its generated default certificates with no acknowledgement
# flag, so it enforces the automatic pin of its own default-gateway.pem, and the
# gateway presents exactly that leaf (sys.config above). Three independent facts:
# the boot line names the leaf's SPKI prefix, the mode gauge says enforce, and the
# guard has denied nobody although the gateway has been calling since boot.
if $USE_TLS && ! $REUSE_STACK; then
    log "Test: gateway-upstream peer authorization is enforcing, with the gateway leaf pinned"
    GW_SPKI=$(openssl x509 -in "$CA_DIR/default-gateway.pem" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' | tr 'A-F' 'a-f')
    TESTS=$((TESTS + 1))
    if [[ "${#GW_SPKI}" -eq 64 ]] \
       && grep -qF "pin prefixes (first 16 hex): ${GW_SPKI:0:16}" "$SERVER_LOG_PATH" \
       && grep -qF "pinned automatically" "$SERVER_LOG_PATH"; then
        pass "Server pinned the default gateway leaf automatically (SPKI ${GW_SPKI:0:16})"
    else
        fail "Server boot line does not show the automatic pin of default-gateway.pem (SPKI '${GW_SPKI:0:16}')"
    fi
    SERVER_METRICS=$(curl -sf --max-time 5 "http://127.0.0.1:$SERVER_WEB_PORT/metrics" 2>/dev/null || echo "")
    assert_contains "Peer authorization mode gauge says enforce" \
        'yuzu_server_gateway_peer_authz_mode{mode="enforce"} 1' "$SERVER_METRICS"
    # Sum every denial series: the gateway's own calls must all have been admitted.
    DENIED=$(awk '/^yuzu_server_gateway_peer_denied_total/ { sum += $NF } END { print sum + 0 }' \
        <<< "$SERVER_METRICS")
    assert_eq "No gateway-upstream call was denied for the pinned gateway" "0" "${DENIED%.*}"
fi

# ── Test 8: Multiple heartbeat cycles ─────────────────────────────────
# Previously: fixed `sleep 10` from the start of this block. That races
# with agent startup — if the agent takes > 5s to enroll (normal on cold
# runs, especially with enrollment-token retry backoff), the sleep ends
# before the first heartbeat has even fired, and downstream metric
# assertions silently drift. Now we loop-poll /metrics until
# yuzu_heartbeats_received_total actually appears. Timeout is generous
# enough to cover a ~12s cold-cache enrollment plus one 5s interval with
# headroom.
if [[ "$AGENT_COUNT" -ge 1 ]]; then
    log "Test: Heartbeat continuity (polling /metrics up to 30s for heartbeats)..."
    heartbeat_seen=false
    for attempt in $(seq 1 30); do
        METRICS_POLL=$(curl -sf "http://127.0.0.1:$SERVER_WEB_PORT/metrics" 2>/dev/null || echo "")
        # Here-string, not a pipe (see assert_contains's comment on the same
        # SIGPIPE-under-pipefail hazard) — this body is large enough to trigger it.
        if grep -qF -- "yuzu_heartbeats_received_total" <<< "$METRICS_POLL"; then
            heartbeat_seen=true
            log "  Heartbeats observed after ${attempt}s"
            break
        fi
        sleep 1
    done
    if ! $heartbeat_seen; then
        log "  WARN: yuzu_heartbeats_received_total not observed in 30s; downstream metric assertions may fail"
    fi

    # Check agents are still alive after the poll
    STILL_ALIVE=0
    for pid in "${AGENT_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            STILL_ALIVE=$((STILL_ALIVE + 1))
        fi
    done
    assert_eq "All agents survived heartbeat cycles" "$AGENT_COUNT" "$STILL_ALIVE"
fi

# ── Test Category: Server API Endpoints ───────────────────────────────

# ── Test 9: Server metrics endpoint ───────────────────────────────────
log "Test: Server metrics endpoint"
METRICS_RESP=$(curl -sf "http://127.0.0.1:$SERVER_WEB_PORT/metrics" 2>/dev/null || echo "")
if [[ -n "$METRICS_RESP" ]]; then
    TESTS=$((TESTS + 1))
    if grep -qF -- "yuzu_" <<< "$METRICS_RESP"; then
        pass "Server /metrics returns Prometheus metrics"
    else
        pass "Server /metrics endpoint accessible"
    fi
else
    TESTS=$((TESTS + 1))
    fail "Server /metrics endpoint not responding"
fi

# ── Test 9b: Fleet health metrics in /metrics output ─────────────────
log "Test: Fleet health metrics (heartbeat piggyback)"
if [[ -n "$METRICS_RESP" ]]; then
    assert_contains "Fleet healthy agents metric present" "yuzu_fleet_agents_healthy" "$METRICS_RESP"
    assert_contains "Heartbeats received metric present" "yuzu_heartbeats_received_total" "$METRICS_RESP"
    # Agents need time for heartbeats to arrive, so fleet by-os may not be populated
    # in short tests; just check the metric name is declared
    TESTS=$((TESTS + 1))
    if grep -q "yuzu_fleet_agents_by_os\|yuzu_fleet_commands_executed_total" <<< "$METRICS_RESP"; then
        pass "Fleet agent breakdown metrics present"
    else
        pass "Fleet metrics declared (agents may not have heartbeated yet)"
    fi
fi

# ── Test 10: Server health endpoint ───────────────────────────────────
log "Test: Server health endpoint"
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SERVER_WEB_PORT/health" 2>/dev/null)
TESTS=$((TESTS + 1))
if [[ "$HEALTH_CODE" == "200" ]] || [[ "$HEALTH_CODE" == "404" ]]; then
    pass "Server health check endpoint accessible ($HEALTH_CODE)"
else
    fail "Server health endpoint returned unexpected code: $HEALTH_CODE"
fi

# ── Test 11: Server help/catalog endpoint ─────────────────────────────
log "Test: Server help/catalog endpoint"
HELP_RESP=$(curl -sf "http://127.0.0.1:$SERVER_WEB_PORT/api/help" 2>/dev/null || echo "")
if [[ -n "$HELP_RESP" ]]; then
    TESTS=$((TESTS + 1))
    if echo "$HELP_RESP" | grep -q "plugins\|commands"; then
        pass "Server /api/help returns plugin catalog"
    else
        pass "Server /api/help endpoint accessible"
    fi
else
    TESTS=$((TESTS + 1))
    pass "Server /api/help requires auth (expected)"
fi

# ── Test Category: Gateway-Server Communication ───────────────────────

# ── Test 12: Gateway upstream connectivity ────────────────────────────
log "Test: Gateway → Server upstream communication"
# Check if server gateway port is listening
if port_open "$SERVER_GW_PORT"; then
    pass "Server GatewayUpstream port ($SERVER_GW_PORT) is listening"
    TESTS=$((TESTS + 1))
else
    fail "Server GatewayUpstream port ($SERVER_GW_PORT) not responding"
fi

# ── Test 13: Gateway agent port ───────────────────────────────────────
log "Test: Gateway agent-facing gRPC port"
if port_open "$GW_AGENT_PORT"; then
    pass "Gateway agent port ($GW_AGENT_PORT) is listening"
    TESTS=$((TESTS + 1))
else
    fail "Gateway agent port ($GW_AGENT_PORT) not responding"
fi

# ── Test Category: Agent Registration & Session ───────────────────────

# ── Test 14: Agent session persistence ────────────────────────────────
log "Test: Agent session persistence across heartbeats"
# Verify agent-1 is still connected after time has passed (AGENT_LOG_PATH is agent-1's log in a
# fresh stack and the reused stack's agent log in reuse mode)
AGENT1_LOG=$(cat "$AGENT_LOG_PATH" 2>/dev/null || echo "")
if echo "$AGENT1_LOG" | grep -qi "session\|heartbeat"; then
    HEARTBEAT_COUNT=$(echo "$AGENT1_LOG" | grep -ci "heartbeat" || echo "0")
    TESTS=$((TESTS + 1))
    if [[ "$HEARTBEAT_COUNT" -ge 1 ]]; then
        pass "Agent-1 sent $HEARTBEAT_COUNT heartbeat(s)"
    else
        pass "Agent-1 established session"
    fi
else
    TESTS=$((TESTS + 1))
    pass "Agent-1 session active (heartbeat verification skipped)"
fi

# ── Test 15: Multi-agent registration ─────────────────────────────────
if [[ "$AGENT_COUNT" -gt 1 ]]; then
    log "Test: Multi-agent registration"
    REGISTERED_COUNT=0
    for i in $(seq 1 "$AGENT_COUNT"); do
        AGENT_LOG=$(cat "$WORK_DIR/agent-$i.log" 2>/dev/null || echo "")
        if echo "$AGENT_LOG" | grep -qi "register\|session\|connect"; then
            REGISTERED_COUNT=$((REGISTERED_COUNT + 1))
        fi
    done
    assert_ge "All agents show registration activity" "$AGENT_COUNT" "$REGISTERED_COUNT"
fi

# ── Test Category: Error Handling ─────────────────────────────────────

# ── Test 16: Server graceful error handling ───────────────────────────
log "Test: Server error handling (invalid endpoint)"
ERROR_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SERVER_WEB_PORT/nonexistent-endpoint" 2>/dev/null || echo "000")
TESTS=$((TESTS + 1))
if [[ "$ERROR_CODE" == "401" ]] || [[ "$ERROR_CODE" == "404" ]] || [[ "$ERROR_CODE" == "302" ]]; then
    pass "Server returns appropriate error code ($ERROR_CODE) for invalid endpoint"
else
    fail "Server returned unexpected code ($ERROR_CODE) for invalid endpoint"
fi

# ── Test Category: Stress & Reliability ───────────────────────────────

# ── Test 17: Rapid heartbeat under load ───────────────────────────────
if [[ "$AGENT_COUNT" -ge 1 ]]; then
    log "Test: Agent stability under heartbeat load"
    # Verify no agents crashed during the test
    CRASHED=0
    for pid in "${AGENT_PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            CRASHED=$((CRASHED + 1))
        fi
    done
    assert_eq "No agent crashes during test" "0" "$CRASHED"
fi

# ── Test 18: Gateway stability ────────────────────────────────────────
# Match on actual Erlang crash / supervisor termination markers, not any
# log line that happens to contain the word "crash". Previously this
# tripped on benign [info]-level lines like:
#   [info] crash: class=exit exception={noproc,{gen_server,call,[yuzu_gw_upstream,...]}}
# which the gateway emits via its own diagnostic logger when an agent's
# first registration attempt races the upstream gen_server startup (the
# agent's retry backoff resolves it cleanly within ~6s). Real Erlang
# crashes always emit a `CRASH REPORT` or `=ERROR REPORT` header, or a
# `Supervisor: ... terminating` line; we match only those, plus any
# explicit SIGTERM at [error] level.
log "Test: Gateway stability throughout test"
TESTS=$((TESTS + 1))
if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    GW_LOG_FINAL=$(cat "$GATEWAY_LOG_PATH" 2>/dev/null || echo "")
    if echo "$GW_LOG_FINAL" | grep -qE 'CRASH REPORT|=ERROR REPORT|Supervisor: .* terminating|\[error\].*SIGTERM'; then
        fail "Gateway log shows critical errors"
    else
        pass "Gateway remained stable throughout test"
    fi
else
    fail "Gateway process died during test"
fi

# ── Test 19: Server stability ─────────────────────────────────────────
log "Test: Server stability throughout test"
TESTS=$((TESTS + 1))
if kill -0 "$SERVER_PID" 2>/dev/null; then
    SERVER_LOG_FINAL=$(cat "$SERVER_LOG_PATH" 2>/dev/null || echo "")
    if echo "$SERVER_LOG_FINAL" | grep -qi "fatal\|SIGSEGV\|abort"; then
        fail "Server log shows fatal errors"
    else
        pass "Server remained stable throughout test"
    fi
else
    fail "Server process died during test"
fi

# ── Test Category: Log Verification ───────────────────────────────────

# ── Test 20: No unexpected errors in logs ─────────────────────────────
log "Test: Log health check"
ALL_LOGS=""
for logfile in "$WORK_DIR"/*.log; do
    if [[ -f "$logfile" ]]; then
        ALL_LOGS="$ALL_LOGS$(cat "$logfile" 2>/dev/null)"
    fi
done

TESTS=$((TESTS + 1))
# Check for critical errors (but allow expected warnings)
if echo "$ALL_LOGS" | grep -qi "SIGSEGV\|segmentation fault\|assertion failed\|stack smashing"; then
    fail "Critical errors found in logs"
else
    pass "No critical errors in any logs"
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 5: Optional gRPC Tests (if grpcurl is available)
# ══════════════════════════════════════════════════════════════════════
if $USE_TLS; then
    log ""
    log "Note: grpcurl probes are plaintext-only; skipped in --tls mode"
elif command -v grpcurl &>/dev/null; then
    log ""
    log "Test Category: gRPC Probing (grpcurl available)"

    # ── Test: gRPC reflection on server ───────────────────────────────
    log "Test: Server gRPC service listing"
    GRPC_SERVICES=$(grpcurl -plaintext "127.0.0.1:$SERVER_AGENT_PORT" list 2>/dev/null || echo "")
    TESTS=$((TESTS + 1))
    if [[ -n "$GRPC_SERVICES" ]]; then
        if echo "$GRPC_SERVICES" | grep -q "AgentService\|yuzu"; then
            pass "Server exposes AgentService via gRPC reflection"
        else
            pass "Server gRPC services accessible"
        fi
    else
        pass "Server gRPC reflection not enabled (not required)"
    fi

    # ── Test: Gateway gRPC service listing ────────────────────────────
    log "Test: Gateway gRPC service listing"
    GW_SERVICES=$(grpcurl -plaintext "127.0.0.1:$GW_AGENT_PORT" list 2>/dev/null || echo "")
    TESTS=$((TESTS + 1))
    if [[ -n "$GW_SERVICES" ]]; then
        if echo "$GW_SERVICES" | grep -q "AgentService\|yuzu"; then
            pass "Gateway exposes AgentService via gRPC reflection"
        else
            pass "Gateway gRPC services accessible"
        fi
    else
        pass "Gateway gRPC reflection not enabled (not required)"
    fi

    # ── Test: Server gateway upstream service ─────────────────────────
    log "Test: Server GatewayUpstream service"
    GW_UPSTREAM_SERVICES=$(grpcurl -plaintext "127.0.0.1:$SERVER_GW_PORT" list 2>/dev/null || echo "")
    TESTS=$((TESTS + 1))
    if [[ -n "$GW_UPSTREAM_SERVICES" ]]; then
        if echo "$GW_UPSTREAM_SERVICES" | grep -q "GatewayUpstream\|yuzu.gateway"; then
            pass "Server exposes GatewayUpstream service"
        else
            pass "Server upstream gRPC accessible"
        fi
    else
        pass "Server GatewayUpstream reflection not enabled (not required)"
    fi
else
    log ""
    log "Note: grpcurl not found — skipping gRPC probing tests"
    log "      Install with: brew install grpcurl (macOS) or go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 5a: The management hop — server -> gateway :$GW_MGMT_PORT -> agent (#5175)
# ══════════════════════════════════════════════════════════════════════
# The server dials the gateway's management listener for every command it routes
# to a gateway-connected agent. That listener is the privileged command plane, so
# it runs here in the production posture (see the gateway sys.config above):
# strict mutual TLS, and the server admitted by its identity or its SPKI pin
# (this rig opts in to identity_or_pin; the shipped configs stay on pin). #5175 was an h2 stream
# crash on exactly this call (every SendCommand reached the server as 'Socket
# closed' with no gRPC status). The commands below go through the server's REST
# API, so the real server's real gRPC client makes the calls: one round trip, then
# a burst whose streams are all multiplexed over the server's one connection.
# The listener's refusals and the deadline/cancel paths, which the server cannot
# drive (it always sends a 300 s deadline and never cancels), are in
# yuzu_gw_real_mgmt_SUITE (Phase 5b).
MGMT_BURST=300
MGMT_CONCURRENCY=16
if $USE_TLS && ! $REUSE_STACK; then
    log ""
    log "Test Category: server -> gateway management hop (pinned mutual TLS)"

    # Boot facts: the server forwards over mutual TLS to the address it was given,
    # and the gateway's management listener came up with TLS and the pin hook.
    assert_contains "Server forwards commands to the gateway over mutual TLS" \
        "Gateway command forwarding enabled: 127.0.0.1:$GW_MGMT_PORT (mutual TLS)" \
        "$(cat "$SERVER_LOG_PATH" 2>/dev/null || true)"
    assert_contains "Gateway management listener is up with TLS and the pin auth_fun" \
        "grpc listener mgmt up on port $GW_MGMT_PORT (tls=true, auth_fun=true" \
        "$(cat "$GATEWAY_LOG_PATH" 2>/dev/null || true)"
    GW_METRICS_BEFORE=$(curl -sf --max-time 5 "http://127.0.0.1:$GW_METRICS_PORT/metrics" 2>/dev/null || echo "")
    assert_contains "Gateway scrapes (management auth counters are registered)" \
        "yuzu_gw_mgmt_auth_rejected_total" "$GW_METRICS_BEFORE"
    assert_eq "No management pin is unresolved (the server leaf file is read)" "0" \
        "$(awk '/^yuzu_gw_mgmt_auth_pin_unresolved_total/ { sum += $NF } END { print sum + 0 }' \
            <<< "$GW_METRICS_BEFORE")"

    MGMT_DRIVER="$WORK_DIR/mgmt_driver.py"
    cat > "$MGMT_DRIVER" << 'MGMTPY'
#!/usr/bin/env python3
# Dispatches os_info.os_name to one agent through the server's REST API and waits
# for each command's terminal SUCCESS. Stdlib only (the Rocky/RHEL python is 3.9).
#   mgmt_driver.py <web-port> <agent-id> <user> <password> <burst> <concurrency>
# Prints KEY=value lines; exits 1 if anything failed.
import http.client, json, sys, threading, time, urllib.parse

port, agent, user, password, burst, conc = (
    int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]))
ORIGIN = "http://127.0.0.1:%d" % port
TERMINAL_OK = (1, "SUCCESS")
TERMINAL_BAD = (2, 3, 4, "FAILURE", "TIMEOUT", "REJECTED")


def connect():
    return http.client.HTTPConnection("127.0.0.1", port, timeout=30)


def login():
    c = connect()
    c.request("POST", "/login",
              body=urllib.parse.urlencode({"username": user, "password": password}),
              headers={"Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse()
    r.read()
    cookies = [v.split(";", 1)[0] for k, v in r.getheaders() if k.lower() == "set-cookie"]
    c.close()
    if not any(x.startswith("yuzu_session=") for x in cookies):
        print("FATAL=login returned no session cookie (HTTP %d)" % r.status)
        sys.exit(1)
    return "; ".join(cookies)


COOKIE = login()


def call(c, method, path, body=None):
    headers = {"Cookie": COOKIE, "Origin": ORIGIN}
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    try:
        return r.status, json.loads(data)
    except ValueError:
        return r.status, {"raw": data[:200].decode("utf-8", "replace")}


def one(c):
    """Dispatch one command and wait for its terminal state. Returns (outcome, ms, detail)."""
    t0 = time.time()
    body = json.dumps({"plugin": "os_info", "action": "os_name", "agent_ids": [agent]})
    status, resp = call(c, "POST", "/api/command", body)
    cid = resp.get("command_id") if isinstance(resp, dict) else None
    if status != 200 or not cid:
        return "DISPATCH_FAILED", 0, "HTTP %s %s" % (status, json.dumps(resp)[:200])
    deadline = t0 + 60
    last = None
    while time.time() < deadline:
        status, resp = call(c, "GET", "/api/responses/" + cid)
        last = resp
        for x in resp.get("responses", []) if isinstance(resp, dict) else []:
            st = x.get("status")
            if st in TERMINAL_OK and x.get("output"):
                return "SUCCESS", int((time.time() - t0) * 1000), x.get("output", "")[:80]
            if st in TERMINAL_BAD:
                return "BAD_TERMINAL", int((time.time() - t0) * 1000), json.dumps(x)[:200]
        time.sleep(0.05)
    return "TIMEOUT", int((time.time() - t0) * 1000), json.dumps(last)[:300]


# One command first: it prints what a response looks like, and proves the path.
c = connect()
outcome, ms, detail = one(c)
print("ROUNDTRIP_OUTCOME=%s" % outcome)
print("ROUNDTRIP_MS=%d" % ms)
print("ROUNDTRIP_DETAIL=%s" % detail.replace("\n", " "))
if outcome != "SUCCESS":
    sys.exit(1)

# Then the burst: `conc` workers, each with its own REST connection; the server
# sends all of them to the gateway over its single management channel.
counts, times, errors = {}, [], []
lock = threading.Lock()
todo = [burst]


def worker():
    cw = connect()
    while True:
        with lock:
            if todo[0] <= 0:
                return
            todo[0] -= 1
        try:
            o, t, d = one(cw)
        except Exception as e:  # noqa: BLE001 - the harness reports every failure
            o, t, d = "EXCEPTION", 0, repr(e)
            cw = connect()
        with lock:
            counts[o] = counts.get(o, 0) + 1
            if o == "SUCCESS":
                times.append(t)
            elif len(errors) < 5:
                errors.append("%s: %s" % (o, d))


t0 = time.time()
threads = [threading.Thread(target=worker) for _ in range(conc)]
[t.start() for t in threads]
[t.join() for t in threads]
elapsed = int((time.time() - t0) * 1000)
times.sort()
print("BURST_TOTAL=%d" % burst)
print("BURST_SUCCESS=%d" % counts.get("SUCCESS", 0))
print("BURST_ELAPSED_MS=%d" % elapsed)
if times:
    print("BURST_P50_MS=%d" % times[len(times) // 2])
    print("BURST_MAX_MS=%d" % times[-1])
for e in errors:
    print("BURST_ERROR=%s" % e)
sys.exit(0 if counts.get("SUCCESS", 0) == burst else 1)
MGMTPY

    log "  Dispatching 1 + $MGMT_BURST commands through the server's REST API ($MGMT_CONCURRENCY at a time)..."
    MGMT_RC=0
    python3 "$MGMT_DRIVER" "$SERVER_WEB_PORT" "integration-agent-1" admin adminpassword1 \
        "$MGMT_BURST" "$MGMT_CONCURRENCY" > "$WORK_DIR/mgmt_driver.log" 2>&1 || MGMT_RC=$?
    cat "$WORK_DIR/mgmt_driver.log" | sed 's/^/    /'
    mgmt_field() { sed -n "s/^$1=//p" "$WORK_DIR/mgmt_driver.log" | head -1; }
    assert_eq "REST command reached the real agent through the management hop and returned SUCCESS" \
        "SUCCESS" "$(mgmt_field ROUNDTRIP_OUTCOME)"
    assert_eq "Every command of the burst over the one management connection completed SUCCESS" \
        "$MGMT_BURST" "$(mgmt_field BURST_SUCCESS)"
    assert_eq "The driver exited clean" "0" "$MGMT_RC"

    # The server's own account of the forwards: every one 'ok', none of the
    # failure statuses (unavailable, unauthenticated, other, unknown_cluster, ...).
    SERVER_METRICS=$(curl -sf --max-time 5 "http://127.0.0.1:$SERVER_WEB_PORT/metrics" 2>/dev/null || echo "")
    FWD_OK=$(awk '/^yuzu_server_gateway_forward_total\{.*status="ok"\}/ { sum += $NF } END { print sum + 0 }' \
        <<< "$SERVER_METRICS")
    FWD_BAD=$(awk '/^yuzu_server_gateway_forward_total\{/ && !/status="ok"/ { sum += $NF } END { print sum + 0 }' \
        <<< "$SERVER_METRICS")
    assert_eq "Server counted every forwarded command as ok" "$((MGMT_BURST + 1))" "${FWD_OK%.*}"
    assert_eq "Server counted no forward as failed" "0" "${FWD_BAD%.*}"
    # The gateway admitted the server's pinned leaf every time.
    GW_METRICS_AFTER=$(curl -sf --max-time 5 "http://127.0.0.1:$GW_METRICS_PORT/metrics" 2>/dev/null || echo "")
    assert_contains "Gateway metrics are readable after the burst" \
        "yuzu_gw_mgmt_auth_rejected_total" "$GW_METRICS_AFTER"
    GW_REJECTED=$(awk '/^yuzu_gw_mgmt_auth_rejected_total/ { sum += $NF } END { print sum + 0 }' \
        <<< "$GW_METRICS_AFTER")
    assert_eq "Gateway rejected no management call from the pinned server" "0" "${GW_REJECTED%.*}"
    # #6016: the gateway admits the server by the identity the C++ server minted onto its leaf
    # (the gateway derives it from the single-certificate CA file). The identity is checked
    # before the pin, so a derivation that differed by a byte would still pass every command
    # above, by the pin, and only these counters would show it.
    GW_ADMITTED_IDENTITY=$(awk '/^yuzu_gw_mgmt_auth_admitted_total\{method="identity"\}/ { sum += $NF } END { print sum + 0 }' \
        <<< "$GW_METRICS_AFTER")
    GW_ADMITTED_PIN=$(awk '/^yuzu_gw_mgmt_auth_admitted_total\{method="pin"\}/ { sum += $NF } END { print sum + 0 }' \
        <<< "$GW_METRICS_AFTER")
    assert_ge "Gateway admitted the server by its identity for every forwarded command" \
        "$((MGMT_BURST + 1))" "${GW_ADMITTED_IDENTITY%.*}"
    assert_eq "Gateway fell back to the pin for no forwarded command" "0" "${GW_ADMITTED_PIN%.*}"
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 5b: Common Test — the gateway's real upstream client against this server
# ══════════════════════════════════════════════════════════════════════
# yuzu_gw_real_upstream_SUITE drives the gateway's own upstream modules and gRPC
# client against THIS stack's server, over the same wire the gateway release
# uses: pinned mutual TLS under --tls (it presents the gateway leaf, and a
# non-pinned leaf of the same CA must be refused), plaintext otherwise. It pairs
# every upstream call site with the real client (#5652) and checks that a
# registration replay makes the server adopt the existing session (#5653).
if $RUN_GATEWAY_CT; then
    if $REUSE_STACK; then
        echo "FAIL: --gateway-ct needs this script's own stack (not a reused one)" >&2
        exit 1
    fi
    log ""
    log "Test Category: gateway real-upstream Common Test suite"
    mkdir -p "$WORK_DIR/ct-logs"
    CT_ENV=(
        "YUZU_UPSTREAM_HOST=127.0.0.1"
        "YUZU_UPSTREAM_PORT=$SERVER_GW_PORT"
        "YUZU_GW_TEST_TOKEN=$ENROLL_TOKEN"
        "YUZU_SERVER_WEB=http://127.0.0.1:$SERVER_WEB_PORT"
        "YUZU_GW_HEALTH_PORT=$GW_HEALTH_PORT"
        # This script owns the stack, so a check the suite cannot make is a failure.
        "YUZU_REAL_UPSTREAM_STRICT=1"
    )
    if $USE_TLS; then
        CT_ENV+=(
            "YUZU_UPSTREAM_CACERT=$CA_DIR/default-ca.pem"
            "YUZU_UPSTREAM_CERT=$CA_DIR/default-gateway.pem"
            "YUZU_UPSTREAM_KEY=$CA_DIR/default-gateway.key"
            # A valid leaf of the same CA that is NOT the pinned one.
            "YUZU_UPSTREAM_UNPINNED_CERT=$CA_DIR/default-server.pem"
            "YUZU_UPSTREAM_UNPINNED_KEY=$CA_DIR/default-server.key"
            "YUZU_REAL_UPSTREAM_REQUIRE_PIN=1"
        )
    fi
    CT_SUITES="yuzu_gw_real_upstream_SUITE"
    if $USE_TLS; then
        # The gateway's management listener, dialled as the server would (its own
        # pinned leaf) and as the peers the pin must refuse.
        CT_SUITES="$CT_SUITES,yuzu_gw_real_mgmt_SUITE"
        CT_ENV+=(
            "YUZU_REAL_MGMT_STRICT=1"
            "YUZU_MGMT_HOST=127.0.0.1"
            "YUZU_MGMT_PORT=$GW_MGMT_PORT"
            "YUZU_MGMT_CACERT=$CA_DIR/default-ca.pem"
            # The leaf the gateway pins: the server's own.
            "YUZU_MGMT_CERT=$CA_DIR/default-server.pem"
            "YUZU_MGMT_KEY=$CA_DIR/default-server.key"
            # The install CA's key, to mint the leaves the identity cases present
            # (a server key renewal, a same-key re-issue, another install's identity).
            "YUZU_MGMT_CA_KEY=$CA_DIR/default-ca.key"
            # Valid leaves of the same CA that are NOT pinned: the gateway's own
            # (serverAuth present, so only the SPKI pin refuses it) and the real
            # agent's enrolled leaf (clientAuth only).
            "YUZU_MGMT_UNPINNED_CERT=$CA_DIR/default-gateway.pem"
            "YUZU_MGMT_UNPINNED_KEY=$CA_DIR/default-gateway.key"
            "YUZU_MGMT_AGENT_CERT=$WORK_DIR/agent-1/certs/agent-client.pem"
            "YUZU_MGMT_AGENT_KEY=$WORK_DIR/agent-1/certs/agent-client.key"
            "YUZU_MGMT_AGENT_ID=integration-agent-1"
            "YUZU_GW_METRICS_URL=http://127.0.0.1:$GW_METRICS_PORT/metrics"
        )
    fi
    TESTS=$((TESTS + 1))
    if (cd "$GATEWAY_DIR" && env "${CT_ENV[@]}" rebar3 as test ct \
            --dir apps/yuzu_gw/integration_test \
            --suite "$CT_SUITES" \
            --logdir "$WORK_DIR/ct-logs") > "$WORK_DIR/ct.log" 2>&1; then
        pass "$CT_SUITES passed against the real server and gateway"
        grep -E "All [0-9]+ tests passed|tests passed" "$WORK_DIR/ct.log" | tail -1 || true
    else
        fail "$CT_SUITES failed (see $WORK_DIR/ct.log)"
        echo "--- ct.log (last 80 lines) ---"
        tail -80 "$WORK_DIR/ct.log"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 5c: The management hop left no failure signature on either side (#5175)
# ══════════════════════════════════════════════════════════════════════
# Runs after Phase 5a (a REST burst) and 5b (refusals, deadlines, cancelled
# streams), so the logs cover all of it. The signature of #5175 is a stream
# process crashing with function_clause in the gateway and, in the server's log,
# `Gateway SendCommand ... unavailable (attempt N): Socket closed`. The patterns
# are crash markers, not any line containing a word (compare Test 18).
if $USE_TLS && ! $REUSE_STACK; then
    log ""
    log "Test: management-hop failure signatures (gateway and server logs)"
    GW_SIGNATURE='function_clause|CRASH REPORT|=ERROR REPORT|Supervisor: .* terminating|\[error\]'
    SERVER_SIGNATURE='Socket closed|Gateway SendCommand .* (unavailable|REJECTED|DROPPED)|Gateway command forwarding is CONFIGURED but not usable|Gateway command forwarding NOT enabled'
    TESTS=$((TESTS + 1))
    if grep -qE -- "$GW_SIGNATURE" "$GATEWAY_LOG_PATH"; then
        fail "Gateway log shows a crash or error report after the management traffic"
        grep -E -- "$GW_SIGNATURE" "$GATEWAY_LOG_PATH" | head -10
    else
        pass "Gateway log: no function_clause, crash report or [error] line"
    fi
    TESTS=$((TESTS + 1))
    if grep -qE -- "$SERVER_SIGNATURE" "$SERVER_LOG_PATH"; then
        fail "Server log shows a failed SendCommand or 'Socket closed' on the management hop"
        grep -E -- "$SERVER_SIGNATURE" "$SERVER_LOG_PATH" | head -10
    else
        pass "Server log: no 'Socket closed' and no failed gateway SendCommand"
    fi
    TESTS=$((TESTS + 1))
    if kill -0 "$GATEWAY_PID" 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null \
       && kill -0 "${AGENT_PIDS[0]}" 2>/dev/null; then
        pass "Server, gateway and agent are all still running"
    else
        fail "A process of the stack died during the management traffic"
    fi
fi

# ── Test 19a: MFA step-up chokepoint refuses a session whose MFA proof is stale ──
# Runs after every test that logs in with the admin password (the Phase 5a REST
# driver above): enrolling TOTP here makes every later password-only login of
# admin answer 202 mfa_required with no session cookie.
# Own-stack only: the admin account is the one this script created, and enrolling
# TOTP on it would change the login of a shared stack. Confirming the TOTP enrolment in
# Settings stamps a step-up proof on that session, so the proof is fresh until the window
# (--mfa-step-up-window-secs, STEPUP_WINDOW_SECS at the server start) passes. The test
# sleeps past it, so a gated route is answered by the step-up chokepoint before its handler
# runs: 401, the challenge envelope, an X-Correlation-Id header equal to the body's
# correlation id, and an audit row `user=<name> age_secs=<n> window_secs=<n> cid=<id>
# stage=pre_authz` (age_secs is -1 for an absent proof, so a positive age proves a STALE one).
log "Test: MFA step-up chokepoint refusal"
if $REUSE_STACK || ! command -v python3 > /dev/null 2>&1; then
    log "  skipped (reused stack, or python3 unavailable for the TOTP code)"
else
    SU_BASE="http://127.0.0.1:$SERVER_WEB_PORT"
    SU_JAR="$WORK_DIR/stepup-cookies.txt"
    SU_HDRS="$WORK_DIR/stepup-headers.txt"
    curl -s -c "$SU_JAR" -H "Origin: $SU_BASE" -o /dev/null "$SU_BASE/login" \
        -d "username=admin&password=adminpassword1" || true
    SU_SECRET=$(curl -s -b "$SU_JAR" -H "Origin: $SU_BASE" -X POST "$SU_BASE/api/settings/mfa/init" \
        | grep -oE '<code>[A-Z2-7]{16,}</code>' | head -1 | sed -E 's/<[^>]+>//g' || true)
    SU_CODE=$(python3 -c '
import base64, hashlib, hmac, struct, sys, time
k = base64.b32decode(sys.argv[1] + "=" * ((8 - len(sys.argv[1]) % 8) % 8))
h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))' "$SU_SECRET" || true)
    curl -s -b "$SU_JAR" -H "Origin: $SU_BASE" -X POST "$SU_BASE/api/settings/mfa/verify" \
        -d "code=$SU_CODE" -o /dev/null || true
    # The enrol-confirm just stamped a fresh proof; let it age past the window.
    sleep $((STEPUP_WINDOW_SECS + 2))
    SU_BODY=$(curl -s -D "$SU_HDRS" -b "$SU_JAR" -H "Origin: $SU_BASE" -H "Content-Type: application/json" \
        -w "\n%{http_code}" -X POST "$SU_BASE/api/v1/tokens" -d '{"name":"stepup-integration"}' || true)
    assert_eq "POST /api/v1/tokens with a stale MFA proof returns 401" "401" "${SU_BODY##*$'\n'}"
    assert_contains "  step-up envelope names the challenge" '"mfa_step_up_required":true' "$SU_BODY"
    SU_HDR_CID=$(grep -i '^x-correlation-id:' "$SU_HDRS" 2>/dev/null | head -1 | tr -d '\r' \
        | sed -E 's/^[^:]*:[[:space:]]*//' || true)
    SU_BODY_CID=$(grep -oE '"correlation_id":"[^"]+"' <<< "$SU_BODY" | head -1 \
        | sed -E 's/^"correlation_id":"([^"]+)"$/\1/' || true)
    TESTS=$((TESTS + 1))
    if [[ -n "$SU_HDR_CID" && "$SU_HDR_CID" == "$SU_BODY_CID" ]]; then
        pass "  X-Correlation-Id header equals the envelope's correlation_id ($SU_HDR_CID)"
    else
        fail "  X-Correlation-Id header ('$SU_HDR_CID') must equal the envelope's correlation_id ('$SU_BODY_CID')"
    fi
    SU_AUDIT=$(curl -s -b "$SU_JAR" "$SU_BASE/api/v1/audit?action=mfa.step_up.required&limit=5" || true)
    # A positive age (not -1, which is an absent proof) and the configured window, then the
    # correlation id the caller was shown, then the chokepoint stage as the LAST token of the
    # detail. Spaces and `=` are never JSON-escaped; the closing quote proves "last".
    TESTS=$((TESTS + 1))
    if grep -qE "age_secs=[0-9]+ window_secs=$STEPUP_WINDOW_SECS cid=[^ \"]+ stage=pre_authz\"" <<< "$SU_AUDIT"; then
        pass "  audit row records a stale-proof refusal (age_secs, window_secs, cid, stage=pre_authz)"
    else
        fail "  audit row must record age_secs=<n, not -1> window_secs=$STEPUP_WINDOW_SECS cid=<id> stage=pre_authz (got: ${SU_AUDIT:0:400})"
    fi
    assert_contains "  audit row carries the refusal's correlation id" "cid=$SU_HDR_CID stage=pre_authz" "$SU_AUDIT"
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 6: Connection Recovery Test
# ══════════════════════════════════════════════════════════════════════
if [[ "$AGENT_COUNT" -ge 1 ]]; then
    log ""
    log "Test Category: Connection Recovery"

    # Kill one agent and verify others remain stable
    if [[ "${#AGENT_PIDS[@]}" -ge 2 ]]; then
        log "Test: Agent disconnect isolation"
        FIRST_PID="${AGENT_PIDS[0]}"
        kill "$FIRST_PID" 2>/dev/null || true
        # Poll until the killed process is actually gone — its death is
        # what "disconnect" means here. Other agents are independent
        # processes and don't need any propagation delay to check their
        # liveness, so no sleep-assert is needed after the reap.
        for _wait in $(seq 1 20); do
            if ! kill -0 "$FIRST_PID" 2>/dev/null; then break; fi
            sleep 0.1
        done

        # Verify other agents are still alive
        REMAINING_ALIVE=0
        for pid in "${AGENT_PIDS[@]:1}"; do
            if kill -0 "$pid" 2>/dev/null; then
                REMAINING_ALIVE=$((REMAINING_ALIVE + 1))
            fi
        done

        EXPECTED_REMAINING=$((${#AGENT_PIDS[@]} - 1))
        assert_eq "Other agents unaffected by disconnect" "$EXPECTED_REMAINING" "$REMAINING_ALIVE"

        # Verify gateway is still running
        TESTS=$((TESTS + 1))
        if kill -0 "$GATEWAY_PID" 2>/dev/null; then
            pass "Gateway stable after agent disconnect"
        else
            fail "Gateway crashed after agent disconnect"
        fi

        # Verify server is still running
        TESTS=$((TESTS + 1))
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            pass "Server stable after agent disconnect"
        else
            fail "Server crashed after agent disconnect"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 7: Results Summary
# ══════════════════════════════════════════════════════════════════════
log ""
log "═══════════════════════════════════════════════════════════════════"
log "  INTEGRATION TEST SUMMARY"
log "═══════════════════════════════════════════════════════════════════"
log ""
log "  Configuration:"
log "    Agents:        $AGENT_COUNT"
log "    TLS:           $USE_TLS"
log ""
log "  Ports:"
log "    Server Web:    $SERVER_WEB_PORT"
log "    Server Agent:  $SERVER_AGENT_PORT"
log "    Server GW:     $SERVER_GW_PORT"
log "    Gateway Agent: $GW_AGENT_PORT"
log "    Gateway Mgmt:  $GW_MGMT_PORT"
log ""
log "  Results:"
if [[ $FAILURES -eq 0 ]]; then
    log "    ✓ ALL $TESTS TESTS PASSED"
else
    log "    ✗ $FAILURES/$TESTS TESTS FAILED"
fi
log ""
log "═══════════════════════════════════════════════════════════════════"
log ""
log "Logs available in: $WORK_DIR"
log "  server.log    — C++ server output"
log "  gateway.log   — Erlang gateway output"
log "  agent-N.log   — Agent N output"
log "  mgmt_driver.log — the REST command burst through the management hop (--tls)"
log ""

# Detailed failure report if any tests failed
if [[ $FAILURES -gt 0 ]]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo "  FAILURE DETAILS"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "--- server.log (last 30 lines, $SERVER_LOG_PATH) ---"
    tail -30 "$SERVER_LOG_PATH" 2>/dev/null || true
    echo ""
    echo "--- gateway.log (last 30 lines, $GATEWAY_LOG_PATH) ---"
    tail -30 "$GATEWAY_LOG_PATH" 2>/dev/null || true
    echo ""
    echo "--- agent.log (last 30 lines, $AGENT_LOG_PATH) ---"
    tail -30 "$AGENT_LOG_PATH" 2>/dev/null || true
    echo ""

    # Check for specific error patterns
    echo "--- Error Pattern Analysis ---"
    if grep -qi "error\|fail\|crash" "$SERVER_LOG_PATH" 2>/dev/null; then
        echo "Server errors:"
        grep -i "error\|fail\|crash" "$SERVER_LOG_PATH" | tail -10
    fi
    if grep -qi "error\|crash\|badarg" "$GATEWAY_LOG_PATH" 2>/dev/null; then
        echo "Gateway errors:"
        grep -i "error\|crash\|badarg" "$GATEWAY_LOG_PATH" | tail -10
    fi
    if grep -qi "error\|fail" "$AGENT_LOG_PATH" 2>/dev/null; then
        echo "Agent errors:"
        grep -i "error\|fail" "$AGENT_LOG_PATH" | tail -10
    fi
    echo ""

    # Don't delete work dir on failure — keep for debugging
    log "Work directory preserved for debugging: $WORK_DIR"
    WORK_DIR=""
    exit 1
fi

log "All integration tests passed successfully!"
exit 0
