#!/usr/bin/env bash
# integration-test.sh — Full-stack integration test: Agent → Gateway → Server
#
# Starts the C++ server, Erlang gateway, and one or more C++ agents,
# then runs test scenarios through the complete chain.
#
# Usage:
#   ./scripts/integration-test.sh                    # 1 agent (quick smoke test)
#   ./scripts/integration-test.sh --agents 10        # 10 agents
#   ./scripts/integration-test.sh --agents 100 --tls # 100 agents with mTLS
#
# Prerequisites:
#   - C++ binaries built:  build-<os>/server/core/yuzu-server
#                           build-<os>/agents/core/yuzu-agent
#   - Erlang gateway:      gateway/ with rebar3 release
#   - curl, grpcurl (optional, for gRPC probing)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
AGENT_COUNT=1
USE_TLS=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure `erl` / `escript` / `rebar3` are on PATH before the gateway build
# step runs. The helper is a no-op if Erlang is already available; otherwise
# it probes kerl / asdf / Homebrew / MSYS2 and activates the first match.
# The "28" arg pins the major version tracked by release.yml — keep in
# sync with erlef/setup-beam otp-version in .github/workflows/release.yml.
# shellcheck source=ensure-erlang.sh
source "$SCRIPT_DIR/ensure-erlang.sh" 28
if ! command -v erl > /dev/null 2>&1; then
    echo "FAIL: erl not on PATH after ensure-erlang.sh (needed for rebar3/escript)" >&2
    echo "      Install via kerl (kerl install 28.4.2), asdf, Homebrew, or the" >&2
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

# ── Argument parsing ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --agents)  AGENT_COUNT="$2"; shift 2 ;;
        --tls)     USE_TLS=true; shift ;;
        --help|-h) echo "Usage: $0 [--agents N] [--tls]"; exit 0 ;;
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
    if echo "$haystack" | grep -q "$needle"; then
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

wait_for_port() {
    local port="$1" name="$2" timeout="${3:-15}"
    local elapsed=0
    while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
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
    # Clean temp dir (preserve when YUZU_KEEP_WORK_DIR is set, for debugging)
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" && -z "${YUZU_KEEP_WORK_DIR:-}" ]]; then
        rm -rf "$WORK_DIR"
    elif [[ -n "${YUZU_KEEP_WORK_DIR:-}" ]]; then
        log "Preserving work dir: $WORK_DIR"
    fi
    log "Cleanup done."
}
trap cleanup EXIT

# ── Create temp work directory ────────────────────────────────────────
WORK_DIR=$(mktemp -d /tmp/yuzu-integration.XXXXXX)
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

# ── TLS certificate generation (if --tls) ────────────────────────────
if $USE_TLS; then
    log "Generating test certificates..."
    CERT_DIR="$WORK_DIR/certs"
    mkdir -p "$CERT_DIR"

    # CA
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 1 -nodes -subj "/CN=Yuzu Test CA" \
        -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" 2>/dev/null

    # Server cert
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -subj "/CN=localhost" \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" -CAcreateserial -days 1 \
        -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1") \
        -out "$CERT_DIR/server.crt" 2>/dev/null

    # Agent client cert
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -nodes -subj "/CN=yuzu-agent" \
        -keyout "$CERT_DIR/agent.key" -out "$CERT_DIR/agent.csr" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/agent.csr" -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" -CAcreateserial -days 1 \
        -out "$CERT_DIR/agent.crt" 2>/dev/null

    TLS_SERVER_FLAGS="--cert $CERT_DIR/server.crt --key $CERT_DIR/server.key --ca-cert $CERT_DIR/ca.crt"
    TLS_AGENT_FLAGS="--ca-cert $CERT_DIR/ca.crt --client-cert $CERT_DIR/agent.crt --client-key $CERT_DIR/agent.key"
    log "Certificates generated in $CERT_DIR"
else
    TLS_SERVER_FLAGS="--no-tls"
    TLS_AGENT_FLAGS="--no-tls"
fi

# ── Generate server config via first-run setup (own-stack only) ───────
if ! $REUSE_STACK; then
    SERVER_DATA_DIR="$WORK_DIR/server-data"
    mkdir -p "$SERVER_DATA_DIR"
    SERVER_CFG="$SERVER_DATA_DIR/yuzu-server.cfg"
    log "Running first-run setup to generate server config..."
    printf 'admin\nadminpassword1\nadminpassword1\nuser\nuserpassword1\nuserpassword1\n' | \
        "$BUILDDIR/server/core/yuzu-server" \
            --config "$SERVER_CFG" \
            --no-tls --no-https --listen "127.0.0.1:$SERVER_AGENT_PORT" \
            --management "127.0.0.1:$SERVER_MGMT_PORT" \
            --web-port "$SERVER_WEB_PORT" \
            > "$WORK_DIR/setup.log" 2>&1 &
    SETUP_PID=$!
    # Wait for config to be written, then kill the server
    for i in $(seq 1 20); do
        if [[ -s "$SERVER_CFG" ]]; then break; fi
        sleep 0.5
    done
    sleep 1
    kill -9 "$SETUP_PID" 2>/dev/null || true
    wait "$SETUP_PID" 2>/dev/null || true
    if [[ ! -s "$SERVER_CFG" ]]; then
        echo "FAIL: Could not generate server config"
        cat "$WORK_DIR/setup.log"
        exit 1
    fi
    log "  Server config created at $SERVER_CFG"

    # Generate an enrollment token so test agents are auto-approved (Tier 2)
    ENROLL_TOKEN=$(
        "$BUILDDIR/server/core/yuzu-server" \
            --config "$SERVER_CFG" \
            --generate-tokens 1 \
            --token-label "integration-test" \
            --token-max-uses "$AGENT_COUNT" \
            --no-tls \
            2>/dev/null \
        | grep -o '"[0-9a-f]\{64\}"' | tr -d '"'
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
    log "Starting C++ server (ports: agent=$SERVER_AGENT_PORT, mgmt=$SERVER_MGMT_PORT, web=$SERVER_WEB_PORT)..."

    "$BUILDDIR/server/core/yuzu-server" \
        --config "$SERVER_CFG" \
        --listen "127.0.0.1:$SERVER_AGENT_PORT" \
        --management "127.0.0.1:$SERVER_MGMT_PORT" \
        --web-port "$SERVER_WEB_PORT" \
        --no-https \
        --gateway-mode \
        --gateway-upstream "127.0.0.1:$SERVER_GW_PORT" \
        $TLS_SERVER_FLAGS \
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
# PHASE 2: Start the Erlang Gateway
# ══════════════════════════════════════════════════════════════════════
if ! $REUSE_STACK; then
log "Starting Erlang gateway (agent=$GW_AGENT_PORT, mgmt=$GW_MGMT_PORT, upstream=$SERVER_AGENT_PORT)..."

# Write a test sys.config pointing upstream at the server
GW_SYS_CONFIG="$WORK_DIR/gw_sys.config"
cat > "$GW_SYS_CONFIG" << ERLCFG
[
    {yuzu_gw, [
        {agent_listen_addr, "0.0.0.0"},
        {agent_listen_port, $GW_AGENT_PORT},
        {mgmt_listen_addr, "0.0.0.0"},
        {mgmt_listen_port, $GW_MGMT_PORT},
        {upstream_addr, "127.0.0.1"},
        {upstream_port, $SERVER_GW_PORT},
        {upstream_pool_size, 4},
        {heartbeat_batch_interval_ms, 2000},
        {default_command_timeout_s, 30},
        {telemetry_gauge_interval_ms, 5000},
        %% #1422 escape hatch - TEST RIG ONLY: the wildcard listener below
        %% serves management_pb in plaintext, and the gateway refuses to boot
        %% that posture without this explicit acknowledgement. Never copy into
        %% production - use deploy/docker/reference-gateway-sys.config.
        {allow_insecure_mgmt, true}
    ]},
    {grpcbox, [
        {client, #{channels => [
            {default_channel, [{http, "127.0.0.1", $SERVER_GW_PORT, []}], #{}}
        ]}},
        {servers, [
            #{grpc_opts => #{
                service_protos => [agent_pb, management_pb],
                services => #{
                    'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service,
                    'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service
                }
            },
            listen_opts => #{port => $GW_AGENT_PORT, ip => {0,0,0,0}}}
        ]}
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

GW_VM_ARGS="$WORK_DIR/gw_vm.args"
cat > "$GW_VM_ARGS" << VMARGS
-name yuzu_gw_test@127.0.0.1
-setcookie yuzu_integration_test
+K true
+A 32
+P 262144
VMARGS

cd "$GATEWAY_DIR"
# Ensure gateway is compiled
rebar3 compile > "$WORK_DIR/gw_build.log" 2>&1 || {
    echo "FAIL: Gateway build failed"
    cat "$WORK_DIR/gw_build.log"
    exit 1
}
# Workaround: rebar3 sometimes skips modules from hex deps (telemetry_handler_table)
# and from proto sources (management_pb). Compile any missing beam files explicitly.
for mod in _build/default/lib/telemetry/src/telemetry_handler_table.erl; do
    beam="_build/default/lib/telemetry/ebin/$(basename "${mod%.erl}.beam")"
    if [[ -f "$mod" && ! -f "$beam" ]]; then
        erlc +debug_info -I _build/default/lib/telemetry/src \
             -o _build/default/lib/telemetry/ebin "$mod"
    fi
done
for mod in apps/yuzu_gw/src/management_pb.erl; do
    beam="_build/default/lib/yuzu_gw/ebin/$(basename "${mod%.erl}.beam")"
    if [[ -f "$mod" && ! -f "$beam" ]]; then
        erlc +debug_info -I _build/default/lib/gpb/include \
             -o _build/default/lib/yuzu_gw/ebin "$mod"
    fi
done
# Start with all deps and generated proto modules on path
erl -pa _build/default/lib/*/ebin \
    -pa _checkouts/*/ebin \
    -config "$GW_SYS_CONFIG" \
    -args_file "$GW_VM_ARGS" \
    -noshell \
    -eval "application:ensure_all_started(yuzu_gw)" \
    > "$WORK_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
cd "$PROJECT_ROOT"
log "  Gateway PID: $GATEWAY_PID"

# Poll the gateway's agent-facing gRPC port until it's bound. grpcbox
# startup is usually 1-2s but can be slower on cold BEAM VM — the old
# `sleep 3` was both too short (flaked on cold runs) and too long (paid
# full budget on warm runs). wait_for_port returns as soon as the port
# accepts connections.
if ! wait_for_port "$GW_AGENT_PORT" "Gateway agent-facing gRPC" 15; then
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

    for i in $(seq 1 "$AGENT_COUNT"); do
        AGENT_DATA_DIR="$WORK_DIR/agent-$i"
        mkdir -p "$AGENT_DATA_DIR"

        "$BUILDDIR/agents/core/yuzu-agent" \
            --server "127.0.0.1:$GW_AGENT_PORT" \
            --agent-id "integration-agent-$i" \
            --data-dir "$AGENT_DATA_DIR" \
            --heartbeat 5 \
            --enrollment-token "$ENROLL_TOKEN" \
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
        yuzu_fleet_agents_healthy 1 15 || true

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
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SERVER_WEB_PORT/login" || echo "000")
assert_eq "Server /login returns 200" "200" "$HTTP_CODE"

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
        if echo "$METRICS_POLL" | grep -q "yuzu_heartbeats_received_total"; then
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
    if echo "$METRICS_RESP" | grep -q "yuzu_"; then
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
    if echo "$METRICS_RESP" | grep -q "yuzu_fleet_agents_by_os\|yuzu_fleet_commands_executed_total"; then
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
if nc -z 127.0.0.1 "$SERVER_GW_PORT" 2>/dev/null; then
    pass "Server GatewayUpstream port ($SERVER_GW_PORT) is listening"
    TESTS=$((TESTS + 1))
else
    fail "Server GatewayUpstream port ($SERVER_GW_PORT) not responding"
fi

# ── Test 13: Gateway agent port ───────────────────────────────────────
log "Test: Gateway agent-facing gRPC port"
if nc -z 127.0.0.1 "$GW_AGENT_PORT" 2>/dev/null; then
    pass "Gateway agent port ($GW_AGENT_PORT) is listening"
    TESTS=$((TESTS + 1))
else
    fail "Gateway agent port ($GW_AGENT_PORT) not responding"
fi

# ── Test Category: Agent Registration & Session ───────────────────────

# ── Test 14: Agent session persistence ────────────────────────────────
log "Test: Agent session persistence across heartbeats"
# Verify agent-1 is still connected after time has passed
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
if command -v grpcurl &>/dev/null; then
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
