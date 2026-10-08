#!/usr/bin/env bash
# win-start-UAT.sh — Full Yuzu UAT on Windows (MSYS2/bash)
#
# Topology (all agent traffic flows through the gateway):
#   Agent --> Gateway(:50051) --> Server(:50055 upstream)
#   Server --> Gateway(:50063) --> Agent   (command fanout)
#
# Single-host UAT note: the server's direct agent listener is moved off
# the default :50051 to :50054 so the gateway can take :50051 for its
# agent-facing port. In production they live on separate hosts and this
# isn't necessary.
#
# Monitoring & Analytics (Docker containers):
#   Prometheus(:9090) scrapes Server(:8080/metrics) + Gateway(:9568/metrics)
#   Grafana(:3000) reads from Prometheus + ClickHouse, dashboards auto-provisioned
#   ClickHouse(:8123) receives analytics events from Server
#
# Usage:
#   bash scripts/win-start-UAT.sh          # start all
#   bash scripts/win-start-UAT.sh stop     # kill all
#   bash scripts/win-start-UAT.sh status   # show running processes

set -euo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDDIR="$YUZU_ROOT/builddir"
GATEWAY_DIR="$YUZU_ROOT/gateway"
UAT_DIR="$YUZU_ROOT/.uat"

ADMIN_USER="admin"
ADMIN_PASS='YuzuUatAdmin1!'

# Ensure Docker CLI is on PATH (Docker Desktop doesn't always add it after reboot)
if ! command -v docker > /dev/null 2>&1; then
    for docker_bin in \
        "/c/Program Files/Docker/Docker/resources/bin" \
        "$PROGRAMFILES/Docker/Docker/resources/bin"; do
        if [ -f "$docker_bin/docker.exe" ]; then
            export PATH="$PATH:$docker_bin"
            break
        fi
    done
fi

# Colours
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

ok()   { echo -e "  ${GREEN}OK${NC} $*"; }
fail() { echo -e "  ${RED}FAIL${NC} $*"; }
warn() { echo -e "  ${YELLOW}WARN${NC} $*"; }
info() { echo -e "  ${CYAN}>>${NC} $*"; }

# ── Kill helpers ──────────────────────────────────────────────────────────

kill_native() {
    echo "Cleaning up native processes..."
    local killed=0
    for proc in yuzu-agent.exe yuzu-server.exe; do
        if tasklist 2>/dev/null | grep -qi "$proc"; then
            taskkill //F //IM "$proc" 2>/dev/null && killed=$((killed + 1)) || true
        fi
    done
    # Erlang BEAM (gateway) — on Windows the process is erl.exe, not beam.smp
    for erlproc in erl.exe beam.smp.exe werl.exe; do
        if tasklist 2>/dev/null | grep -qi "$erlproc"; then
            taskkill //F //IM "$erlproc" 2>/dev/null && killed=$((killed + 1)) || true
        fi
    done
    if [ "$killed" -eq 0 ]; then
        ok "No stale native processes"
    else
        ok "Killed $killed process(es)"
        # Wait for gateway ports to be released by the OS (TCP TIME_WAIT)
        local port_wait=0
        while netstat -an 2>/dev/null | grep -q ":50063.*LISTEN\|:50051.*LISTEN"; do
            sleep 1
            port_wait=$((port_wait + 1))
            if [ "$port_wait" -ge 10 ]; then
                warn "Gateway ports still held after 10s — continuing anyway"
                break
            fi
        done
    fi
    sleep 1
}

kill_docker() {
    echo "Stopping Docker containers..."
    cd "$YUZU_ROOT/deploy/docker"
    docker compose -f docker-compose.uat.yml down -v 2>/dev/null && ok "Containers stopped" || ok "No containers running"
    cd "$YUZU_ROOT"
}

# ── Status ────────────────────────────────────────────────────────────────

show_status() {
    echo "=== Yuzu UAT Stack Status ==="
    echo ""
    echo "Native processes:"
    for proc in yuzu-server.exe yuzu-agent.exe beam.smp.exe; do
        if tasklist 2>/dev/null | grep -qi "$proc"; then
            ok "$proc running"
        else
            fail "$proc not running"
        fi
    done
    echo ""
    echo "Docker containers:"
    cd "$YUZU_ROOT/deploy/docker"
    docker compose -f docker-compose.uat.yml ps 2>/dev/null || echo "  (compose not running)"
    cd "$YUZU_ROOT"
    echo ""
    echo "Endpoints:"
    echo "  Dashboard:   http://localhost:8080"
    echo "  Grafana:     http://localhost:3000 (admin/admin)"
    echo "  Prometheus:  http://localhost:9090"
    echo "  ClickHouse:  http://localhost:8123 (HTTP) / localhost:9000 (native)"
    echo "  GW Health:   http://localhost:8081/readyz"
    echo "  GW Metrics:  http://localhost:9568/metrics"
}

# ── Wait for port ─────────────────────────────────────────────────────────

wait_for_port() {
    local port=$1 name=$2 timeout=${3:-15}
    local elapsed=0
    while ! netstat -an 2>/dev/null | grep -q ":${port}.*LISTENING"; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            fail "$name did not bind to :$port within ${timeout}s"
            return 1
        fi
    done
    # SRE-2 — surface cold-start duration so future drift is visible.
    echo "  ✓ $name bound to :$port in ${elapsed}s"
    return 0
}

# ── Wait for HTTP endpoint ────────────────────────────────────────────────

wait_for_http() {
    local url=$1 name=$2 timeout=${3:-20}
    local elapsed=0
    while true; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        if [ "$code" != "000" ]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "$elapsed" -ge "$timeout" ]; then
            fail "$name not reachable at $url within ${timeout}s"
            return 1
        fi
    done
}

# ── Generate server config ────────────────────────────────────────────────

generate_config() {
    python -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', '${ADMIN_PASS}'.encode(), salt, 100000, dklen=32)
print(f'${ADMIN_USER}:admin:{salt.hex()}:{dk.hex()}')
" > "$UAT_DIR/yuzu-server.cfg"
}

# ── Prepare Grafana dashboards ────────────────────────────────────────────
# Convert import-format dashboards (${DS_PROMETHEUS}) to provisioned format

prepare_dashboards() {
    local src="$YUZU_ROOT/deploy/grafana"
    local dst="$UAT_DIR/dashboards"
    mkdir -p "$dst"

    for f in "$src"/*.json; do
        local base
        base=$(basename "$f")
        # Replace import variables with provisioned datasource refs
        sed \
            -e 's|"\${DS_PROMETHEUS}"|{"type": "prometheus", "uid": "prometheus"}|g' \
            -e 's|"\${DS_CLICKHOUSE}"|{"type": "grafana-clickhouse-datasource", "uid": "clickhouse"}|g' \
            "$f" > "$dst/$base"
    done

    # Also copy alert rules if present
    if [ -f "$src/yuzu-alerts.yml" ]; then
        cp "$src/yuzu-alerts.yml" "$dst/"
    fi
}

# ── Start everything ──────────────────────────────────────────────────────

start_all() {
    echo ""
    echo "=============================================="
    echo "         Yuzu UAT Environment (Windows)       "
    echo "=============================================="
    echo ""

    # ── Preflight ─────────────────────────────────────────────────────────
    local errors=0
    if [ ! -f "$BUILDDIR/server/core/yuzu-server.exe" ]; then
        fail "yuzu-server.exe not found — run: meson compile -C builddir"
        errors=$((errors + 1))
    fi
    if [ ! -f "$BUILDDIR/agents/core/yuzu-agent.exe" ]; then
        fail "yuzu-agent.exe not found — run: meson compile -C builddir"
        errors=$((errors + 1))
    fi
    if [ ! -d "$GATEWAY_DIR/ebin" ] && [ ! -d "$GATEWAY_DIR/_build/default/lib/yuzu_gw/ebin" ]; then
        fail "Gateway not compiled — run: cd gateway && rebar3 compile"
        errors=$((errors + 1))
    fi
    if ! command -v erl > /dev/null 2>&1; then
        fail "erl not found in PATH"
        errors=$((errors + 1))
    fi
    if ! docker info > /dev/null 2>&1; then
        info "Docker not running — attempting to start Docker Desktop..."
        # Try common install locations
        local docker_exe=""
        for candidate in \
            "/c/Program Files/Docker/Docker/Docker Desktop.exe" \
            "$PROGRAMFILES/Docker/Docker/Docker Desktop.exe" \
            "$LOCALAPPDATA/Docker/Docker Desktop.exe"; do
            if [ -f "$candidate" ]; then
                docker_exe="$candidate"
                break
            fi
        done
        if [ -z "$docker_exe" ]; then
            fail "Docker not running and Docker Desktop not found"
            errors=$((errors + 1))
        else
            "$docker_exe" &
            disown
            # Poll until Docker daemon responds (up to 60s)
            local docker_wait=0
            while ! docker info > /dev/null 2>&1; do
                sleep 2
                docker_wait=$((docker_wait + 2))
                if [ "$docker_wait" -ge 60 ]; then
                    fail "Docker Desktop did not start within 60s"
                    errors=$((errors + 1))
                    break
                fi
            done
            if docker info > /dev/null 2>&1; then
                ok "Docker Desktop started (${docker_wait}s)"
            fi
        fi
    fi
    if [ "$errors" -gt 0 ]; then
        echo ""; fail "$errors preflight check(s) failed — aborting"
        exit 1
    fi
    ok "Preflight checks passed"

    # ── Clean state ───────────────────────────────────────────────────────
    kill_native
    kill_docker
    rm -rf "$UAT_DIR"
    mkdir -p "$UAT_DIR/agent-data" "$UAT_DIR/dashboards"

    # ── Generate credentials ──────────────────────────────────────────────
    generate_config
    ok "Generated server config ($ADMIN_USER / $ADMIN_PASS)"

    # ── Prepare dashboards for Grafana provisioning ───────────────────────
    prepare_dashboards
    ok "Prepared provisioned dashboards"

    # ── 1. Docker (Prometheus + Grafana + ClickHouse) ───────────────────
    echo ""
    echo "[1/4] Starting Prometheus + Grafana + ClickHouse (Docker)..."
    cd "$YUZU_ROOT/deploy/docker"
    UAT_DASHBOARDS="$UAT_DIR/dashboards" docker compose -f docker-compose.uat.yml up -d 2>&1 | tail -5
    cd "$YUZU_ROOT"

    if ! wait_for_http "http://localhost:9090/-/ready" "Prometheus" 30; then
        warn "Prometheus may still be starting"
    else
        ok "Prometheus up at http://localhost:9090"
    fi
    if ! wait_for_http "http://localhost:8123/ping" "ClickHouse" 30; then
        warn "ClickHouse may still be starting"
    else
        ok "ClickHouse up at http://localhost:8123"
    fi
    if ! wait_for_http "http://localhost:3000/api/health" "Grafana" 45; then
        warn "Grafana may still be starting (installing ClickHouse plugin...)"
    else
        ok "Grafana up at http://localhost:3000 (admin/admin)"
    fi

    # ── 2. Server ─────────────────────────────────────────────────────────
    echo ""
    echo "[2/4] Starting yuzu-server..."
    # Plaintext rig: --insecure-gateway-peer explicitly acknowledges that peer
    # authorization on the gateway-upstream service is disabled. Not for
    # production.
    "$BUILDDIR/server/core/yuzu-server.exe" \
        --no-tls \
        --no-https \
        --listen 0.0.0.0:50054 \
        --gateway-upstream 0.0.0.0:50055 \
        --insecure-gateway-peer \
        --gateway-mode \
        --gateway-command-addr localhost:50063 \
        --web-address 0.0.0.0 \
        --log-level info \
        --metrics-no-auth \
        --config "$UAT_DIR/yuzu-server.cfg" \
        --clickhouse-url http://127.0.0.1:8123 \
        --clickhouse-database yuzu \
        --clickhouse-table yuzu_events \
        --clickhouse-user default \
        --analytics-drain-interval 5 \
        --analytics-batch-size 50 \
        > "$UAT_DIR/server.log" 2>&1 &
    disown

    if ! wait_for_port 8080 "yuzu-server" 30; then
        fail "Server failed to start — check $UAT_DIR/server.log"
        exit 1
    fi
    ok "Server up (dashboard http://localhost:8080)"
    info "Direct agent gRPC :50054 | Gateway upstream :50055 | Mgmt :50052"

    # ── 3. Gateway ────────────────────────────────────────────────────────
    echo ""
    echo "[3/4] Starting Erlang gateway..."
    (cd "$GATEWAY_DIR" && erl \
        -pa ebin \
        -pa _build/default/lib/*/ebin \
        -config config/sys \
        -eval "application:ensure_all_started(yuzu_gw)" \
        -noshell \
        > "$UAT_DIR/gateway.log" 2>&1) &
    disown

    if ! wait_for_port 50051 "gateway (agent-facing)" 15; then
        fail "Gateway failed to start — check $UAT_DIR/gateway.log"
        exit 1
    fi
    if ! wait_for_port 50063 "gateway (mgmt/command)" 30; then
        fail "Gateway mgmt port :50063 not ready — command forwarding will fail"
        exit 1
    fi
    ok "Gateway up"
    info "Agent-facing :50051 | Command mgmt :50063 | Metrics :9568 | Health :8081"

    # ── Login & enrollment token ──────────────────────────────────────────
    info "Creating enrollment token..."
    curl -s -c "$UAT_DIR/cookies.txt" http://localhost:8080/login \
        -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null

    local token_html
    token_html=$(curl -s -b "$UAT_DIR/cookies.txt" \
        -X POST http://localhost:8080/api/settings/enrollment-tokens \
        -d "label=uat-auto&max_uses=1000&ttl=86400")
    local enroll_token
    enroll_token=$(echo "$token_html" | python -c "import sys,re; m=re.search(r'[a-f0-9]{64}', sys.stdin.read()); print(m.group() if m else '')" 2>/dev/null || true)

    if [ -z "$enroll_token" ]; then
        fail "Failed to create enrollment token"
        exit 1
    fi
    echo "$enroll_token" > "$UAT_DIR/enrollment-token"
    ok "Enrollment token created"

    # ── 4. Agent (via gateway) ────────────────────────────────────────────
    echo ""
    echo "[4/4] Starting yuzu-agent (-> gateway :50051)..."
    "$BUILDDIR/agents/core/yuzu-agent.exe" \
        --server localhost:50051 \
        --no-tls \
        --data-dir "$UAT_DIR/agent-data" \
        --plugin-dir "$BUILDDIR/agents/plugins" \
        --log-level info \
        --enrollment-token "$enroll_token" \
        > "$UAT_DIR/agent.log" 2>&1 &
    disown

    # Wait for registration
    local waited=0
    while ! grep -q "Registered with server" "$UAT_DIR/agent.log" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge 15 ]; then
            fail "Agent did not register within 15s — check $UAT_DIR/agent.log"
            exit 1
        fi
    done
    local session_id
    session_id=$(grep "Registered with server" "$UAT_DIR/agent.log" | python -c "import sys,re; lines=sys.stdin.read(); m=re.findall(r'session=[^ ,)]+', lines); print(m[-1] if m else 'unknown')" 2>/dev/null || echo "unknown")
    ok "Agent up ($session_id)"

    if echo "$session_id" | grep -q "gw-session"; then
        ok "Agent confirmed via gateway (gw-session prefix)"
    else
        warn "Agent session: $session_id (may not be routed through gateway)"
    fi

    # ── Connectivity tests ────────────────────────────────────────────────
    echo ""
    echo "=== Connectivity Tests ==="

    local tests_passed=0 tests_total=0

    # Test 1: Dashboard
    tests_total=$((tests_total + 1))
    local dash_code
    dash_code=$(curl -s -o /dev/null -w "%{http_code}" -b "$UAT_DIR/cookies.txt" http://localhost:8080/ 2>/dev/null)
    if [ "$dash_code" = "200" ]; then
        ok "Dashboard reachable (HTTP $dash_code)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Dashboard returned HTTP $dash_code"
    fi

    # Test 2: Gateway health
    tests_total=$((tests_total + 1))
    local gw_health
    gw_health=$(curl -s -m 3 http://localhost:8081/readyz 2>/dev/null || echo '{"status":"error"}')
    if echo "$gw_health" | grep -q '"ready"'; then
        ok "Gateway healthy"
        tests_passed=$((tests_passed + 1))
    else
        fail "Gateway health: $gw_health"
    fi

    # Test 3: Server metrics — agent registered
    tests_total=$((tests_total + 1))
    local reg_count
    reg_count=$(curl -s http://localhost:8080/metrics 2>/dev/null | python -c "import sys,re; m=re.search(r'yuzu_agents_registered_total (\d+)', sys.stdin.read()); print(m.group(1) if m else '0')" 2>/dev/null || echo "0")
    if [ "$reg_count" -ge 1 ]; then
        ok "Server sees $reg_count registered agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Server shows 0 registered agents"
    fi

    # Test 4: Gateway metrics — agent connected
    tests_total=$((tests_total + 1))
    local gw_agents
    gw_agents=$(curl -s http://localhost:9568/metrics 2>/dev/null | python -c "import sys,re; m=re.search(r'yuzu_gw_agents_connected_total\{[^}]*\} (\d+)', sys.stdin.read()); print(m.group(1) if m else '0')" 2>/dev/null || echo "0")
    if [ "$gw_agents" -ge 1 ]; then
        ok "Gateway shows $gw_agents connected agent(s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "Gateway shows 0 connected agents"
    fi

    # Test 5: Prometheus scraping
    tests_total=$((tests_total + 1))
    sleep 3  # let Prometheus do a scrape cycle
    local prom_targets
    prom_targets=$(curl -s http://localhost:9090/api/v1/targets 2>/dev/null)
    local up_count
    up_count=$(echo "$prom_targets" | python -c "
import sys, json
try:
    d = json.load(sys.stdin)
    active = d.get('data',{}).get('activeTargets',[])
    print(sum(1 for t in active if t.get('health') == 'up'))
except: print(0)
" 2>/dev/null)
    if [ "$up_count" -ge 1 ]; then
        ok "Prometheus scraping $up_count target(s)"
        tests_passed=$((tests_passed + 1))
    else
        warn "Prometheus targets not yet up ($up_count) — may need another scrape cycle"
    fi

    # Test 6: Grafana health
    tests_total=$((tests_total + 1))
    local grafana_ok
    grafana_ok=$(curl -s http://localhost:3000/api/health 2>/dev/null | grep -c '"ok"' || echo "0")
    if [ "$grafana_ok" -ge 1 ]; then
        ok "Grafana healthy"
        tests_passed=$((tests_passed + 1))
    else
        fail "Grafana not healthy"
    fi

    # Test 7: ClickHouse reachable and schema applied
    tests_total=$((tests_total + 1))
    local ch_tables
    ch_tables=$(curl -s "http://localhost:8123/?query=SHOW+TABLES+FROM+yuzu" 2>/dev/null || echo "")
    if echo "$ch_tables" | grep -q "yuzu_events"; then
        ok "ClickHouse: yuzu.yuzu_events table exists"
        tests_passed=$((tests_passed + 1))
    else
        fail "ClickHouse: yuzu_events table not found"
    fi

    # Test 8: help command (plugin listing via /api/help/html)
    echo ""
    echo "=== Command Tests ==="
    tests_total=$((tests_total + 1))
    local help_html
    help_html=$(curl -s -m 10 -b "$UAT_DIR/cookies.txt" \
        http://localhost:8080/api/help/html 2>/dev/null)
    local plugin_count
    plugin_count=$(echo "$help_html" | grep -o 'result-row' | wc -l)
    if [ "$plugin_count" -gt 0 ]; then
        ok "help: $plugin_count plugin actions listed"
        tests_passed=$((tests_passed + 1))
    else
        fail "help: no plugin actions returned"
    fi

    # Test 9: os_info round-trip (server -> gateway -> agent -> gateway -> server)
    tests_total=$((tests_total + 1))
    info "Sending 'os_info os_name' (full round-trip via gateway)..."
    local cmd_resp
    cmd_resp=$(curl -s -m 10 -b "$UAT_DIR/cookies.txt" \
        -X POST http://localhost:8080/api/command \
        -H "Content-Type: application/json" \
        -d '{"plugin":"os_info","action":"os_name"}' 2>/dev/null)
    local cmd_id
    cmd_id=$(echo "$cmd_resp" | python -c "import sys,json; print(json.load(sys.stdin).get('command_id',''))" 2>/dev/null || true)

    if [ -z "$cmd_id" ]; then
        fail "os_info: failed to dispatch (response: $cmd_resp)"
    else
        info "Command dispatched: $cmd_id"
        local os_result="" poll_count=0
        while [ $poll_count -lt 15 ]; do
            sleep 1
            poll_count=$((poll_count + 1))
            os_result=$(curl -s -b "$UAT_DIR/cookies.txt" \
                "http://localhost:8080/api/responses/$cmd_id" 2>/dev/null | \
                python -c "
import sys,json
d=json.load(sys.stdin)
for r in d.get('responses',[]):
    o = r.get('output','')
    if 'os_name|' in o:
        print(o.split('|',1)[1])
        break
" 2>/dev/null || true)
            [ -n "$os_result" ] && break
        done

        if [ -n "$os_result" ]; then
            ok "os_info: $os_result (round-trip ${poll_count}s)"
            tests_passed=$((tests_passed + 1))
        else
            fail "os_info: no response after ${poll_count}s"
            warn "Check: $UAT_DIR/server.log and $UAT_DIR/gateway.log"
        fi
    fi

    # Test 10: ClickHouse analytics ingest (poll until drain fires)
    # The server drains events from SQLite to ClickHouse every 5s.
    # Poll up to 15s (3 drain cycles) rather than sleeping a fixed amount.
    tests_total=$((tests_total + 1))
    info "Waiting for analytics drain to ClickHouse..."
    local ch_count=0
    local ch_attempt=0
    for ch_attempt in $(seq 1 15); do
        ch_count=$(curl -s "http://localhost:8123/?query=SELECT+count()+FROM+yuzu.yuzu_events" 2>/dev/null || echo "0")
        ch_count=$(echo "$ch_count" | tr -d '[:space:]')
        if [ "$ch_count" -gt 0 ] 2>/dev/null; then
            break
        fi
        sleep 1
    done
    if [ "$ch_count" -gt 0 ] 2>/dev/null; then
        ok "ClickHouse: $ch_count event(s) ingested (${ch_attempt}s)"
        tests_passed=$((tests_passed + 1))
    else
        fail "ClickHouse: no events after 15s — check server analytics config"
    fi

    # ── Summary ───────────────────────────────────────────────────────────
    echo ""
    if [ "$tests_passed" -eq "$tests_total" ]; then
        echo -e "${GREEN}=== All $tests_total/$tests_total tests passed ===${NC}"
    else
        echo -e "${YELLOW}=== $tests_passed/$tests_total tests passed ===${NC}"
    fi

    echo ""
    echo "=============================================="
    echo "           UAT Stack Ready                    "
    echo "=============================================="
    echo ""
    echo "  Dashboard:   http://localhost:8080"
    printf "  Login:       %s / %s\n" "$ADMIN_USER" "$ADMIN_PASS"
    echo "  Grafana:     http://localhost:3000 (admin/admin)"
    echo "  Prometheus:  http://localhost:9090"
    echo "  ClickHouse:  http://localhost:8123"
    echo ""
    echo "  GW Health:   http://localhost:8081/readyz"
    echo "  GW Metrics:  http://localhost:9568/metrics"
    echo ""
    echo "  Agent -> GW(:50051) -> Server(:50055)   [data]"
    echo "  Server -> GW(:50063) -> Agent           [commands]"
    echo "  Server -> ClickHouse(:8123)             [analytics]"
    echo "  Prometheus -> Server(:8080) + GW(:9568) [metrics]"
    echo "  Grafana -> Prometheus + ClickHouse      [dashboards]"
    echo ""
    echo "  Logs: $UAT_DIR/{server,gateway,agent}.log"
    echo "  Stop: bash scripts/win-start-UAT.sh stop"
    echo "=============================================="
}

# ── Main ──────────────────────────────────────────────────────────────────

case "${1:-start}" in
    start)  start_all ;;
    stop)   kill_native; kill_docker; echo "UAT stack stopped." ;;
    status) show_status ;;
    *)      echo "Usage: $0 {start|stop|status}"; exit 1 ;;
esac
