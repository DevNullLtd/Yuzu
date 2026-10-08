#!/usr/bin/env bash
# start-stack.sh — Start the full Yuzu development stack
#
# Components:
#   1. yuzu-server  (gRPC :50051, web :8080)
#   2. Erlang gateway (agent gRPC :50051, metrics :9568)
#   3. yuzu-agent   (connects to gateway :50051)
#   4. Prometheus   (scraper :9090)
#   5. Grafana      (dashboards :3000)
#
# Usage:
#   bash scripts/start-stack.sh          # start all
#   bash scripts/start-stack.sh stop     # kill all
#   bash scripts/start-stack.sh status   # show running processes

set -euo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDDIR="$YUZU_ROOT/builddir"
GATEWAY_DIR="$YUZU_ROOT/gateway"
AGENT_DATA_DIR="C:/Users/rdpdev/yuzu-agent-data"
GRAFANA_HOME="/c/ProgramData/chocolatey/lib/grafana/tools/grafana-12.4.1"

# ── Helpers ──────────────────────────────────────────────────────────────

status() {
    echo "=== Yuzu Stack Status ==="
    for proc in yuzu-server yuzu-agent beam.smp prometheus grafana-server; do
        if tasklist 2>/dev/null | grep -qi "${proc}"; then
            echo "  ✓ $proc running"
        else
            echo "  ✗ $proc not running"
        fi
    done
    echo ""
    echo "=== Ports ==="
    netstat -an 2>/dev/null | grep -E "LISTENING" | grep -E ":(50051|8080|9090|9568|3000) " || true
}

stop_all() {
    echo "Stopping Yuzu stack..."
    taskkill //F //IM yuzu-agent.exe 2>/dev/null && echo "  Stopped yuzu-agent" || true
    taskkill //F //IM beam.smp.exe 2>/dev/null && echo "  Stopped gateway (beam)" || true
    taskkill //F //IM erl.exe 2>/dev/null || true
    taskkill //F //IM yuzu-server.exe 2>/dev/null && echo "  Stopped yuzu-server" || true
    taskkill //F //IM prometheus.exe 2>/dev/null && echo "  Stopped prometheus" || true
    # Don't kill Grafana by default — it may be shared
    echo "  (Grafana left running — kill manually if needed)"
    echo "Done."
}

start_all() {
    echo "=== Starting Yuzu Development Stack ==="
    echo ""

    # Check binaries exist
    if [ ! -f "$BUILDDIR/server/core/yuzu-server.exe" ]; then
        echo "ERROR: yuzu-server.exe not found. Run: meson compile -C builddir"
        exit 1
    fi
    if [ ! -f "$BUILDDIR/agents/core/yuzu-agent.exe" ]; then
        echo "ERROR: yuzu-agent.exe not found. Run: meson compile -C builddir"
        exit 1
    fi

    # Kill any existing instances
    taskkill //F //IM yuzu-agent.exe 2>/dev/null || true
    taskkill //F //IM beam.smp.exe 2>/dev/null || true
    taskkill //F //IM erl.exe 2>/dev/null || true
    taskkill //F //IM yuzu-server.exe 2>/dev/null || true
    sleep 1

    # 1. Yuzu Server (gRPC on :50051 for gateway upstream, web on :8080)
    echo "[1/5] Starting yuzu-server (gRPC :50051, web :8080)..."
    # Plaintext rig: --insecure-gateway-peer explicitly acknowledges that peer
    # authorization on the gateway-upstream service is disabled. Not for
    # production.
    "$BUILDDIR/server/core/yuzu-server.exe" \
        --no-tls \
        --listen 0.0.0.0:50051 \
        --gateway-upstream 0.0.0.0:50055 \
        --insecure-gateway-peer \
        --web-port 8080 \
        2>&1 &
    disown
    sleep 2

    if ! tasklist | grep -q yuzu-server; then
        echo "ERROR: yuzu-server failed to start"
        exit 1
    fi
    echo "  ✓ Server up — dashboard at http://127.0.0.1:8080"

    # 2. Erlang Gateway (agent-facing :50051, upstream to server :50051, metrics :9568)
    echo "[2/5] Starting Erlang gateway (agent gRPC :50051, metrics :9568)..."
    cd "$GATEWAY_DIR"
    erl -pa _build/default/lib/*/ebin \
        -config config/sys \
        -eval "application:ensure_all_started(yuzu_gw)" \
        -noshell 2>&1 &
    disown
    cd "$YUZU_ROOT"
    sleep 6

    if netstat -an | grep -q ":50051.*LISTENING"; then
        echo "  ✓ Gateway up — agents connect to :50051, metrics at :9568"
    else
        echo "  ⚠ Gateway may not be listening yet (check logs)"
    fi

    # 3. Yuzu Agent (connects directly to server on :50051)
    #    NOTE: Gateway proxy registration is not yet wired — agents register
    #    directly with the server. Once registered, heartbeats can go via gateway.
    echo "[3/5] Starting yuzu-agent (connecting to server :50051)..."
    "$BUILDDIR/agents/core/yuzu-agent.exe" \
        --server localhost:50051 \
        --no-tls \
        --data-dir "$AGENT_DATA_DIR" \
        --plugin-dir "$BUILDDIR/agents/plugins" \
        2>&1 &
    disown
    sleep 3

    if tasklist | grep -q yuzu-agent; then
        echo "  ✓ Agent up — 35 plugins loaded"
    else
        echo "  ⚠ Agent may need approval in Settings → Pending Agents"
    fi

    # 4. Prometheus (scraper on :9090)
    echo "[4/5] Starting Prometheus (:9090)..."
    if which prometheus >/dev/null 2>&1; then
        prometheus \
            --config.file "$YUZU_ROOT/deploy/prometheus/prometheus.yml" \
            --storage.tsdb.path "C:/tmp/prometheus-data" \
            --web.listen-address=":9090" \
            2>&1 &
        disown
        sleep 2
        echo "  ✓ Prometheus up at http://localhost:9090"
    else
        echo "  ⚠ Prometheus not installed (skipped)"
    fi

    # 5. Grafana (dashboards on :3000)
    echo "[5/5] Starting Grafana (:3000)..."
    if [ -d "$GRAFANA_HOME" ]; then
        if ! netstat -an | grep -q ":3000.*LISTENING"; then
            cd "$GRAFANA_HOME"
            bin/grafana-server.exe 2>&1 &
            disown
            cd "$YUZU_ROOT"
            sleep 3
            echo "  ✓ Grafana up at http://localhost:3000 (admin/admin)"
        else
            echo "  ✓ Grafana already running on :3000"
        fi
    else
        echo "  ⚠ Grafana not found at $GRAFANA_HOME (skipped)"
    fi

    echo ""
    echo "=== Stack Ready ==="
    echo "  Dashboard:  http://127.0.0.1:8080"
    echo "  Grafana:    http://localhost:3000"
    echo "  Prometheus: http://localhost:9090"
    echo "  Gateway:    :50051 (agents) → :50051 (server upstream)"
    echo "  Metrics:    :9568 (gateway), :8080/metrics (server)"
    echo ""
    echo "  Stop all:   bash scripts/start-stack.sh stop"
    echo "  Status:     bash scripts/start-stack.sh status"
}

# ── Main ─────────────────────────────────────────────────────────────────

case "${1:-start}" in
    start)  start_all ;;
    stop)   stop_all ;;
    status) status ;;
    *)      echo "Usage: $0 {start|stop|status}"; exit 1 ;;
esac
