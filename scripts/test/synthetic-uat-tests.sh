#!/usr/bin/env bash
# synthetic-uat-tests.sh — The 6 connectivity tests from linux-start-UAT.sh,
# extracted into a standalone script that takes URLs as args so it can run
# against any UAT stack (the upgraded one in Phase 2, the fresh one in
# Phase 4, the OTA harness in Phase 3).
#
# Each test records its wall-clock duration in milliseconds via
# test-db-write.sh timing if --run-id is provided, so the operator can
# track per-command latency over time.
#
# Tests:
#   1. dashboard reachable        (HTTP 200 on /)
#   2. gateway readiness          (/readyz returns "ready")  — skipped if no gateway URL
#   3. server registered agents   (Prometheus metric)
#   4. gateway connected agents   (Prometheus metric)         — skipped if no gateway URL
#   5. help command round-trip    (POST /api/dashboard/execute)
#   6. os_info command round-trip (POST /api/command, poll responses)
#
# Usage:
#   bash scripts/test/synthetic-uat-tests.sh \
#       --dashboard http://localhost:8080 \
#       --gateway-health http://localhost:8081 \
#       --gateway-metrics http://localhost:9568 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --run-id "$RUN_ID" --gate-name phase2-synthetic
#
# Returns:
#   0  if all non-skipped tests pass
#   1  if any test fails
#   2  on argument error
#
# When --run-id is omitted, runs as a standalone smoke test and only
# prints results.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

DASHBOARD_URL=""
GATEWAY_HEALTH_URL=""
GATEWAY_METRICS_URL=""
USERNAME="admin"
PASSWORD=""
RUN_ID=""
GATE_NAME="synthetic-uat"
TIMEOUT_S=15
NO_AGENT=0

usage() {
    cat <<EOF
usage: $0 --dashboard URL [options]

Required:
  --dashboard URL          Yuzu server dashboard root, e.g. http://localhost:8080
  --password PASS          admin password

Optional:
  --user NAME              admin user (default: admin)
  --gateway-health URL     Gateway /readyz root, e.g. http://localhost:8081
  --gateway-metrics URL    Gateway /metrics root, e.g. http://localhost:9568
  --run-id ID              record per-test timings to test-runs DB
  --gate-name NAME         gate name to scope timings under (default: synthetic-uat)
  --timeout SECONDS        per-test timeout (default: 15)
  --no-agent               skip tests that require a registered agent (3, 5, 6)
                           — used by /test Phase 2 upgrade harness which has
                           a server but no agent in the upgrade compose
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)        DASHBOARD_URL="$2"; shift 2 ;;
        --gateway-health)   GATEWAY_HEALTH_URL="$2"; shift 2 ;;
        --gateway-metrics)  GATEWAY_METRICS_URL="$2"; shift 2 ;;
        --user)             USERNAME="$2"; shift 2 ;;
        --password)         PASSWORD="$2"; shift 2 ;;
        --run-id)           RUN_ID="$2"; shift 2 ;;
        --gate-name)        GATE_NAME="$2"; shift 2 ;;
        --timeout)          TIMEOUT_S="$2"; shift 2 ;;
        --no-agent)         NO_AGENT=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$DASHBOARD_URL" || -z "$PASSWORD" ]]; then
    echo "missing --dashboard or --password" >&2
    usage >&2
    exit 2
fi

# --- output helpers -------------------------------------------------------

if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()   { printf "  ${G}\u2713${N} %s\n" "$*"; }
fl()   { printf "  ${R}\u2717${N} %s\n" "$*"; }
sk()   { printf "  ${Y}-${N} %s\n" "$*"; }
info() { printf "  ${C}\u2192${N} %s\n" "$*"; }

PASSED=0
FAILED=0
SKIPPED=0
COOKIES="$(mktemp -t yuzu-test-cookies.XXXXXX)"
trap 'rm -f "$COOKIES"' EXIT

# Record a timing if --run-id was provided. Argument: step_name, ms.
record_timing() {
    local step="$1" ms="$2"
    if [[ -n "$RUN_ID" ]]; then
        bash "$HERE/test-db-write.sh" timing \
            --run-id "$RUN_ID" --gate "$GATE_NAME" --step "$step" --ms "$ms" >/dev/null || true
    fi
}

# millisecond wall clock since epoch (portable across Linux + macOS)
now_ms() {
    python3 -c "import time; print(int(time.time()*1000))"
}

elapsed_ms() {
    local start="$1"
    local end
    end=$(now_ms)
    echo $((end - start))
}

# --- login ----------------------------------------------------------------

info "logging in as $USERNAME"
LOGIN_START=$(now_ms)
LOGIN_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" \
    "$DASHBOARD_URL/login" \
    -d "username=${USERNAME}&password=${PASSWORD}" 2>/dev/null || echo "000")
LOGIN_MS=$(elapsed_ms "$LOGIN_START")
if [[ "$LOGIN_HTTP" =~ ^[23] ]]; then
    ok "login $LOGIN_HTTP (${LOGIN_MS}ms)"
    record_timing "login" "$LOGIN_MS"
else
    fl "login HTTP $LOGIN_HTTP"
    FAILED=$((FAILED + 1))
    # No point continuing to the auth-required tests
    echo ""
    echo "synthetic UAT: FAILED at login ($FAILED fail / $PASSED pass / $SKIPPED skip)"
    exit 1
fi

# --- Test 1: dashboard reachable ------------------------------------------

info "test 1: dashboard reachable"
T1_START=$(now_ms)
T1_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$DASHBOARD_URL/" 2>/dev/null || echo "000")
T1_MS=$(elapsed_ms "$T1_START")
if [[ "$T1_CODE" == "200" ]]; then
    ok "dashboard HTTP 200 (${T1_MS}ms)"
    PASSED=$((PASSED + 1))
    record_timing "dashboard-200" "$T1_MS"
else
    fl "dashboard HTTP $T1_CODE"
    FAILED=$((FAILED + 1))
fi

# --- Test 2: gateway readyz -----------------------------------------------

info "test 2: gateway /readyz"
if [[ -z "$GATEWAY_HEALTH_URL" ]]; then
    sk "no --gateway-health URL provided"
    SKIPPED=$((SKIPPED + 1))
else
    T2_START=$(now_ms)
    T2_BODY=$(curl -s --max-time "$TIMEOUT_S" "$GATEWAY_HEALTH_URL/readyz" 2>/dev/null || echo '{"status":"error"}')
    T2_MS=$(elapsed_ms "$T2_START")
    # Parse /readyz JSON via python3 rather than greping for the literal
    # `"ready"` substring — a response like `{"status":"degraded","note":
    # "ready_for_disposal"}` would false-positive the old grep. python3 is a
    # hard build dependency project-wide (CLAUDE.md), so it's safe to invoke
    # here. Mirrors the same change in scripts/start-UAT.sh test 2.
    if echo "$T2_BODY" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if d.get("status") == "ready" else 1)
' 2>/dev/null; then
        ok "gateway healthy (${T2_MS}ms)"
        PASSED=$((PASSED + 1))
        record_timing "gateway-readyz" "$T2_MS"
    else
        fl "gateway not ready: $T2_BODY"
        FAILED=$((FAILED + 1))
    fi
fi

# --- Test 3: server registered agents ------------------------------------

info "test 3: server-side registered agents metric"
if [[ $NO_AGENT -eq 1 ]]; then
    sk "no agent expected (--no-agent) — skipping"
    SKIPPED=$((SKIPPED + 1))
else
    T3_START=$(now_ms)
    T3_COUNT=$(curl -s --max-time "$TIMEOUT_S" "$DASHBOARD_URL/metrics" 2>/dev/null \
        | awk '/^yuzu_agents_registered_total /{print $2; exit}')
    T3_COUNT="${T3_COUNT:-0}"
    T3_MS=$(elapsed_ms "$T3_START")
    if [[ "$T3_COUNT" -ge 1 ]]; then
        ok "server sees $T3_COUNT registered agent(s) (${T3_MS}ms)"
        PASSED=$((PASSED + 1))
        record_timing "server-agents-metric" "$T3_MS"
    else
        fl "server shows 0 registered agents"
        FAILED=$((FAILED + 1))
    fi
fi

# --- Test 4: gateway connected agents -------------------------------------

info "test 4: gateway-side connected agents metric"
if [[ -z "$GATEWAY_METRICS_URL" ]]; then
    sk "no --gateway-metrics URL provided"
    SKIPPED=$((SKIPPED + 1))
else
    T4_START=$(now_ms)
    T4_COUNT=$(curl -s --max-time "$TIMEOUT_S" "$GATEWAY_METRICS_URL/metrics" 2>/dev/null \
        | awk '/^yuzu_gw_agents_connected_total\{/{print $2; exit}')
    T4_COUNT="${T4_COUNT:-0}"
    T4_MS=$(elapsed_ms "$T4_START")
    if [[ "$T4_COUNT" -ge 1 ]]; then
        ok "gateway sees $T4_COUNT connected agent(s) (${T4_MS}ms)"
        PASSED=$((PASSED + 1))
        record_timing "gateway-agents-metric" "$T4_MS"
    else
        fl "gateway shows 0 connected agents"
        FAILED=$((FAILED + 1))
    fi
fi

# --- Test 5: help command --------------------------------------------------

info "test 5: help command round-trip"
if [[ $NO_AGENT -eq 1 ]]; then
    sk "no agent expected (--no-agent) — skipping (help requires registered plugins)"
    SKIPPED=$((SKIPPED + 1))
else
    T5_START=$(now_ms)
    HELP_BODY=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
        -X POST "$DASHBOARD_URL/api/dashboard/execute" \
        -H "Origin: ${DASHBOARD_URL%/}" \
        -d "instruction=help&scope=__all__" 2>/dev/null || echo "")
    T5_MS=$(elapsed_ms "$T5_START")
    HELP_ROWS=$(echo "$HELP_BODY" | grep -o 'result-row' | wc -l)
    if [[ "$HELP_ROWS" -gt 0 ]]; then
        ok "help: $HELP_ROWS plugin actions listed (${T5_MS}ms)"
        PASSED=$((PASSED + 1))
        record_timing "help-command-roundtrip" "$T5_MS"
    else
        fl "help: no plugin actions returned"
        FAILED=$((FAILED + 1))
    fi
fi

# --- Test 6: os_info command (full round trip) ----------------------------

info "test 6: os_info command full round-trip"
if [[ $NO_AGENT -eq 1 ]]; then
    sk "no agent expected (--no-agent) — skipping (full round-trip requires agent)"
    SKIPPED=$((SKIPPED + 1))
    echo ""
    TOTAL=$((PASSED + FAILED + SKIPPED))
    if [[ $FAILED -eq 0 ]]; then
        echo -e "${G}synthetic UAT: $PASSED/$TOTAL passed${N} ($SKIPPED skipped)"
        exit 0
    else
        echo -e "${R}synthetic UAT: $FAILED failed, $PASSED passed, $SKIPPED skipped${N}"
        exit 1
    fi
fi

T6_START=$(now_ms)
DISPATCH_BODY=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
    -X POST "$DASHBOARD_URL/api/command" \
    -H "Content-Type: application/json" \
    -d '{"plugin":"os_info","action":"os_name"}' 2>/dev/null || echo "")
CMD_ID=$(echo "$DISPATCH_BODY" \
    | python3 -c "import sys,json;
try: print(json.load(sys.stdin).get('command_id',''))
except: print('')" 2>/dev/null)
if [[ -z "$CMD_ID" ]]; then
    fl "os_info dispatch failed (response: $DISPATCH_BODY)"
    FAILED=$((FAILED + 1))
else
    OS_RESULT=""
    POLL=0
    while [[ -z "$OS_RESULT" && $POLL -lt $TIMEOUT_S ]]; do
        sleep 1
        POLL=$((POLL + 1))
        OS_RESULT=$(curl -s -b "$COOKIES" --max-time 5 \
            "$DASHBOARD_URL/api/responses/$CMD_ID" 2>/dev/null \
            | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for r in d.get('responses',[]):
        o=r.get('output','')
        if 'os_name|' in o:
            print(o.split('|',1)[1])
            break
except: pass" 2>/dev/null)
    done
    T6_MS=$(elapsed_ms "$T6_START")
    if [[ -n "$OS_RESULT" ]]; then
        ok "os_info → $OS_RESULT (${T6_MS}ms, polled ${POLL}s)"
        PASSED=$((PASSED + 1))
        record_timing "os_info-command-roundtrip" "$T6_MS"
    else
        fl "os_info: no response after ${POLL}s"
        FAILED=$((FAILED + 1))
    fi
fi

# --- summary --------------------------------------------------------------

echo ""
TOTAL=$((PASSED + FAILED + SKIPPED))
if [[ $FAILED -eq 0 ]]; then
    echo -e "${G}synthetic UAT: $PASSED/$TOTAL passed${N} ($SKIPPED skipped)"
    exit 0
else
    echo -e "${R}synthetic UAT: $FAILED failed, $PASSED passed, $SKIPPED skipped${N}"
    exit 1
fi
