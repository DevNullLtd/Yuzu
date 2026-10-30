#!/usr/bin/env bash
# e2e-mcp-haiku-test.sh — MCP UAT test via Claude Haiku subagent
#
# Launches a Claude Code Haiku agent that exercises every MCP tool against
# the live UAT stack, dispatches commands via execute_instruction, and
# verifies results via query_responses.
#
# Usage:
#   ./scripts/e2e-mcp-haiku-test.sh               # assumes stack is running
#   ./scripts/e2e-mcp-haiku-test.sh --setup        # bring up stack first
#   ./scripts/e2e-mcp-haiku-test.sh --teardown     # tear down after test
#
# Prerequisites:
#   - Claude Code CLI (`claude`) in PATH
#   - Docker UAT stack running (or use --setup)
#   - At least one agent connected

set -euo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_URL="${YUZU_URL:-http://localhost:8080}"
ADMIN_USER="${YUZU_USER:-admin}"
ADMIN_PASS="${YUZU_PASS:-adminpassword1}"
DO_SETUP=false
DO_TEARDOWN=false

# Colours
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''; BOLD=''
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --setup)    DO_SETUP=true; shift ;;
        --teardown) DO_TEARDOWN=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--setup] [--teardown]"
            exit 0
            ;;
        *)  echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# The MCP endpoint refuses session cookies (and API tokens without an MCP tier),
# so the agent is handed a tiered bearer token minted over the login cookie. The
# cookie is used here only for the REST token mint/revoke and the metrics read;
# it is never exported to the agent (a live cookie would win session resolution
# over the bearer token and be refused). The adapter reads YUZU_MCP_TOKEN.
SESSION_COOKIE=""
MCP_TOKEN=""
MCP_TOKEN_ID=""
SITE_REFERER="$(sed -E 's,^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#@]*@)?([^/?#]*).*,\1\3,' <<< "$SERVER_URL")/"

cleanup() {
    if [ -n "$MCP_TOKEN_ID" ] && [ -n "$SESSION_COOKIE" ]; then
        # Cookie-session write: carries the same-site Referer. Best effort.
        curl -s -m 10 -o /dev/null -b "yuzu_session=$SESSION_COOKIE" \
            -H "Referer: $SITE_REFERER" \
            -X DELETE "$SERVER_URL/api/v1/tokens/$MCP_TOKEN_ID" >/dev/null 2>&1 || true
    fi
    if $DO_TEARDOWN; then
        echo -e "\n${CYAN}Tearing down UAT stack...${NC}"
        docker compose -f "$YUZU_ROOT/docker-compose.local.yml" down -v 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Stack management ─────────────────────────────────────────────────────

if $DO_SETUP; then
    echo -e "${CYAN}Starting UAT stack...${NC}"
    docker compose -f "$YUZU_ROOT/docker-compose.local.yml" up -d 2>&1
    echo "Waiting for services..."
    for i in $(seq 1 30); do
        if curl -sf "$SERVER_URL/livez" >/dev/null 2>&1 && \
           curl -sf "http://localhost:8081/healthz" >/dev/null 2>&1; then
            echo -e "${GREEN}Stack healthy${NC}"
            break
        fi
        sleep 1
        [ "$i" -eq 30 ] && { echo -e "${RED}Stack failed to start${NC}"; exit 1; }
    done
fi

# ── Health check ──────────────────────────────────────────────────────────

echo -e "${BOLD}Checking UAT stack health...${NC}"
if ! curl -sf "$SERVER_URL/livez" >/dev/null 2>&1; then
    echo -e "${RED}Server not reachable at $SERVER_URL${NC}"
    echo "Start the stack with: docker compose -f docker-compose.local.yml up -d"
    echo "Or run with --setup flag"
    exit 1
fi
if ! curl -sf "http://localhost:8081/healthz" >/dev/null 2>&1; then
    echo -e "${RED}Gateway not reachable at localhost:8081${NC}"
    exit 1
fi
echo -e "${GREEN}Server and gateway healthy${NC}"

# ── Log in (session cookie: token mint/revoke and metrics only) ──────────

COOKIE_JAR=$(mktemp /tmp/yuzu-mcp-haiku.XXXXXX)
curl -s -c "$COOKIE_JAR" -X POST "$SERVER_URL/login" \
    -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" >/dev/null

SESSION_COOKIE=$(grep yuzu_session "$COOKIE_JAR" 2>/dev/null | awk '{print $NF}')
if [ -z "$SESSION_COOKIE" ]; then
    echo -e "${RED}Failed to authenticate${NC}"
    rm -f "$COOKIE_JAR"
    exit 1
fi
rm -f "$COOKIE_JAR"
echo -e "${GREEN}Authenticated as ${ADMIN_USER}${NC}"

# ── Verify agent is connected ────────────────────────────────────────────

# Portable (BSD/GNU): awk, not `grep -oP ... \K` (Perl regex, unsupported by
# macOS BSD grep — Darwin-compat). Prints 0 when the metric is absent.
AGENT_COUNT=$(curl -s -b "yuzu_session=$SESSION_COOKIE" "$SERVER_URL/metrics" 2>/dev/null \
    | awk '/^yuzu_agents_registered_total /{v=$2} END{print v+0}')
if [ "$AGENT_COUNT" -eq 0 ]; then
    echo -e "${RED}No agents connected. Start an agent first.${NC}"
    exit 1
fi
echo -e "${GREEN}${AGENT_COUNT} agent(s) connected${NC}"

# ── Mint a tiered MCP bearer token ───────────────────────────────────────

# The agent dispatches commands via execute_instruction and reads the results
# back. At the supervised tier execute_instruction is approval-gated (the first
# call mints a ticket, -32006, instead of running), so the default is operator,
# where Execution:Execute is auto-approved. YUZU_MCP_TIER=supervised exercises the
# approval-ticket path instead (the agent's Phase 3 will then stop at tickets).
MCP_TIER="${YUZU_MCP_TIER:-operator}"
MCP_TOKEN_NAME="e2e-mcp-haiku-$$"
MINT_BODY=$(mktemp /tmp/yuzu-mcp-haiku-mint.XXXXXX)
MINT_STATUS=$(curl -s -m 10 -o "$MINT_BODY" -w "%{http_code}" \
    -b "yuzu_session=$SESSION_COOKIE" \
    -H "Referer: $SITE_REFERER" \
    -X POST -H "Content-Type: application/json" \
    -d "$(printf '{"name":"%s","mcp_tier":"%s","expires_at":%d}' \
        "$MCP_TOKEN_NAME" "$MCP_TIER" "$(( $(date +%s) + 86400 ))")" \
    "$SERVER_URL/api/v1/tokens" 2>/dev/null) || MINT_STATUS="000"
MCP_TOKEN=$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1]))["data"]["token"])
except Exception:
    print("")
' "$MINT_BODY" 2>/dev/null || echo "")
rm -f "$MINT_BODY"
# The create reply carries the secret but no token_id: find it by name.
MCP_TOKEN_ID=$(curl -s -m 10 -b "yuzu_session=$SESSION_COOKIE" "$SERVER_URL/api/v1/tokens" 2>/dev/null \
    | python3 -c '
import json, sys
try:
    for t in json.load(sys.stdin).get("data", []):
        if t.get("name") == sys.argv[1] and not t.get("revoked"):
            print(t["token_id"])
            break
except Exception:
    pass
' "$MCP_TOKEN_NAME" 2>/dev/null || echo "")
if [ "$MINT_STATUS" != "201" ] || [ -z "$MCP_TOKEN" ]; then
    echo -e "${RED}Failed to mint an MCP ${MCP_TIER} token (HTTP ${MINT_STATUS})${NC}"
    exit 1
fi
echo -e "${GREEN}Minted ${MCP_TIER} MCP token${NC}"

# ── Run the Haiku agent ──────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}Launching MCP UAT tester agent (Haiku)...${NC}"
echo -e "${BOLD}This will exercise all MCP tools against the live stack.${NC}"
echo ""

export YUZU_MCP_TOKEN="${MCP_TOKEN}"
export YUZU_MCP_URL="${SERVER_URL}/mcp/v1/"

# Run the Claude Code agent
# The agent uses the MCP tools exposed by the Yuzu server via the stdio adapter
AGENT_OUTPUT=$(claude --agent mcp-uat-tester --model haiku --print 2>&1) || true

echo "$AGENT_OUTPUT"

# ── Parse results ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}=== Haiku Agent Test Results ===${NC}"

if echo "$AGENT_OUTPUT" | grep -q "STATUS: PASS"; then
    echo -e "${GREEN}${BOLD}MCP UAT TEST PASSED${NC}"
    exit 0
elif echo "$AGENT_OUTPUT" | grep -q "STATUS: FAIL"; then
    echo -e "${RED}${BOLD}MCP UAT TEST FAILED${NC}"
    echo "$AGENT_OUTPUT" | grep -A 10 "=== MCP UAT TEST REPORT ===" || true
    exit 1
else
    echo -e "${YELLOW}Could not parse agent output for pass/fail status${NC}"
    echo -e "${YELLOW}Review the agent output above for details${NC}"
    exit 2
fi
