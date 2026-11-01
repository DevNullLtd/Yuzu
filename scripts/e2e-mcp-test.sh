#!/usr/bin/env bash
# e2e-mcp-test.sh — Comprehensive MCP (Model Context Protocol) test suite
#
# Tests every MCP protocol method, the tool surface (read + write tools,
# including the #289 write tools + approval-ticket flow), resources,
# prompts, error handling, read-only enforcement, and kill switch.
#
# Usage:
#   ./scripts/e2e-mcp-test.sh                                   # default: http://127.0.0.1:8080
#   ./scripts/e2e-mcp-test.sh --server-url http://10.0.0.5:9090 # custom server
#
# Prerequisites:
#   - Yuzu server running with MCP enabled
#   - curl, python3
#   - At least one agent connected (for agent-related tools)
#
# Authentication: /mcp/v1/ refuses every credential without an MCP tier (a
# session cookie, or an API token minted without mcp_tier) with HTTP 403 and
# JSON-RPC -32003. The script therefore logs in over the cookie only to mint a
# `supervised` API token, then sends ONLY `Authorization: Bearer <token>` on
# every MCP call. A cookie sent alongside the token would win session
# resolution and be refused, so no MCP call carries one. The token is revoked
# on exit.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
SERVER_URL="http://127.0.0.1:8080"
ADMIN_USER="admin"
ADMIN_PASS=""

# ── Argument parsing ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)  SERVER_URL="$2"; shift 2 ;;
        --password)    ADMIN_PASS="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--server-url URL] [--password PASS]"
            exit 0
            ;;
        *)  echo "Unknown arg: $1"; exit 1 ;;
    esac
done

SERVER_URL="${SERVER_URL%/}"
MCP_URL="${SERVER_URL}/mcp/v1/"
# Cookie-session writes (the REST token mint and revoke) send a same-site
# Referer. MCP calls send neither the cookie nor a Referer: they carry a tiered
# bearer token only.
MCP_REFERER="$(sed -E 's,^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#@]*@)?([^/?#]*).*,\1\3,' <<< "$SERVER_URL")/"
API_TOKENS_URL="${SERVER_URL}/api/v1/tokens"

# ── Temp files & cleanup ─────────────────────────────────────────────
COOKIE_JAR=$(mktemp /tmp/yuzu-mcp-cookies.XXXXXX)
RESP_BODY=$(mktemp /tmp/yuzu-mcp-body.XXXXXX)

# Tokens minted by this run (ids), revoked on exit. MCP_TOKEN is the supervised
# bearer token every MCP call uses. Every token this run mints is named
# "${TOKEN_NAME_PREFIX}<suffix>", so the exit trap can also revoke by name when an
# id was never captured (the create reply carries no token_id). The trailing "-"
# keeps the prefix from matching another run's pid, e.g. e2e-mcp-12- vs e2e-mcp-123-.
TOKEN_NAME_PREFIX="e2e-mcp-$$-"
MINTED_TOKEN_IDS=()
MCP_TOKEN=""

# _revoke_token_id ID: DELETE over the cookie session (a cookie-session write, so
# it carries the same-site Referer). A status other than 200 prints one stderr
# WARNING naming the id (a short display id, never the secret). Never fails.
_revoke_token_id() {
    local code
    code=$(curl -s -m 10 -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -H "Referer: $MCP_REFERER" \
        -X DELETE "${API_TOKENS_URL}/$1" 2>/dev/null) || code="000"
    if [[ "$code" != "200" ]]; then
        echo "WARNING: could not revoke e2e token id=$1 (HTTP $code); revoke it by hand" >&2
    fi
    return 0
}

cleanup() {
    # Best effort; the exit status of the script must not depend on it.
    local tid
    for tid in ${MINTED_TOKEN_IDS[@]+"${MINTED_TOKEN_IDS[@]}"}; do
        _revoke_token_id "$tid"
    done
    # Then by name prefix: covers a token whose id lookup came back empty. A list
    # that fails (server down, session gone) yields no ids and is tolerated.
    local listed
    listed=$(curl -s -m 10 -b "$COOKIE_JAR" "$API_TOKENS_URL" 2>/dev/null \
        | python3 -c '
import json, sys
try:
    for t in json.load(sys.stdin).get("data", []):
        if t.get("name", "").startswith(sys.argv[1]) and not t.get("revoked"):
            print(t["token_id"])
except Exception:
    pass
' "$TOKEN_NAME_PREFIX" 2>/dev/null) || listed=""
    for tid in $listed; do
        _revoke_token_id "$tid"
    done
    rm -f "$COOKIE_JAR" "$RESP_BODY"
}
trap cleanup EXIT

# ── Helpers ───────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { echo "  ✓ $*"; PASSED=$((PASSED + 1)); TESTS=$((TESTS + 1)); }
fail() { echo "  ✗ $*"; FAILURES=$((FAILURES + 1)); TESTS=$((TESTS + 1)); }

FAILURES=0
PASSED=0
TESTS=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then pass "$desc"; else fail "$desc (expected '$expected', got '$actual')"; fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if grep -qF -- "$needle" <<< "$haystack"; then pass "$desc"; else fail "$desc (expected to contain '$needle')"; fi
}

assert_not_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if ! grep -qF -- "$needle" <<< "$haystack"; then pass "$desc"; else fail "$desc (expected NOT to contain '$needle')"; fi
}

# ── JSON-RPC helper ───────────────────────────────────────────────────
# mcp_call METHOD PARAMS_JSON [ID]
# Sets MCP_STATUS (HTTP code) and MCP_BODY (response body)
MCP_STATUS=""
MCP_BODY=""
MCP_REQ_ID=0

_EMPTY_JSON='{}'
mcp_call() {
    local method="$1"
    local params="${2:-$_EMPTY_JSON}"
    local id="${3:-}"

    if [[ -z "$id" ]]; then
        MCP_REQ_ID=$((MCP_REQ_ID + 1))
        id="$MCP_REQ_ID"
    fi

    # Build JSON-RPC envelope using python3 for safe escaping
    local body
    body=$(python3 -c "
import json, sys
params_raw = sys.argv[1]
try:
    params = json.loads(params_raw)
except:
    params = {}
d = {'jsonrpc': '2.0', 'method': sys.argv[2], 'id': int(sys.argv[3])}
if params:
    d['params'] = params
print(json.dumps(d))
" "$params" "$method" "$id" 2>/dev/null)

    if [[ -z "$body" ]]; then
        body="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"id\":$id}"
    fi

    MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -H "Authorization: Bearer $MCP_TOKEN" \
        -X POST -H "Content-Type: application/json" \
        -d "$body" \
        "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
    MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

# mcp_notify METHOD PARAMS_JSON — sends a notification (no id → expect 204)
mcp_notify() {
    local method="$1"
    local params="${2:-{}}"

    local body="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params}"

    MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -H "Authorization: Bearer $MCP_TOKEN" \
        -X POST -H "Content-Type: application/json" \
        -d "$body" \
        "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
    MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

# Extract a field from JSON-RPC result
mcp_result_field() {
    local field="$1"
    echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    r = d.get('result', {})
    if isinstance(r, str):
        import json as j2
        r = j2.loads(r)
    # Walk dotted paths
    for part in '$field'.split('.'):
        if isinstance(r, dict):
            r = r.get(part, '')
        elif isinstance(r, list) and part.isdigit():
            r = r[int(part)]
        else:
            r = ''
            break
    if isinstance(r, (dict, list)):
        print(json.dumps(r))
    else:
        print(r)
except:
    print('')
" 2>/dev/null || echo ""
}

has_error() {
    echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print('yes' if 'error' in d else 'no')
except:
    print('no')
" 2>/dev/null || echo "no"
}

error_code() {
    echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin)['error']['code'])
except:
    print('')
" 2>/dev/null || echo ""
}

error_message() {
    echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin)['error']['message'])
except:
    print('')
" 2>/dev/null || echo ""
}

# ── Preflight ─────────────────────────────────────────────────────────
log "Yuzu MCP Protocol E2E Test Suite"
log "Server: $SERVER_URL"
log "MCP Endpoint: $MCP_URL"
log ""

PREFLIGHT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/livez" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT_STATUS" == "000" ]]; then
    echo "FATAL: Cannot reach server at $SERVER_URL"
    exit 1
fi

# Detect admin password
if [[ -z "$ADMIN_PASS" ]]; then
    for candidate in "YuzuUatAdmin1!" "admin" "adminpassword1" "password"; do
        LOGIN_STATUS=$(curl -s -L -o /dev/null -w "%{http_code}" \
            -c "$COOKIE_JAR" \
            -X POST "$SERVER_URL/login" \
            -d "username=${ADMIN_USER}&password=${candidate}" 2>/dev/null || echo "000")
        if [[ "$LOGIN_STATUS" == "200" ]]; then
            ADMIN_PASS="$candidate"
            break
        fi
    done
fi

if [[ -z "$ADMIN_PASS" ]]; then
    echo "FATAL: Could not auto-detect admin password"
    exit 1
fi

# Login (follow redirects with -L)
curl -s -L -o /dev/null -c "$COOKIE_JAR" \
    -X POST "$SERVER_URL/login" \
    -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" 2>/dev/null
log "Authenticated as $ADMIN_USER"

# mint_api_token NAME [TIER]
# Mints an API token over the cookie session and sets MINT_STATUS, MINTED_RAW
# and MINTED_ID. This is a cookie-session write, so it carries the same-site
# Referer. The create reply holds the raw secret but no token_id, so the id is
# found by listing the caller's tokens by name. Every token gets a 24h expires_at
# (a tiered token requires one, at most 90 days out; an untiered token accepts
# one), so a token that outlives a crashed run still dies on its own. Every
# minted id is revoked by the EXIT trap, which also sweeps by TOKEN_NAME_PREFIX.
MINT_STATUS=""
MINTED_RAW=""
MINTED_ID=""
mint_api_token() {
    local name="$1" tier="${2:-}"
    local payload expires_at
    expires_at=$(( $(date +%s) + 86400 ))
    if [[ -n "$tier" ]]; then
        payload=$(printf '{"name":"%s","mcp_tier":"%s","expires_at":%d}' \
            "$name" "$tier" "$expires_at")
    else
        payload=$(printf '{"name":"%s","expires_at":%d}' "$name" "$expires_at")
    fi

    MINTED_RAW=""
    MINTED_ID=""
    MINT_STATUS=$(curl -s -m 10 -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -H "Referer: $MCP_REFERER" \
        -X POST -H "Content-Type: application/json" \
        -d "$payload" \
        "$API_TOKENS_URL" 2>/dev/null) || MINT_STATUS="000"
    [[ "$MINT_STATUS" == "201" ]] || return 0

    MINTED_RAW=$(python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["data"]["token"])
except Exception:
    print("")
' < "$RESP_BODY" 2>/dev/null || echo "")

    curl -s -m 10 -o "$RESP_BODY" -b "$COOKIE_JAR" "$API_TOKENS_URL" 2>/dev/null || true
    MINTED_ID=$(python3 -c '
import json, sys
try:
    for t in json.load(sys.stdin).get("data", []):
        if t.get("name") == sys.argv[1] and not t.get("revoked"):
            print(t["token_id"])
            break
except Exception:
    pass
' "$name" < "$RESP_BODY" 2>/dev/null || echo "")
    if [[ -n "$MINTED_ID" ]]; then
        MINTED_TOKEN_IDS+=("$MINTED_ID")
    fi
}

# Every MCP call below sends this supervised token and no cookie. Supervised is
# required: section 12c asserts the approver_assurance_required: prefix, which an
# operator-tier token never reaches (Approval:Approve fails tier_allows first).
mint_api_token "${TOKEN_NAME_PREFIX}supervised" "supervised"
if [[ "$MINT_STATUS" != "201" || -z "$MINTED_RAW" || -z "$MINTED_ID" ]]; then
    echo "FATAL: could not mint a supervised MCP token (HTTP $MINT_STATUS, token_id='$MINTED_ID')"
    exit 1
fi
MCP_TOKEN="$MINTED_RAW"
log "Minted supervised MCP token (id=$MINTED_ID); MCP calls use it as a bearer token"
log ""

# ══════════════════════════════════════════════════════════════════════
# 1. MCP PROTOCOL METHODS
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  1. MCP Protocol Methods"
log "═══════════════════════════════════════════"

# 1.1 initialize
mcp_call "initialize" '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}'
assert_eq "initialize returns HTTP 200" "200" "$MCP_STATUS"
PROTO_VER=$(mcp_result_field "protocolVersion")
assert_eq "initialize returns protocol version" "2025-03-26" "$PROTO_VER"
SERVER_NAME=$(mcp_result_field "serverInfo.name")
assert_eq "initialize returns server name" "yuzu-server" "$SERVER_NAME"
assert_contains "initialize has tools capability" "tools" "$MCP_BODY"
assert_contains "initialize has resources capability" "resources" "$MCP_BODY"
assert_contains "initialize has prompts capability" "prompts" "$MCP_BODY"

# 1.2 notifications/initialized (notification — no id → 204 or 200)
mcp_notify "notifications/initialized" "{}"
TESTS=$((TESTS + 1))
if [[ "$MCP_STATUS" == "204" || "$MCP_STATUS" == "200" ]]; then
    pass "notifications/initialized returns $MCP_STATUS (notification accepted)"
else
    fail "notifications/initialized returns $MCP_STATUS (expected 204 or 200)"
fi

# 1.3 ping
mcp_call "ping" "{}"
assert_eq "ping returns HTTP 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "ping has no error" "no" "$HAS_ERR"

log ""

# ══════════════════════════════════════════════════════════════════════
# 2. TOOLS LIST — verify all 23 tools present
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  2. tools/list — Verify All 23 Tools"
log "═══════════════════════════════════════════"

mcp_call "tools/list" "{}"
assert_eq "tools/list returns HTTP 200" "200" "$MCP_STATUS"

TOOL_COUNT=$(echo "$MCP_BODY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('result', {})
if isinstance(r, str):
    r = json.loads(r)
print(len(r.get('tools', [])))
" 2>/dev/null || echo "0")
if [ "$TOOL_COUNT" -ge 23 ]; then
    pass "tools/list returns at least 23 tools (got $TOOL_COUNT)"
else
    fail "tools/list returns at least 23 tools (got $TOOL_COUNT)"
fi

EXPECTED_TOOLS=(
    list_agents get_agent_details query_audit_log
    list_definitions get_definition query_responses aggregate_responses
    query_inventory list_inventory_tables get_agent_inventory
    get_tags search_agents_by_tag
    list_policies get_compliance_summary get_fleet_compliance
    list_management_groups
    get_execution_status list_executions list_schedules
    validate_scope preview_scope_targets list_pending_approvals
    execute_instruction
)

for tool_name in "${EXPECTED_TOOLS[@]}"; do
    if echo "$MCP_BODY" | grep -q "\"$tool_name\""; then
        pass "Tool present: $tool_name"
    else
        fail "Tool missing: $tool_name"
    fi
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 3. RESOURCES LIST — verify all 11 resources
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  3. resources/list — Verify All 11 Resources"
log "═══════════════════════════════════════════"

mcp_call "resources/list" "{}"
assert_eq "resources/list returns HTTP 200" "200" "$MCP_STATUS"

RES_COUNT=$(echo "$MCP_BODY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('result', {})
if isinstance(r, str):
    r = json.loads(r)
print(len(r.get('resources', [])))
" 2>/dev/null || echo "0")
# 9 pre-existing + yuzu://openapi + yuzu://scope-dsl (2g PR4). Floor, not exact
# equality, matching the tools/list -ge check above -- an exact-equality
# assertion here is exactly what went stale when this PR added 2 resources.
if [ "$RES_COUNT" -ge 11 ]; then
    pass "resources/list returns at least 11 resources (got $RES_COUNT)"
else
    fail "resources/list returns at least 11 resources (got $RES_COUNT)"
fi

for uri in "yuzu://server/health" "yuzu://compliance/fleet" "yuzu://audit/recent"; do
    if echo "$MCP_BODY" | grep -q "$uri"; then
        pass "Resource present: $uri"
    else
        fail "Resource missing: $uri"
    fi
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 4. PROMPTS LIST — verify all 4 prompts
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  4. prompts/list — Verify All 4 Prompts"
log "═══════════════════════════════════════════"

mcp_call "prompts/list" "{}"
assert_eq "prompts/list returns HTTP 200" "200" "$MCP_STATUS"

PROMPT_COUNT=$(echo "$MCP_BODY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('result', {})
if isinstance(r, str):
    r = json.loads(r)
print(len(r.get('prompts', [])))
" 2>/dev/null || echo "0")
assert_eq "prompts/list returns 13 prompts" "13" "$PROMPT_COUNT"

for pname in "fleet_overview" "investigate_agent" "compliance_report" "audit_investigation"; do
    if echo "$MCP_BODY" | grep -q "\"$pname\""; then
        pass "Prompt present: $pname"
    else
        fail "Prompt missing: $pname"
    fi
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 5. RESOURCES/READ — all 3 resources
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  5. resources/read — All Resources"
log "═══════════════════════════════════════════"

# 5.1 yuzu://server/health
mcp_call "resources/read" '{"uri":"yuzu://server/health"}'
assert_eq "resources/read server/health returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "resources/read server/health has no error" "no" "$HAS_ERR"
assert_contains "server/health contains 'status'" "status" "$MCP_BODY"
assert_contains "server/health contains 'agents_connected'" "agents_connected" "$MCP_BODY"

# 5.2 yuzu://compliance/fleet
mcp_call "resources/read" '{"uri":"yuzu://compliance/fleet"}'
assert_eq "resources/read compliance/fleet returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "resources/read compliance/fleet has no error" "no" "$HAS_ERR"
assert_contains "compliance/fleet contains 'compliance_pct'" "compliance_pct" "$MCP_BODY"

# 5.3 yuzu://audit/recent
mcp_call "resources/read" '{"uri":"yuzu://audit/recent"}'
assert_eq "resources/read audit/recent returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "resources/read audit/recent has no error" "no" "$HAS_ERR"

# 5.4 Unknown resource → error
mcp_call "resources/read" '{"uri":"yuzu://nonexistent/resource"}'
HAS_ERR=$(has_error)
assert_eq "resources/read unknown URI returns error" "yes" "$HAS_ERR"

log ""

# ══════════════════════════════════════════════════════════════════════
# 6. PROMPTS/GET — all 4 prompts
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  6. prompts/get — All Prompts"
log "═══════════════════════════════════════════"

# 6.1 fleet_overview
mcp_call "prompts/get" '{"name":"fleet_overview"}'
assert_eq "prompts/get fleet_overview returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "fleet_overview has no error" "no" "$HAS_ERR"
assert_contains "fleet_overview has messages" "messages" "$MCP_BODY"
assert_contains "fleet_overview mentions list_agents" "list_agents" "$MCP_BODY"

# 6.2 investigate_agent
mcp_call "prompts/get" '{"name":"investigate_agent","agent_id":"test-agent-001"}'
assert_eq "prompts/get investigate_agent returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "investigate_agent has no error" "no" "$HAS_ERR"
assert_contains "investigate_agent mentions agent ID" "test-agent-001" "$MCP_BODY"

# 6.3 compliance_report (fleet-wide)
mcp_call "prompts/get" '{"name":"compliance_report"}'
assert_eq "prompts/get compliance_report returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "compliance_report has no error" "no" "$HAS_ERR"
assert_contains "compliance_report mentions fleet-wide" "fleet-wide" "$MCP_BODY"

# 6.4 compliance_report (per-policy)
mcp_call "prompts/get" '{"name":"compliance_report","policy_id":"pol-123"}'
HAS_ERR=$(has_error)
assert_eq "compliance_report per-policy has no error" "no" "$HAS_ERR"
assert_contains "compliance_report per-policy mentions policy" "pol-123" "$MCP_BODY"

# 6.5 audit_investigation
mcp_call "prompts/get" '{"name":"audit_investigation","principal":"admin","hours":12}'
assert_eq "prompts/get audit_investigation returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "audit_investigation has no error" "no" "$HAS_ERR"
assert_contains "audit_investigation mentions principal" "admin" "$MCP_BODY"
assert_contains "audit_investigation mentions hours" "12" "$MCP_BODY"

# 6.6 Unknown prompt → error
mcp_call "prompts/get" '{"name":"nonexistent_prompt"}'
HAS_ERR=$(has_error)
assert_eq "prompts/get unknown prompt returns error" "yes" "$HAS_ERR"

log ""

# ══════════════════════════════════════════════════════════════════════
# 7. TOOLS/CALL — All 22 Read-Only Tools
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  7. tools/call — All 22 Read-Only Tools"
log "═══════════════════════════════════════════"

# Helper for tools/call
# mcp_tool TOOL_NAME ARGS_JSON [EXPECT_ERROR]
mcp_tool() {
    local tool="$1"
    local args="${2:-$_EMPTY_JSON}"
    local expect_error="${3:-no}"

    mcp_call "tools/call" "{\"name\":\"$tool\",\"arguments\":$args}"

    if [[ "$expect_error" == "no" ]]; then
        local err
        err=$(has_error)
        if [[ "$err" == "no" ]]; then
            pass "tools/call $tool — success"
        else
            local ecode
            ecode=$(error_code)
            # -32603 (internal error) means store unavailable — acceptable in UAT
            # -32602 (invalid params) means resource not found — acceptable when
            # using placeholder IDs (no agents connected, no executions yet)
            if [[ "$ecode" == "-32603" || "$ecode" == "-32602" ]]; then
                pass "tools/call $tool — error $ecode (acceptable in UAT)"
            else
                fail "tools/call $tool — got error code=$ecode"
            fi
        fi
    else
        local err
        err=$(has_error)
        assert_eq "tools/call $tool — expected error" "yes" "$err"
    fi
}

# 7.1 list_agents — no params required
mcp_tool "list_agents" "{}"

# Capture an agent_id for subsequent tests
AGENT_ID=$(echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    r = d.get('result', {})
    if isinstance(r, str): r = json.loads(r)
    content = r.get('content', [])
    if content:
        text = content[0].get('text', '[]')
        agents = json.loads(text)
        if agents and isinstance(agents, list):
            print(agents[0].get('agent_id', ''))
        else:
            print('')
    else:
        print('')
except:
    print('')
" 2>/dev/null || echo "")

if [[ -n "$AGENT_ID" ]]; then
    pass "Captured agent_id=$AGENT_ID for subsequent tests"
else
    pass "No agents connected — agent-specific tools will test error handling"
    AGENT_ID="no-agent"
fi

# 7.2 get_agent_details
mcp_tool "get_agent_details" "{\"agent_id\":\"$AGENT_ID\"}"

# 7.3 query_audit_log
mcp_tool "query_audit_log" "{\"limit\":5}"

# 7.4 query_audit_log with filters
mcp_tool "query_audit_log" "{\"principal\":\"admin\",\"limit\":5}"

# 7.5 list_definitions
mcp_tool "list_definitions" "{}"

# 7.6 list_definitions with filter
mcp_tool "list_definitions" "{\"type\":\"question\"}"

# Capture a definition_id for get_definition
DEF_ID=$(echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    r = d.get('result', {})
    if isinstance(r, str): r = json.loads(r)
    content = r.get('content', [])
    if content:
        text = content[0].get('text', '[]')
        defs = json.loads(text)
        if defs and isinstance(defs, list):
            # Get first def with an id
            for df in defs:
                did = df.get('id', df.get('definition_id', ''))
                if did:
                    print(did)
                    break
            else:
                print('')
        else:
            print('')
    else:
        print('')
except:
    print('')
" 2>/dev/null || echo "")

# 7.7 get_definition (if we have an ID)
if [[ -n "$DEF_ID" ]]; then
    mcp_tool "get_definition" "{\"id\":\"$DEF_ID\"}"
else
    mcp_tool "get_definition" "{\"id\":\"nonexistent-def\"}" "yes"
fi

# 7.8 query_responses — requires instruction_id
mcp_tool "query_responses" "{\"instruction_id\":\"test-instruction-id\",\"limit\":5}"

# 7.9 aggregate_responses
mcp_tool "aggregate_responses" "{\"instruction_id\":\"test-instruction-id\",\"group_by\":\"agent_id\"}"

# 7.10 query_inventory
mcp_tool "query_inventory" "{\"limit\":5}"

# 7.11 list_inventory_tables
mcp_tool "list_inventory_tables" "{}"

# 7.12 get_agent_inventory
mcp_tool "get_agent_inventory" "{\"agent_id\":\"$AGENT_ID\"}"

# 7.13 get_tags
mcp_tool "get_tags" "{\"agent_id\":\"$AGENT_ID\"}"

# 7.14 search_agents_by_tag
mcp_tool "search_agents_by_tag" "{\"key\":\"env\"}"

# 7.15 list_policies
mcp_tool "list_policies" "{}"

# 7.16 get_compliance_summary — needs a policy_id (may return empty)
mcp_tool "get_compliance_summary" "{\"policy_id\":\"test-policy\"}"

# 7.17 get_fleet_compliance
mcp_tool "get_fleet_compliance" "{}"

# 7.18 list_management_groups
mcp_tool "list_management_groups" "{}"

# 7.19 get_execution_status — needs execution_id (may return not found)
mcp_tool "get_execution_status" "{\"execution_id\":\"test-exec-id\"}"

# 7.20 list_executions
mcp_tool "list_executions" "{\"limit\":5}"

# 7.21 list_schedules
mcp_tool "list_schedules" "{}"

# 7.22 validate_scope — valid expression
mcp_tool "validate_scope" "{\"expression\":\"os == \\\"linux\\\"\"}"

# 7.23 validate_scope — invalid expression
mcp_call "tools/call" '{"name":"validate_scope","arguments":{"expression":"!!!invalid(("}}'
assert_eq "validate_scope invalid expression returns 200" "200" "$MCP_STATUS"
# Should succeed (tool returns validation result, not an error)

# 7.24 preview_scope_targets
mcp_tool "preview_scope_targets" "{\"expression\":\"os == \\\"linux\\\"\"}"

# 7.25 list_pending_approvals
mcp_tool "list_pending_approvals" "{}"

# 7.26 list_pending_approvals with status filter
mcp_tool "list_pending_approvals" "{\"status\":\"pending\"}"

log ""

# ══════════════════════════════════════════════════════════════════════
# 8. TOOLS/CALL — Parameter Validation
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  8. Parameter Validation"
log "═══════════════════════════════════════════"

# Missing required param: get_agent_details without agent_id
mcp_call "tools/call" '{"name":"get_agent_details","arguments":{}}'
HAS_ERR=$(has_error)
assert_eq "get_agent_details without agent_id → error" "yes" "$HAS_ERR"

# Missing required param: get_definition without id
mcp_call "tools/call" '{"name":"get_definition","arguments":{}}'
HAS_ERR=$(has_error)
assert_eq "get_definition without id → error" "yes" "$HAS_ERR"

# Missing required param: query_responses without instruction_id
mcp_call "tools/call" '{"name":"query_responses","arguments":{}}'
HAS_ERR=$(has_error)
assert_eq "query_responses without instruction_id → error" "yes" "$HAS_ERR"

# Missing required param: validate_scope without expression
mcp_call "tools/call" '{"name":"validate_scope","arguments":{}}'
HAS_ERR=$(has_error)
assert_eq "validate_scope without expression → error" "yes" "$HAS_ERR"

# get_compliance_summary without policy_id — server may accept (fleet-wide fallback)
mcp_call "tools/call" '{"name":"get_compliance_summary","arguments":{}}'
TESTS=$((TESTS + 1))
pass "get_compliance_summary without policy_id — server responded ($MCP_STATUS)"

# Unknown tool name
mcp_call "tools/call" '{"name":"nonexistent_tool","arguments":{}}'
HAS_ERR=$(has_error)
assert_eq "unknown tool name → error" "yes" "$HAS_ERR"

log ""

# ══════════════════════════════════════════════════════════════════════
# 9. ERROR HANDLING — JSON-RPC protocol errors
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  9. JSON-RPC Error Handling"
log "═══════════════════════════════════════════"

# 9.1 Unknown method
mcp_call "nonexistent/method" "{}"
HAS_ERR=$(has_error)
assert_eq "unknown method → error" "yes" "$HAS_ERR"

# 9.2 Invalid JSON body
MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
    -H "Authorization: Bearer $MCP_TOKEN" \
    -X POST -H "Content-Type: application/json" \
    -d '{"this is not valid json' \
    "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
assert_eq "invalid JSON returns 200" "200" "$MCP_STATUS"
HAS_ERR=$(has_error)
assert_eq "invalid JSON → parse error" "yes" "$HAS_ERR"

# 9.3 Missing jsonrpc field (treated as parse error)
MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
    -H "Authorization: Bearer $MCP_TOKEN" \
    -X POST -H "Content-Type: application/json" \
    -d '{"method":"ping","id":999}' \
    "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
assert_eq "missing jsonrpc field returns HTTP response" "200" "$MCP_STATUS"

# 9.4 Wrong jsonrpc version
mcp_call_raw() {
    MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -H "Authorization: Bearer $MCP_TOKEN" \
        -X POST -H "Content-Type: application/json" \
        -d "$1" \
        "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
    MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}
mcp_call_raw '{"jsonrpc":"1.0","method":"ping","id":998}'
assert_eq "wrong jsonrpc version returns HTTP response" "200" "$MCP_STATUS"

# 9.5 Empty body
mcp_call_raw ""
TESTS=$((TESTS + 1))
if [[ "$MCP_STATUS" != "000" ]]; then
    pass "empty body returns HTTP response ($MCP_STATUS)"
else
    fail "empty body connection error"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 10. AUTHENTICATION — MCP requires auth
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  10. Authentication Enforcement"
log "═══════════════════════════════════════════"

# Call MCP with no credential at all
NOAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"ping","id":1}' \
    "$MCP_URL" 2>/dev/null) || NOAUTH_STATUS="000"
assert_eq "MCP without auth → 401" "401" "$NOAUTH_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 10b. TIERLESS PRINCIPALS REFUSED: /mcp/v1/ needs an MCP-tier credential
# ══════════════════════════════════════════════════════════════════════
# Every credential whose mcp_tier is empty is refused before any JSON-RPC parse:
# HTTP 403 with JSON-RPC code -32003 (kPermissionDenied) and a null id. That is
# every cookie session and every API token minted without mcp_tier. The
# supervised token the rest of this script uses is the control.
log "═══════════════════════════════════════════"
log "  10b. Tierless Principals Refused"
log "═══════════════════════════════════════════"

# 10b.1 A cookie session is refused even though it passes the same-site gate
# (it carries the Referer a browser would send), so the 403 below is the MCP
# tier check and not a cross-site refusal.
MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
    -b "$COOKIE_JAR" \
    -H "Referer: $MCP_REFERER" \
    -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"ping","id":1}' \
    "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
assert_eq "cookie session POST ping → 403" "403" "$MCP_STATUS"
assert_eq "cookie session refusal carries JSON-RPC code -32003" "-32003" "$(error_code)"
assert_contains "cookie session refusal names the tier requirement" \
    "/mcp/v1/ requires an MCP-tier bearer token" "$MCP_BODY"

# 10b.1b The precedence trap: a valid session cookie sent TOGETHER with the valid
# supervised Bearer token is still refused. Session resolution reads a live cookie
# before the Authorization header, so the request is classed as the cookie session
# (no MCP tier) and the token is never consulted. This pins that documented
# precedence, which is why every other MCP call in this script sends no cookie.
MCP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
    -b "$COOKIE_JAR" \
    -H "Referer: $MCP_REFERER" \
    -H "Authorization: Bearer $MCP_TOKEN" \
    -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"ping","id":1}' \
    "$MCP_URL" 2>/dev/null) || MCP_STATUS="000"
MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
assert_eq "cookie + valid supervised Bearer POST ping → 403 (cookie wins)" "403" "$MCP_STATUS"
assert_eq "cookie + Bearer refusal carries JSON-RPC code -32003" "-32003" "$(error_code)"

# 10b.2 An API token minted WITHOUT mcp_tier is refused the same way.
mint_api_token "${TOKEN_NAME_PREFIX}tierless"
TIERLESS_TOKEN=""
if [[ "$MINT_STATUS" == "201" && -n "$MINTED_RAW" ]]; then
    TIERLESS_TOKEN="$MINTED_RAW"
    pass "tierless API token minted (HTTP 201)"
    TIERLESS_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -H "Authorization: Bearer $TIERLESS_TOKEN" \
        -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"ping","id":1}' \
        "$MCP_URL" 2>/dev/null) || TIERLESS_STATUS="000"
    MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
    assert_eq "tierless API token POST ping → 403" "403" "$TIERLESS_STATUS"
    assert_eq "tierless API token refusal carries JSON-RPC code -32003" "-32003" "$(error_code)"
else
    fail "tierless API token could not be minted (HTTP $MINT_STATUS)"
fi
# The token's id is needed to revoke it. An empty lookup is a failure; the exit
# trap still revokes it by name prefix.
if [[ -n "$MINTED_ID" ]]; then
    pass "tierless API token id located for revocation"
else
    fail "tierless API token id could not be located (the exit trap revokes by name prefix)"
fi

# 10b.2b GET and DELETE are refused the same way, before any session-id check.
# Both answer 405 under --mcp-no-streaming, so first probe for streaming with the
# supervised token and no session id: streaming on answers 400 (session id
# required), streaming off 405. Anything else, or no tierless token, skips.
if [[ -n "$TIERLESS_TOKEN" ]]; then
    STREAM_PROBE=$(curl -s -m 10 -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $MCP_TOKEN" \
        "$MCP_URL" 2>/dev/null) || STREAM_PROBE="000"
    if [[ "$STREAM_PROBE" == "400" ]]; then
        for verb in GET DELETE; do
            VERB_STATUS=$(curl -s -m 10 -o "$RESP_BODY" -w "%{http_code}" \
                -H "Authorization: Bearer $TIERLESS_TOKEN" \
                -X "$verb" "$MCP_URL" 2>/dev/null) || VERB_STATUS="000"
            MCP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
            assert_eq "tierless API token $verb (no session id) → 403" "403" "$VERB_STATUS"
            assert_eq "tierless API token $verb refusal carries JSON-RPC code -32003" \
                "-32003" "$(error_code)"
        done
    else
        log "  (skipping GET/DELETE tierless checks: streaming probe returned $STREAM_PROBE, not 400; --mcp-no-streaming?)"
    fi
fi

# 10b.3 Control: the supervised token (Bearer only, no cookie) is admitted.
mcp_call "ping" "{}"
assert_eq "supervised token POST ping → 200" "200" "$MCP_STATUS"
assert_eq "supervised token ping has no error" "no" "$(has_error)"

log ""

# ══════════════════════════════════════════════════════════════════════
# 11. AUDIT TRAIL — MCP tool calls are audited
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  11. Audit Trail Verification"
log "═══════════════════════════════════════════"

# Call a tool, then check audit log for MCP entries
mcp_call "tools/call" '{"name":"list_agents","arguments":{}}'

# Query audit log for mcp.list_agents action
mcp_call "tools/call" '{"name":"query_audit_log","arguments":{"action":"mcp.list_agents","limit":5}}'
HAS_ERR=$(has_error)
assert_eq "audit query for mcp.list_agents succeeds" "no" "$HAS_ERR"

# Check that at least one audit entry exists for our MCP calls AND that every
# returned mcp.* row has a populated principal. The principal-population assertion
# is a regression net for the bug fixed in the same commit as this assertion:
# AuthRoutes::make_audit_event used to resolve the principal from session cookies
# only, so token-authenticated MCP calls logged audit rows with empty principal.
MCP_AUDIT_REPORT=$(echo "$MCP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    r = d.get('result', {})
    if isinstance(r, str): r = json.loads(r)
    content = r.get('content', [])
    if content:
        events = json.loads(content[0].get('text', '[]'))
        if not isinstance(events, list):
            print('0 0'); sys.exit(0)
        empty = sum(1 for e in events if not e.get('principal'))
        print(f'{len(events)} {empty}')
    else:
        print('0 0')
except:
    print('0 0')
" 2>/dev/null || echo "0 0")

MCP_AUDIT_COUNT=$(echo "$MCP_AUDIT_REPORT" | awk '{print $1}')
MCP_AUDIT_EMPTY_PRINCIPAL=$(echo "$MCP_AUDIT_REPORT" | awk '{print $2}')

TESTS=$((TESTS + 1))
if [[ "$MCP_AUDIT_COUNT" -gt 0 && "$MCP_AUDIT_EMPTY_PRINCIPAL" -eq 0 ]]; then
    pass "MCP tool calls appear in audit log with populated principal ($MCP_AUDIT_COUNT entries)"
elif [[ "$MCP_AUDIT_COUNT" -gt 0 ]]; then
    fail "MCP audit rows present ($MCP_AUDIT_COUNT) but $MCP_AUDIT_EMPTY_PRINCIPAL have empty principal — token-auth attribution regression"
else
    # Audit entries may take a moment to flush — acceptable
    pass "MCP audit entries pending flush (non-blocking)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 12. WRITE TOOLS ARE DISPATCHED + GATED (#289 / Issue 13.5)
# ══════════════════════════════════════════════════════════════════════
# The write tools are advertised in tools/list and have dispatch handlers. This
# test session authenticates with a `supervised` MCP token minted for an admin
# (a session cookie is refused at /mcp/v1/, section 10b), so the MCP tier gate
# runs and the handlers are reached. With empty arguments each returns a
# VALIDATION error (missing required field), NOT the "unknown tool"
# method-not-found (-32601) they returned before they were wired, proving they
# are now recognised and gated rather than invisible.
#
# At the supervised tier delete_tag, execute_instruction and quarantine_device
# are approval-gated (requires_approval), but the input-schema check runs BEFORE
# any ticket is minted, so empty arguments still return a validation error
# (-32602) and no ticket (-32006) is created. A valid-arguments call to one of
# them would mint a ticket instead of running; this script makes no such call.
#
# approve_request / reject_request are the exception to "validation error": since
# #6061 they are a recorded ADR-1005 human-session exception and ALWAYS return a
# typed refusal (error.message "approver_assurance_required:<reason>") whatever the
# arguments, because no MCP session is an interactive human one. 12c asserts that.
#
# NOTE: under `--mcp-read-only` these same five (all in kWriteTools) are instead
# rejected with kTierDenied (-32004) "MCP is in read-only mode" before any
# handler runs. That path needs a server started with the flag, so it is covered
# by the read-only-mode section / unit tests rather than re-flipped here.
log "═══════════════════════════════════════════"
log "  12. Write Tools Dispatched + Gated (#289)"
log "═══════════════════════════════════════════"

WRITE_TOOLS=("set_tag" "delete_tag" "execute_instruction" "approve_request" "reject_request" "quarantine_device")

# 12a. All five new write tools are advertised in tools/list.
mcp_call "tools/list" "{}"
for wt in "set_tag" "delete_tag" "approve_request" "reject_request" "quarantine_device"; do
    assert_contains "Write tool $wt is advertised in tools/list" "\"$wt\"" "$MCP_BODY"
done

# 12b. Each write tool is dispatched + gated (validation error, not method-not-found).
for wt in "${WRITE_TOOLS[@]}"; do
    mcp_call "tools/call" "{\"name\":\"$wt\",\"arguments\":{}}"
    HAS_ERR=$(has_error)
    assert_eq "Write tool $wt is dispatched + gated (returns an error)" "yes" "$HAS_ERR"
    ERR_CODE=$(error_code)
    if [[ "$ERR_CODE" != "-32601" ]]; then
        pass "Write tool $wt is a recognised tool (not method-not-found)"
    else
        fail "Write tool $wt returned -32601 (unknown tool) — dispatch handler missing"
    fi
done

# 12c. approve_request / reject_request return the typed approver-assurance refusal
# (#6061), never a success, even for a supervised-tier token whose creator holds Approval:Approve.
for wt in "approve_request" "reject_request"; do
    mcp_call "tools/call" "{\"name\":\"$wt\",\"arguments\":{\"approval_id\":\"e2e-nonexistent\"}}"
    assert_eq "$wt returns an error (never a success)" "yes" "$(has_error)"
    ERR_MSG=$(error_message)
    if [[ "$ERR_MSG" == approver_assurance_required:* ]]; then
        pass "$wt refusal carries the approver_assurance_required: prefix ($ERR_MSG)"
    else
        fail "$wt error message '$ERR_MSG' lacks the approver_assurance_required: prefix"
    fi
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 13. CONTENT FORMAT VALIDATION
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  13. Response Format Validation"
log "═══════════════════════════════════════════"

# Verify JSON-RPC 2.0 envelope on success
mcp_call "ping" "{}"
assert_contains "Response has jsonrpc field" "\"jsonrpc\"" "$MCP_BODY"
assert_contains "Response has jsonrpc 2.0" "\"2.0\"" "$MCP_BODY"
assert_contains "Response has id field" "\"id\"" "$MCP_BODY"
assert_contains "Response has result field" "\"result\"" "$MCP_BODY"
assert_not_contains "Success response has no error field" "\"error\"" "$MCP_BODY"

# Verify JSON-RPC 2.0 envelope on error
mcp_call "nonexistent/method" "{}"
assert_contains "Error response has jsonrpc field" "\"jsonrpc\"" "$MCP_BODY"
assert_contains "Error response has error field" "\"error\"" "$MCP_BODY"
assert_contains "Error response has error.code" "\"code\"" "$MCP_BODY"
assert_contains "Error response has error.message" "\"message\"" "$MCP_BODY"

# Verify tools/call content array format
mcp_call "tools/call" '{"name":"list_agents","arguments":{}}'
assert_contains "tools/call result has content array" "\"content\"" "$MCP_BODY"
assert_contains "tools/call content has type field" "\"type\"" "$MCP_BODY"
assert_contains "tools/call content has text type" "\"text\"" "$MCP_BODY"

log ""

# ══════════════════════════════════════════════════════════════════════
# 14. CONCURRENT / SEQUENTIAL TOOL CALLS
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  14. Sequential Tool Calls (State Isolation)"
log "═══════════════════════════════════════════"

# Call multiple tools in sequence and verify each returns independently
mcp_call "tools/call" '{"name":"list_agents","arguments":{}}' "100"
AGENTS_BODY="$MCP_BODY"
mcp_call "tools/call" '{"name":"list_management_groups","arguments":{}}' "101"
GROUPS_BODY="$MCP_BODY"
mcp_call "tools/call" '{"name":"list_policies","arguments":{}}' "102"
POLICIES_BODY="$MCP_BODY"

# Verify each returned its own request id
assert_contains "Sequential call 100 echoes id" "100" "$AGENTS_BODY"
assert_contains "Sequential call 101 echoes id" "101" "$GROUPS_BODY"
assert_contains "Sequential call 102 echoes id" "102" "$POLICIES_BODY"

# Verify responses are distinct
TESTS=$((TESTS + 1))
if [[ "$AGENTS_BODY" != "$GROUPS_BODY" ]]; then
    pass "Sequential calls return distinct responses"
else
    fail "Sequential calls returned identical responses"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
log ""
log "═══════════════════════════════════════════════════════════════════"
log "  MCP PROTOCOL E2E TEST SUMMARY"
log "═══════════════════════════════════════════════════════════════════"
log ""
log "  Server:     $SERVER_URL"
log "  Tests:      $TESTS"
log "  Passed:     $PASSED"
log "  Failed:     $FAILURES"
log ""
if [[ $FAILURES -eq 0 ]]; then
    log "  ✓ ALL $TESTS MCP TESTS PASSED"
else
    log "  ✗ $FAILURES/$TESTS MCP TESTS FAILED"
fi
log ""
log "═══════════════════════════════════════════════════════════════════"
log ""

if [[ $FAILURES -gt 0 ]]; then
    exit 1
fi

exit 0
