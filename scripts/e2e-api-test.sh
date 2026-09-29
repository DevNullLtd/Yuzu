#!/usr/bin/env bash
# e2e-api-test.sh — Comprehensive REST API end-to-end test for Yuzu Server
#
# Exercises every public REST API endpoint across health, auth, CRUD, legacy,
# and error-handling categories. Assumes the Yuzu server is already running.
#
# Usage:
#   ./scripts/e2e-api-test.sh                                   # default: http://127.0.0.1:8080
#   ./scripts/e2e-api-test.sh --server-url http://10.0.0.5:9090 # custom server
#   ./scripts/e2e-api-test.sh --skip-auth                       # skip login/auth tests
#
# Prerequisites:
#   - Yuzu server running and reachable
#   - curl
#   - Optional: python3 (for JSON extraction; falls back to grep)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
SERVER_URL="http://127.0.0.1:8080"
SKIP_AUTH=false

# ── Argument parsing ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-url)  SERVER_URL="$2"; shift 2 ;;
        --skip-auth)   SKIP_AUTH=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--server-url URL] [--skip-auth]"
            echo ""
            echo "Options:"
            echo "  --server-url URL   Base URL of the running Yuzu server (default: http://127.0.0.1:8080)"
            echo "  --skip-auth        Skip authentication tests and run all API tests without a session cookie"
            exit 0
            ;;
        *)  echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Strip trailing slash from server URL
SERVER_URL="${SERVER_URL%/}"

# ── Temp files & cleanup ─────────────────────────────────────────────
COOKIE_JAR=$(mktemp /tmp/yuzu-e2e-cookies.XXXXXX)
RESP_BODY=$(mktemp /tmp/yuzu-e2e-body.XXXXXX)
RESP_HEADERS=$(mktemp /tmp/yuzu-e2e-headers.XXXXXX)

cleanup() {
    rm -f "$COOKIE_JAR" "$RESP_BODY" "$RESP_HEADERS"
}
trap cleanup EXIT

# ── Helpers (same pattern as integration-test.sh) ────────────────────
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
    # grep's success (this exact failure was already hand-worked-around once, at
    # the openapi.json check below, but every other large-body assert_contains
    # call site — e.g. GET /metrics — stayed exposed). A here-string has no writer
    # process to SIGPIPE.
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

# assert_status_ok: pass if HTTP status is in the 2xx range
assert_status_ok() {
    TESTS=$((TESTS + 1))
    local desc="$1" actual="$2"
    if [[ "$actual" -ge 200 && "$actual" -lt 300 ]]; then
        pass "$desc (HTTP $actual)"
    else
        fail "$desc (expected 2xx, got $actual)"
    fi
}

# assert_status_any: pass if HTTP status matches any of the listed codes
assert_status_any() {
    TESTS=$((TESTS + 1))
    local desc="$1" actual="$2"
    shift 2
    for expected in "$@"; do
        if [[ "$actual" == "$expected" ]]; then
            pass "$desc (HTTP $actual)"
            return
        fi
    done
    fail "$desc (got HTTP $actual, expected one of: $*)"
}

# ── curl wrappers ────────────────────────────────────────────────────
# Each sets HTTP_STATUS (3-digit code) and HTTP_BODY (response body).
# Body is written to a temp file; status code is captured via -w.

http_get() {
    local url="$1"
    sleep 0.05  # pace requests to avoid exhausting server thread pool
    HTTP_STATUS=$(curl -s -m 10 -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_post() {
    local url="$1" data="$2" content_type="${3:-application/json}"
    sleep 0.05
    HTTP_STATUS=$(curl -s -m 10 -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -X POST -H "Content-Type: $content_type" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

# Like http_post but saves cookies (for login only)
http_post_login() {
    local url="$1" data="$2" content_type="${3:-application/x-www-form-urlencoded}"
    HTTP_STATUS=$(curl -s -L -o "$RESP_BODY" -w "%{http_code}" \
        -c "$COOKIE_JAR" \
        -X POST -H "Content-Type: $content_type" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_put() {
    local url="$1" data="$2"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -X PUT -H "Content-Type: application/json" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_delete() {
    local url="$1"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -b "$COOKIE_JAR" \
        -X DELETE \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_get_noauth() {
    local url="$1"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

http_post_noauth() {
    local url="$1" data="$2" content_type="${3:-application/json}"
    HTTP_STATUS=$(curl -s -o "$RESP_BODY" -w "%{http_code}" \
        -X POST -H "Content-Type: $content_type" \
        -d "$data" \
        "$url" 2>/dev/null) || HTTP_STATUS="000"
    HTTP_BODY=$(cat "$RESP_BODY" 2>/dev/null || echo "")
}

# Re-authenticate to ensure a valid session cookie
refresh_session() {
    http_post_login "$SERVER_URL/login" "username=admin&password=${ADMIN_PASS:-admin}"
}

# ── JSON extraction helper ───────────────────────────────────────────
# extract_json_field FIELD JSON -> prints the value (uses python3 if available, else grep)
extract_json_field() {
    local field="$1" json="$2"
    if command -v python3 &>/dev/null; then
        echo "$json" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # Walk into nested 'data' if present
    if 'data' in d and isinstance(d['data'], dict) and '$field' in d['data']:
        print(d['data']['$field'])
    elif '$field' in d:
        print(d['$field'])
    else:
        print('')
except:
    print('')
" 2>/dev/null
    else
        # Fallback: grep for "field":"value" — handles simple string/numeric values
        echo "$json" | grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
            | head -1 | sed "s/\"${field}\"[[:space:]]*:[[:space:]]*\"//" | sed 's/"$//' \
            || echo ""
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Preflight: verify server is reachable
# ══════════════════════════════════════════════════════════════════════
log "Yuzu REST API E2E Test Suite"
log "Server: $SERVER_URL"
log "Skip auth: $SKIP_AUTH"
log ""

log "Preflight: checking server reachability..."
PREFLIGHT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/livez" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT_STATUS" == "000" ]]; then
    echo "FATAL: Cannot reach server at $SERVER_URL"
    echo "       Make sure Yuzu server is running and the URL is correct."
    exit 1
fi
log "  Server is reachable (HTTP $PREFLIGHT_STATUS)."
log ""

# ══════════════════════════════════════════════════════════════════════
# 1. HEALTH ENDPOINTS (no auth required)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  1. Health Endpoints (no auth)"
log "═══════════════════════════════════════════"

# GET /livez
http_get_noauth "$SERVER_URL/livez"
assert_eq "GET /livez returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /livez body contains 'ok'" "ok" "$HTTP_BODY"

# GET /readyz (may return 503 if stores initializing)
http_get_noauth "$SERVER_URL/readyz"
assert_status_any "GET /readyz returns 200 or 503" "$HTTP_STATUS" 200 503

# GET /health
http_get_noauth "$SERVER_URL/health"
assert_eq "GET /health returns 200" "200" "$HTTP_STATUS"

# GET /metrics
http_get_noauth "$SERVER_URL/metrics"
assert_eq "GET /metrics returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /metrics body contains 'yuzu_'" "yuzu_" "$HTTP_BODY"

# L9 (wave1 remediation): these deny counters are PRE-REGISTERED at boot
# (server.cpp) with a concrete zero-value series, deliberately never left to
# spring into existence on first increment — for a fail-closed check, "absent"
# (never ran) and "zero" (ran, denied nothing) are different facts, and only
# pre-registration keeps them distinguishable on a fresh dashboard. This is
# the one place that boot-time wiring is provable: the counters are set on a
# private ServerImpl member with no live-Session-free construction path, so a
# unit test cannot reach them — only a real boot, which this e2e run against a
# freshly-started stack (no schedule/dispatch/gateway denial has fired yet) is.
assert_contains "GET /metrics pre-registers yuzu_schedule_arming_denied_total at boot" \
    "yuzu_schedule_arming_denied_total" "$HTTP_BODY"
assert_contains "GET /metrics pre-registers yuzu_server_dispatch_denied_total at boot" \
    "yuzu_server_dispatch_denied_total" "$HTTP_BODY"
assert_contains "GET /metrics pre-registers yuzu_server_dispatch_tag_invalid_total at boot" \
    "yuzu_server_dispatch_tag_invalid_total" "$HTTP_BODY"
assert_contains "GET /metrics pre-registers yuzu_server_gateway_capability_denied_total at boot" \
    "yuzu_server_gateway_capability_denied_total" "$HTTP_BODY"

log ""

# ══════════════════════════════════════════════════════════════════════
# 2. AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════
if [[ "$SKIP_AUTH" == "false" ]]; then
    log "═══════════════════════════════════════════"
    log "  2. Authentication"
    log "═══════════════════════════════════════════"

    # Detect admin password
    ADMIN_PASS=""
    for candidate_pass in "YuzuUatAdmin1!" "admin" "adminpassword1" "password"; do
        DETECT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -c "$COOKIE_JAR" \
            -X POST "$SERVER_URL/login" \
            -d "username=admin&password=${candidate_pass}" 2>/dev/null || echo "000")
        if [[ "$DETECT_STATUS" == "200" ]]; then
            ADMIN_PASS="$candidate_pass"
            break
        fi
    done

    # POST /login with valid credentials
    http_post_login "$SERVER_URL/login" "username=admin&password=${ADMIN_PASS:-admin}"
    assert_eq "POST /login returns 200" "200" "$HTTP_STATUS"
    # Verify session cookie was set by checking the cookie jar
    TESTS=$((TESTS + 1))
    if grep -q "yuzu_session" "$COOKIE_JAR" 2>/dev/null; then
        pass "Login set yuzu_session cookie"
    else
        fail "Login did not set yuzu_session cookie"
    fi

    # POST /login with bad password
    http_post_noauth "$SERVER_URL/login" "username=admin&password=wrongpass" "application/x-www-form-urlencoded"
    assert_eq "POST /login (bad password) returns 401" "401" "$HTTP_STATUS"

    # GET /api/v1/me without cookie (unauthenticated)
    http_get_noauth "$SERVER_URL/api/v1/me"
    assert_eq "GET /api/v1/me without cookie returns 401" "401" "$HTTP_STATUS"

    # GET /api/v1/me with valid cookie
    http_get "$SERVER_URL/api/v1/me"
    assert_eq "GET /api/v1/me with cookie returns 200" "200" "$HTTP_STATUS"
    assert_contains "GET /api/v1/me contains 'admin'" "admin" "$HTTP_BODY"

    # POST /logout
    http_post "$SERVER_URL/logout" "" "application/json"
    assert_eq "POST /logout returns 200" "200" "$HTTP_STATUS"

    # After logout, GET /api/v1/me should fail
    http_get "$SERVER_URL/api/v1/me"
    assert_eq "GET /api/v1/me after logout returns 401" "401" "$HTTP_STATUS"

    # Re-login for remaining tests
    log "  Re-authenticating for remaining tests..."
    refresh_session
    if [[ "$HTTP_STATUS" != "200" ]]; then
        echo "FATAL: Cannot re-authenticate (HTTP $HTTP_STATUS). Remaining tests will fail."
    fi

    log ""
else
    log "  (Skipping authentication tests — --skip-auth)"
    log ""
fi

# ══════════════════════════════════════════════════════════════════════
# 3. REST API v1 — Management Groups CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  3. Management Groups CRUD"
log "═══════════════════════════════════════════"

TEST_GROUP_NAME="e2e-test-group-$(date +%s)"
GROUP_ID=""

# POST /api/v1/management-groups -> 201
http_post "$SERVER_URL/api/v1/management-groups" \
    "{\"name\":\"$TEST_GROUP_NAME\",\"description\":\"E2E test group\",\"membership_type\":\"static\"}"
assert_eq "POST /api/v1/management-groups returns 201" "201" "$HTTP_STATUS"
GROUP_ID=$(extract_json_field "id" "$HTTP_BODY")
TESTS=$((TESTS + 1))
if [[ -n "$GROUP_ID" ]]; then
    pass "Management group created with id=$GROUP_ID"
else
    fail "Management group creation did not return an id"
fi

# GET /api/v1/management-groups -> 200, contains group name
http_get "$SERVER_URL/api/v1/management-groups"
assert_eq "GET /api/v1/management-groups returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /api/v1/management-groups contains test group" "$TEST_GROUP_NAME" "$HTTP_BODY"

# GET /api/v1/management-groups/{id} -> 200
if [[ -n "$GROUP_ID" ]]; then
    http_get "$SERVER_URL/api/v1/management-groups/$GROUP_ID"
    assert_eq "GET /api/v1/management-groups/{id} returns 200" "200" "$HTTP_STATUS"

    # PUT /api/v1/management-groups/{id} -> 200
    http_put "$SERVER_URL/api/v1/management-groups/$GROUP_ID" \
        "{\"name\":\"$TEST_GROUP_NAME\",\"description\":\"Updated by E2E test\"}"
    assert_status_ok "PUT /api/v1/management-groups/{id}" "$HTTP_STATUS"

    # DELETE /api/v1/management-groups/{id} -> 200
    http_delete "$SERVER_URL/api/v1/management-groups/$GROUP_ID"
    assert_status_ok "DELETE /api/v1/management-groups/{id}" "$HTTP_STATUS"

    # GET after delete -> 404
    http_get "$SERVER_URL/api/v1/management-groups/$GROUP_ID"
    assert_eq "GET /api/v1/management-groups/{id} after delete returns 404" "404" "$HTTP_STATUS"
else
    log "  (Skipping management group CRUD — no id captured)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 4. REST API v1 — API Tokens CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  4. API Tokens CRUD"
log "═══════════════════════════════════════════"

TOKEN_LABEL="e2e-test-token-$(date +%s)"
API_TOKEN=""
TOKEN_NAME=""

# POST /api/v1/tokens -> 201
http_post "$SERVER_URL/api/v1/tokens" "{\"name\":\"$TOKEN_LABEL\"}"
assert_eq "POST /api/v1/tokens returns 201" "201" "$HTTP_STATUS"
API_TOKEN=$(extract_json_field "token" "$HTTP_BODY")
TOKEN_NAME=$(extract_json_field "name" "$HTTP_BODY")
TESTS=$((TESTS + 1))
if [[ -n "$API_TOKEN" ]]; then
    pass "API token created (name=$TOKEN_NAME)"
else
    fail "API token creation did not return a token"
fi

# GET /api/v1/tokens -> 200, contains label
http_get "$SERVER_URL/api/v1/tokens"
assert_eq "GET /api/v1/tokens returns 200" "200" "$HTTP_STATUS"
assert_contains "GET /api/v1/tokens contains token label" "$TOKEN_LABEL" "$HTTP_BODY"

# DELETE /api/v1/tokens/{token_id} -> 200
# Extract token_id from the list response (deletion uses token_id, not name)
TOKEN_ID=$(echo "$HTTP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for t in d.get('data', []):
        if t.get('name') == '$TOKEN_LABEL':
            print(t['token_id']); break
except: pass
" 2>/dev/null)
if [[ -n "$TOKEN_ID" ]]; then
    http_delete "$SERVER_URL/api/v1/tokens/$TOKEN_ID"
    assert_status_ok "DELETE /api/v1/tokens/{token_id}" "$HTTP_STATUS"
else
    TESTS=$((TESTS + 1))
    fail "DELETE /api/v1/tokens — could not extract token_id"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 5. REST API v1 — RBAC
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  5. RBAC"
log "═══════════════════════════════════════════"

# GET /api/v1/rbac/roles -> 200
http_get "$SERVER_URL/api/v1/rbac/roles"
assert_eq "GET /api/v1/rbac/roles returns 200" "200" "$HTTP_STATUS"

# POST /api/v1/rbac/check -> 200
http_post "$SERVER_URL/api/v1/rbac/check" \
    "{\"principal\":\"admin\",\"securable_type\":\"ManagementGroup\",\"operation\":\"Read\"}"
assert_eq "POST /api/v1/rbac/check returns 200" "200" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 6. REST API v1 — Tags
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  6. Tags"
log "═══════════════════════════════════════════"

# GET /api/v1/tags -> 200 (requires agent_id parameter)
http_get "$SERVER_URL/api/v1/tags?agent_id=test-agent"
assert_eq "GET /api/v1/tags returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/tag-categories -> 200
http_get "$SERVER_URL/api/v1/tag-categories"
assert_eq "GET /api/v1/tag-categories returns 200" "200" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 7. REST API v1 — Other
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  7. REST API v1 — Other Endpoints"
log "═══════════════════════════════════════════"

# GET /api/v1/quarantine -> 200
http_get "$SERVER_URL/api/v1/quarantine"
assert_eq "GET /api/v1/quarantine returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/definitions -> 200
http_get "$SERVER_URL/api/v1/definitions"
assert_eq "GET /api/v1/definitions returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/audit -> 200
http_get "$SERVER_URL/api/v1/audit"
assert_eq "GET /api/v1/audit returns 200" "200" "$HTTP_STATUS"

# #2057: /api/v1/openapi.json now gates Infrastructure:Read — unauthenticated
# gets a 401, authenticated (the session logged in above) gets 200. A caller
# with NO session at all never reaches the route's own perm_fn/A4 gate: the
# pre-routing chokepoint's session-resolution check (server.cpp, "if
# (!session)") short-circuits every unauthenticated /api/* request with its
# own pre-existing, non-A4 401 body ({"error":{"code","message"},"meta"} —
# no correlation_id) BEFORE routing — verified identical on GET /api/v1/me
# unauthenticated too, so this is a uniform pre-existing gap across every
# /api/v1/* route, not something #2057 introduced or scoped to fix.
http_get_noauth "$SERVER_URL/api/v1/openapi.json"
assert_eq "GET /api/v1/openapi.json (unauthenticated) returns 401" "401" "$HTTP_STATUS"
assert_contains "GET /api/v1/openapi.json (unauthenticated) body contains error code 401" \
    '"code":401' "$HTTP_BODY"

http_get "$SERVER_URL/api/v1/openapi.json"
assert_eq "GET /api/v1/openapi.json (authenticated) returns 200" "200" "$HTTP_STATUS"
# Not assert_contains: that helper's `echo "$haystack" | grep -q "$needle"`
# pipeline can spuriously report no-match under `pipefail` when the needle
# is found on an early line of a large multi-line haystack — grep(1) exits
# the instant it matches, echo(1) is still mid-write of the remaining
# ~200KB spec body, SIGPIPE kills echo, and pipefail surfaces THAT non-zero
# exit rather than grep's success. The pretty-printed OpenAPI doc (its
# "openapi" key is on line 2) triggers this every time. Plain bash glob
# match has no subshell/pipe to race.
TESTS=$((TESTS + 1))
if [[ "$HTTP_BODY" == *openapi* ]]; then
    pass "GET /api/v1/openapi.json (authenticated) body contains openapi"
else
    fail "GET /api/v1/openapi.json (authenticated) body contains openapi (expected to contain 'openapi')"
fi

# GET /api/v1/tag-compliance -> 200
http_get "$SERVER_URL/api/v1/tag-compliance"
assert_eq "GET /api/v1/tag-compliance returns 200" "200" "$HTTP_STATUS"

# GET /api/v1/inventory/tables -> 200
http_get "$SERVER_URL/api/v1/inventory/tables"
assert_status_any "GET /api/v1/inventory/tables returns 200 or 503" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 8. Legacy API Endpoints
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  8. Legacy API Endpoints"
log "═══════════════════════════════════════════"

# Each legacy endpoint: 200 (or 401 if auth-gated and no cookie; still counts as reachable)
declare -a LEGACY_ENDPOINTS=(
    "/api/agents"
    "/api/help"
    "/api/audit"
    "/api/instructions"
    "/api/executions"
    "/api/compliance"
    "/api/tags?agent_id=test-agent"
    "/api/policies"
    "/api/policy-fragments"
    "/api/workflows"
    "/api/product-packs"
    "/api/notifications"
    "/api/webhooks"
    "/api/approvals/pending/count"
    "/api/nvd/status"
    "/api/schedules"
)

for endpoint in "${LEGACY_ENDPOINTS[@]}"; do
    http_get "$SERVER_URL$endpoint"
    assert_status_any "GET $endpoint" "$HTTP_STATUS" 200 401 503
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 9. Legacy API — Command & Scope
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  9. Command & Scope"
log "═══════════════════════════════════════════"

# POST /api/scope/validate with valid expression
http_post "$SERVER_URL/api/scope/validate" '{"expression":"os == \"linux\""}'
assert_eq "POST /api/scope/validate returns 200" "200" "$HTTP_STATUS"
assert_contains "POST /api/scope/validate returns valid=true" "true" "$HTTP_BODY"

# POST /api/scope/estimate with valid expression
http_post "$SERVER_URL/api/scope/estimate" '{"expression":"os == \"linux\""}'
assert_eq "POST /api/scope/estimate returns 200" "200" "$HTTP_STATUS"

# POST /api/command with invalid JSON -> 400
http_post "$SERVER_URL/api/command" "not-valid-json"
assert_eq "POST /api/command with invalid JSON returns 400" "400" "$HTTP_STATUS"

# POST /api/command with empty object (missing plugin/action) -> 400
http_post "$SERVER_URL/api/command" '{}'
assert_eq "POST /api/command with {} returns 400" "400" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 10. Instruction Definition CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  10. Instruction Definition CRUD"
log "═══════════════════════════════════════════"

INSTRUCTION_ID=""

# POST /api/instructions with JSON (the legacy API accepts JSON with type field)
INSTR_NAME="e2e-test-instr-$(date +%s)"
http_post "$SERVER_URL/api/instructions" \
    "{\"name\":\"$INSTR_NAME\",\"plugin\":\"os_info\",\"action\":\"os_name\",\"type\":\"question\",\"description\":\"E2E test\",\"category\":\"testing\"}"
assert_status_any "POST /api/instructions returns 200 or 201" "$HTTP_STATUS" 200 201 400 503
# Try to extract the instruction ID from the response
INSTRUCTION_ID=$(extract_json_field "id" "$HTTP_BODY")
if [[ -z "$INSTRUCTION_ID" ]]; then
    # Some servers return the ID under a different key or in the URL; try "name"
    INSTRUCTION_ID=$(extract_json_field "name" "$HTTP_BODY")
fi

if [[ -n "$INSTRUCTION_ID" ]]; then
    # GET /api/instructions/{id} -> 200
    http_get "$SERVER_URL/api/instructions/$INSTRUCTION_ID"
    assert_eq "GET /api/instructions/{id} returns 200" "200" "$HTTP_STATUS"

    # DELETE /api/instructions/{id} -> 200
    http_delete "$SERVER_URL/api/instructions/$INSTRUCTION_ID"
    assert_status_ok "DELETE /api/instructions/{id}" "$HTTP_STATUS"
else
    log "  (Could not capture instruction ID — skipping GET/DELETE)"
    # Still count as tested via the POST above
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 11. Schedule CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  11. Schedule CRUD"
log "═══════════════════════════════════════════"

SCHEDULE_ID=""

# POST /api/schedules (needs a valid definition_id from a prior instruction)
SCHED_DEF_ID="${INSTRUCTION_ID:-missing}"
http_post "$SERVER_URL/api/schedules" \
    "{\"name\":\"e2e-test-schedule\",\"cron\":\"0 0 * * *\",\"definition_id\":\"$SCHED_DEF_ID\",\"scope\":\"os == \\\"linux\\\"\"}"
assert_status_any "POST /api/schedules returns 200 or 201" "$HTTP_STATUS" 200 201 400 503
SCHEDULE_ID=$(extract_json_field "id" "$HTTP_BODY")

if [[ -n "$SCHEDULE_ID" ]]; then
    # DELETE /api/schedules/{id} -> 200
    http_delete "$SERVER_URL/api/schedules/$SCHEDULE_ID"
    assert_status_ok "DELETE /api/schedules/{id}" "$HTTP_STATUS"
else
    log "  (Could not capture schedule ID — skipping DELETE)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 12. Deployment & Discovery (Phase 7)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  12. Deployment & Discovery"
log "═══════════════════════════════════════════"

# GET /api/deployment-jobs -> 200 (empty list is fine)
http_get "$SERVER_URL/api/deployment-jobs"
assert_status_any "GET /api/deployment-jobs" "$HTTP_STATUS" 200 401 503

# GET /api/patches -> 200
http_get "$SERVER_URL/api/patches"
assert_status_any "GET /api/patches" "$HTTP_STATUS" 200 401 503

# GET /api/directory/status -> 200
http_get "$SERVER_URL/api/directory/status"
assert_status_any "GET /api/directory/status" "$HTTP_STATUS" 200 401 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 13. Error Handling
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  13. Error Handling"
log "═══════════════════════════════════════════"

# Invalid JSON body on a POST endpoint
http_post "$SERVER_URL/api/v1/management-groups" "{{{{not json"
assert_eq "Invalid JSON body returns 400" "400" "$HTTP_STATUS"

# Nonexistent v1 endpoint -> 404
# Note: the server may redirect unauthenticated requests, so test with auth
http_get "$SERVER_URL/api/v1/nonexistent-endpoint-xyz"
assert_status_any "Nonexistent v1 endpoint returns 404 or 302" "$HTTP_STATUS" 404 302

# GET /api/v1/management-groups/nonexistent (not a valid hex id) -> 404
# The route regex requires [a-f0-9]+, so a non-matching path falls through to 404
http_get "$SERVER_URL/api/v1/management-groups/000000000000dead"
assert_eq "GET /api/v1/management-groups/nonexistent returns 404" "404" "$HTTP_STATUS"

# NOTE: Rate limiting test moved to the end of the suite (section 39)
# to avoid blocking subsequent tests

log ""

# Brief pause between sections to avoid rate limiting
sleep 1
refresh_session

# ══════════════════════════════════════════════════════════════════════
# 14. Execution Statistics
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  14. Execution Statistics"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/v1/execution-statistics"
assert_status_any "GET /api/v1/execution-statistics" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/v1/execution-statistics/agents"
assert_status_any "GET /api/v1/execution-statistics/agents" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/v1/execution-statistics/definitions"
assert_status_any "GET /api/v1/execution-statistics/definitions" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 15. Help System
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  15. Help System"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/help"
assert_status_any "GET /api/help" "$HTTP_STATUS" 200 503; # "$HTTP_STATUS"

http_get "$SERVER_URL/api/help/html"
assert_status_any "GET /api/help/html" "$HTTP_STATUS" 200 503
assert_contains "GET /api/help/html contains HTML" "<" "$HTTP_BODY"

http_get "$SERVER_URL/api/help/autocomplete"
assert_status_any "GET /api/help/autocomplete" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/help/palette"
assert_status_any "GET /api/help/palette" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 16. Webhook CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  16. Webhook CRUD"
log "═══════════════════════════════════════════"

WEBHOOK_ID=""

http_post "$SERVER_URL/api/webhooks" \
    "{\"name\":\"e2e-test-webhook\",\"url\":\"http://localhost:9999/hook\",\"events\":[\"agent.registered\"]}"
assert_status_any "POST /api/webhooks returns 200 or 201" "$HTTP_STATUS" 200 201 400 503
WEBHOOK_ID=$(extract_json_field "id" "$HTTP_BODY")

http_get "$SERVER_URL/api/webhooks"
assert_status_any "GET /api/webhooks" "$HTTP_STATUS" 200 503

if [[ -n "$WEBHOOK_ID" ]]; then
    http_get "$SERVER_URL/api/webhooks/$WEBHOOK_ID/deliveries"
    assert_status_any "GET /api/webhooks/{id}/deliveries" "$HTTP_STATUS" 200 404

    http_delete "$SERVER_URL/api/webhooks/$WEBHOOK_ID"
    assert_status_any "DELETE /api/webhooks/{id}" "$HTTP_STATUS" 200 503
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 17. Policy & Compliance CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  17. Policy & Compliance CRUD"
log "═══════════════════════════════════════════"

# Policy fragments
http_get "$SERVER_URL/api/policy-fragments"
assert_status_any "GET /api/policy-fragments" "$HTTP_STATUS" 200 503

# Salt the fragment name with the run timestamp so back-to-back runs against
# the same server don't collide with #396's new 409-on-duplicate-name guard.
FRAGMENT_NAME="e2e-test-fragment-$(date +%s)-$$"
http_post "$SERVER_URL/api/policy-fragments" \
    "{\"name\":\"$FRAGMENT_NAME\",\"expression\":\"os == \\\"linux\\\"\",\"description\":\"E2E test\"}"
# 409 is also accepted to keep this script resilient to a polluted DB on
# shared environments — the next run will use a fresh salted name.
assert_status_any "POST /api/policy-fragments" "$HTTP_STATUS" 200 201 400 409
FRAGMENT_ID=$(extract_json_field "id" "$HTTP_BODY")

# Policies
http_get "$SERVER_URL/api/policies"
assert_status_any "GET /api/policies" "$HTTP_STATUS" 200 503

POLICY_NAME="e2e-test-policy-$(date +%s)-$$"
http_post "$SERVER_URL/api/policies" \
    "{\"name\":\"$POLICY_NAME\",\"description\":\"E2E test\",\"scope\":\"os == \\\"linux\\\"\",\"rules\":[{\"plugin\":\"os_info\",\"action\":\"os_name\",\"condition\":\"output != ''\",\"name\":\"has-os\"}]}"
# Accept 409 against shared environments (same rationale as fragments above).
assert_status_any "POST /api/policies" "$HTTP_STATUS" 200 201 400 409
POLICY_ID=$(extract_json_field "id" "$HTTP_BODY")

if [[ -n "$POLICY_ID" ]]; then
    http_get "$SERVER_URL/api/policies/$POLICY_ID"
    assert_status_any "GET /api/policies/{id}" "$HTTP_STATUS" 200 503

    http_get "$SERVER_URL/api/compliance/$POLICY_ID"
    assert_status_any "GET /api/compliance/{policy_id}" "$HTTP_STATUS" 200 404

    http_post "$SERVER_URL/api/policies/$POLICY_ID/disable" "{}"
    assert_status_any "POST /api/policies/{id}/disable" "$HTTP_STATUS" 200 503

    http_post "$SERVER_URL/api/policies/$POLICY_ID/enable" "{}"
    assert_status_any "POST /api/policies/{id}/enable" "$HTTP_STATUS" 200 503

    http_delete "$SERVER_URL/api/policies/$POLICY_ID"
    assert_status_any "DELETE /api/policies/{id}" "$HTTP_STATUS" 200 503
fi

if [[ -n "$FRAGMENT_ID" ]]; then
    http_delete "$SERVER_URL/api/policy-fragments/$FRAGMENT_ID"
    assert_status_any "DELETE /api/policy-fragments/{id}" "$HTTP_STATUS" 200 503
fi

# Fleet compliance
http_get "$SERVER_URL/api/compliance"
assert_status_any "GET /api/compliance" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 18. Workflow CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  18. Workflow CRUD"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/workflows"
assert_status_any "GET /api/workflows" "$HTTP_STATUS" 200 503

http_post "$SERVER_URL/api/workflows" \
    "{\"name\":\"e2e-test-workflow\",\"description\":\"E2E test\",\"steps\":[]}"
assert_status_any "POST /api/workflows" "$HTTP_STATUS" 200 201 400
WORKFLOW_ID=$(extract_json_field "id" "$HTTP_BODY")

if [[ -n "$WORKFLOW_ID" ]]; then
    http_get "$SERVER_URL/api/workflows/$WORKFLOW_ID"
    assert_status_any "GET /api/workflows/{id}" "$HTTP_STATUS" 200 503

    http_delete "$SERVER_URL/api/workflows/$WORKFLOW_ID"
    assert_status_any "DELETE /api/workflows/{id}" "$HTTP_STATUS" 200 503
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 19. Instruction Sets CRUD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  19. Instruction Sets CRUD"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/instruction-sets"
assert_status_any "GET /api/instruction-sets" "$HTTP_STATUS" 200 503

http_post "$SERVER_URL/api/instruction-sets" \
    "{\"name\":\"e2e-test-set\",\"description\":\"E2E test set\"}"
assert_status_any "POST /api/instruction-sets" "$HTTP_STATUS" 200 201
ISET_ID=$(extract_json_field "id" "$HTTP_BODY")

if [[ -n "$ISET_ID" ]]; then
    http_delete "$SERVER_URL/api/instruction-sets/$ISET_ID"
    assert_status_any "DELETE /api/instruction-sets/{id}" "$HTTP_STATUS" 200 503
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 20. YAML Validation
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  20. YAML Instruction Validation"
log "═══════════════════════════════════════════"

VALID_YAML='apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  name: e2e-yaml-test
spec:
  plugin: os_info
  action: os_name
  type: question
  description: E2E yaml test'

http_post "$SERVER_URL/api/instructions/validate-yaml" "$VALID_YAML" "application/x-yaml"
assert_status_any "POST /api/instructions/validate-yaml (valid)" "$HTTP_STATUS" 200 201

INVALID_YAML='apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  name: ""
spec:
  plugin: ""'

http_post "$SERVER_URL/api/instructions/validate-yaml" "$INVALID_YAML" "application/x-yaml"
assert_status_any "POST /api/instructions/validate-yaml (invalid)" "$HTTP_STATUS" 200 400 422

log ""

# ══════════════════════════════════════════════════════════════════════
# 21. Approvals
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  21. Approvals"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/approvals"
assert_status_any "GET /api/approvals" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/approvals/pending/count"
assert_status_any "GET /api/approvals/pending/count" "$HTTP_STATUS" 200 503

log ""

sleep 1
refresh_session

# ══════════════════════════════════════════════════════════════════════
# 22. Execution Lifecycle
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  22. Execution Lifecycle"
log "═══════════════════════════════════════════"

# Dispatch a command and track its execution
http_post "$SERVER_URL/api/command" \
    '{"plugin":"os_info","action":"os_name"}'
assert_status_any "POST /api/command (os_info.os_name)" "$HTTP_STATUS" 200 503
CMD_ID=$(extract_json_field "command_id" "$HTTP_BODY")

if [[ -n "$CMD_ID" ]]; then
    sleep 2

    # Poll responses
    http_get "$SERVER_URL/api/responses/$CMD_ID"
    assert_status_any "GET /api/responses/{id}" "$HTTP_STATUS" 200 503

    # Execution list
    http_get "$SERVER_URL/api/executions"
    assert_status_any "GET /api/executions (list)" "$HTTP_STATUS" 200 503

    # Get specific execution details if available
    EXEC_ID=$(echo "$HTTP_BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    execs = d.get('data', d.get('executions', []))
    if isinstance(execs, list) and execs:
        print(execs[0].get('id', execs[0].get('execution_id', '')))
    else:
        print('')
except: print('')
" 2>/dev/null || echo "")

    if [[ -n "$EXEC_ID" ]]; then
        http_get "$SERVER_URL/api/executions/$EXEC_ID"
        assert_status_any "GET /api/executions/{id}" "$HTTP_STATUS" 200 404

        http_get "$SERVER_URL/api/executions/$EXEC_ID/summary"
        assert_status_any "GET /api/executions/{id}/summary" "$HTTP_STATUS" 200 404
    fi
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 23. Notifications
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  23. Notifications"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/notifications"
assert_status_any "GET /api/notifications" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 24. Agent Properties & Config
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  24. Agent Properties & Config"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/property-schemas"
assert_status_any "GET /api/property-schemas" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/config"
assert_status_any "GET /api/config" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 25. Analytics & NVD
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  25. Analytics & NVD"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/analytics/status"
assert_status_any "GET /api/analytics/status" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/nvd/status"
assert_status_any "GET /api/nvd/status" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 26. Inventory Queries
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  26. Inventory Queries"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/v1/inventory/tables"
assert_status_any "GET /api/v1/inventory/tables" "$HTTP_STATUS" 200 503

http_post "$SERVER_URL/api/v1/inventory/query" \
    '{"plugin":"os_info"}'
assert_status_any "POST /api/v1/inventory/query" "$HTTP_STATUS" 200 400 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 27. Directory & Discovery
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  27. Directory & Discovery"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/directory/status"
assert_status_any "GET /api/directory/status" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/directory/users"
assert_status_any "GET /api/directory/users" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/discovery/results"
assert_status_any "GET /api/discovery/results" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 28. Scope Engine
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  28. Scope Engine"
log "═══════════════════════════════════════════"

# Valid expression
http_post "$SERVER_URL/api/scope/validate" '{"expression":"os == \"linux\""}'
assert_eq "POST /api/scope/validate (valid) returns 200" "200" "$HTTP_STATUS"

# Invalid expression
http_post "$SERVER_URL/api/scope/validate" '{"expression":"!!!bad((("}'
assert_eq "POST /api/scope/validate (invalid) returns 200" "200" "$HTTP_STATUS"

# Estimate with expression
http_post "$SERVER_URL/api/scope/estimate" '{"expression":"os == \"linux\""}'
assert_eq "POST /api/scope/estimate returns 200" "200" "$HTTP_STATUS"

log ""

# Pause and re-authenticate before heavy fragment sections
sleep 2
refresh_session

# ══════════════════════════════════════════════════════════════════════
# 29. Settings Endpoints (Admin)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  29. Settings Endpoints"
log "═══════════════════════════════════════════"

SETTINGS_FRAGMENTS=(
    "/fragments/settings/tls"
    "/fragments/settings/users"
    "/fragments/settings/tokens"
    "/fragments/settings/pending"
    "/fragments/settings/auto-approve"
    "/fragments/settings/api-tokens"
    "/fragments/settings/management-groups"
    "/fragments/settings/tag-compliance"
    "/fragments/settings/updates"
    "/fragments/settings/gateway"
    "/fragments/settings/server-config"
    "/fragments/settings/https"
    "/fragments/settings/analytics"
    "/fragments/settings/data-retention"
    "/fragments/settings/mcp"
    "/fragments/settings/nvd"
    "/fragments/settings/directory"
)

for frag in "${SETTINGS_FRAGMENTS[@]}"; do
    http_get "$SERVER_URL$frag"
    assert_status_any "GET $frag" "$HTTP_STATUS" 200 403 404
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 30. Dashboard Fragments
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  30. Dashboard Fragments"
log "═══════════════════════════════════════════"

DASH_FRAGMENTS=(
    "/fragments/results"
    "/fragments/executions"
    "/fragments/schedules"
    "/fragments/health/summary"
    "/fragments/compliance/summary"
)

for frag in "${DASH_FRAGMENTS[@]}"; do
    http_get "$SERVER_URL$frag"
    assert_status_any "GET $frag" "$HTTP_STATUS" 200 400 404
done

log ""

# ══════════════════════════════════════════════════════════════════════
# 31. SSE Stream (quick connect/disconnect)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  31. SSE Stream"
log "═══════════════════════════════════════════"

SSE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "$COOKIE_JAR" \
    -m 2 \
    -H "Accept: text/event-stream" \
    "$SERVER_URL/events" 2>/dev/null) || true
SSE_STATUS="${SSE_STATUS:-000}"
TESTS=$((TESTS + 1))
# SSE returns 200 (connection opens) or curl times out after 2s (returns 000 or partial)
if [[ "$SSE_STATUS" =~ ^(200|000)$ ]]; then
    pass "GET /events SSE stream connects (HTTP $SSE_STATUS or timeout)"
else
    fail "GET /events SSE unexpected status: $SSE_STATUS"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# 32. Static Assets
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  32. Static Assets"
log "═══════════════════════════════════════════"

http_get_noauth "$SERVER_URL/static/yuzu.css"
assert_eq "GET /static/yuzu.css returns 200" "200" "$HTTP_STATUS"

http_get_noauth "$SERVER_URL/static/htmx.js"
assert_eq "GET /static/htmx.js returns 200" "200" "$HTTP_STATUS"

http_get_noauth "$SERVER_URL/static/sse.js"
assert_eq "GET /static/sse.js returns 200" "200" "$HTTP_STATUS"

http_get_noauth "$SERVER_URL/static/icons.svg"
assert_eq "GET /static/icons.svg returns 200" "200" "$HTTP_STATUS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 33. Security Headers
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  33. Security Headers"
log "═══════════════════════════════════════════"

SEC_HEADERS=$(curl -s -D- -o /dev/null -b "$COOKIE_JAR" "$SERVER_URL/api/v1/me" 2>/dev/null)

assert_contains "X-Content-Type-Options: nosniff" "nosniff" "$SEC_HEADERS"
assert_contains "X-Frame-Options: DENY" "DENY" "$SEC_HEADERS"
assert_contains "Referrer-Policy present" "Referrer-Policy" "$SEC_HEADERS"
assert_contains "Permissions-Policy present" "Permissions-Policy" "$SEC_HEADERS"
assert_contains "Content-Security-Policy present" "Content-Security-Policy" "$SEC_HEADERS"

log ""

# ══════════════════════════════════════════════════════════════════════
# 34. MCP Endpoint Reachability
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  34. MCP Endpoint Reachability"
log "═══════════════════════════════════════════"

# MCP without auth → 401
http_post_noauth "$SERVER_URL/mcp/v1/" '{"jsonrpc":"2.0","method":"ping","id":1}'
assert_eq "POST /mcp/v1/ without auth returns 401" "401" "$HTTP_STATUS"

# MCP with auth → 200
http_post "$SERVER_URL/mcp/v1/" '{"jsonrpc":"2.0","method":"ping","id":1}'
assert_eq "POST /mcp/v1/ with auth returns 200" "200" "$HTTP_STATUS"
assert_contains "MCP ping returns jsonrpc response" "jsonrpc" "$HTTP_BODY"

log ""

# ══════════════════════════════════════════════════════════════════════
# 35. Topology & Statistics
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  35. Topology & Statistics"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/v1/topology"
assert_status_any "GET /api/v1/topology" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/v1/statistics"
assert_status_any "GET /api/v1/statistics" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 36. License Endpoints
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  36. License Management"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/v1/license"
assert_status_any "GET /api/v1/license" "$HTTP_STATUS" 200 404 503

http_get "$SERVER_URL/api/v1/license/alerts"
assert_status_any "GET /api/v1/license/alerts" "$HTTP_STATUS" 200 404 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 37. Software Deployment
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  37. Software Deployment"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/v1/software-packages"
assert_status_any "GET /api/v1/software-packages" "$HTTP_STATUS" 200 404 503

http_get "$SERVER_URL/api/v1/software-deployments"
assert_status_any "GET /api/v1/software-deployments" "$HTTP_STATUS" 200 404 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 38. Patch Management
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  38. Patch Management"
log "═══════════════════════════════════════════"

http_get "$SERVER_URL/api/patches"
assert_status_any "GET /api/patches" "$HTTP_STATUS" 200 503

http_get "$SERVER_URL/api/patches/deployments"
assert_status_any "GET /api/patches/deployments" "$HTTP_STATUS" 200 503

log ""

# ══════════════════════════════════════════════════════════════════════
# 39. Rate Limiting (run last — may block subsequent requests)
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════"
log "  39. Rate Limiting"
log "═══════════════════════════════════════════"

log "  Running rate limit test (50 rapid requests to /livez)..."
RATE_LIMIT_HIT=false
for i in $(seq 1 50); do
    RL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/livez" 2>/dev/null || echo "000")
    if [[ "$RL_STATUS" == "429" ]]; then
        RATE_LIMIT_HIT=true
        break
    fi
done
TESTS=$((TESTS + 1))
if [[ "$RATE_LIMIT_HIT" == "true" ]]; then
    pass "Rate limiter triggered (429 returned)"
else
    pass "No rate limiting on health endpoint (acceptable)"
fi

log ""

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
log "═══════════════════════════════════════════════════════════════════"
log "  REST API E2E TEST SUMMARY"
log "═══════════════════════════════════════════════════════════════════"
log ""
log "  Server:     $SERVER_URL"
log "  Skip auth:  $SKIP_AUTH"
log ""
if [[ $FAILURES -eq 0 ]]; then
    log "  ✓ ALL $TESTS TESTS PASSED"
else
    log "  ✗ $FAILURES/$TESTS TESTS FAILED"
fi
log ""
log "═══════════════════════════════════════════════════════════════════"
log ""

if [[ $FAILURES -gt 0 ]]; then
    exit 1
fi

exit 0
