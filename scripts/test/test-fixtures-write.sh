#!/usr/bin/env bash
# test-fixtures-write.sh — Pre-populate a known-good fixture set against a
# Yuzu server so the upgrade test can verify nothing was dropped during
# schema migrations.
#
# The fixture set is deliberately MINIMUM-VIABLE for PR1: enough to verify
# the data-preservation guarantee for the highest-stakes stores
# (api_token_store, audit_store, instruction_store, the user table) without
# depending on REST endpoints whose exact shape may differ across versions.
# The verify script re-checks each fixture and reports what survived.
#
# Fixture set:
#   1. enrollment_token  — POST /api/settings/enrollment-tokens
#   2. api_token         — POST /api/settings/api-tokens (best-effort; warns if 404)
#   3. audit_baseline    — GET /api/v1/audit count to record a watermark
#   4. login_session     — proves the admin user persists (re-login post-upgrade)
#
# State persisted to: $STATE_FILE (default: $YUZU_TEST_DIR/fixtures-state.json)
# Verifier reads this file to know what to check for.
#
# Usage:
#   bash scripts/test/test-fixtures-write.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --state-file /tmp/yuzu-test-${RUN_ID}/fixtures-state.json

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
STATE_FILE=""
TIMEOUT_S=15

usage() {
    cat <<EOF
usage: $0 --dashboard URL --password PASS --state-file PATH [options]

Required:
  --dashboard URL          Yuzu server dashboard root
  --password PASS          admin password
  --state-file PATH        where to persist fixture IDs for the verifier

Optional:
  --user NAME              admin user (default: admin)
  --timeout SECONDS        per-call timeout (default: 15)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)   DASHBOARD_URL="$2"; shift 2 ;;
        --user)        USERNAME="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --state-file)  STATE_FILE="$2"; shift 2 ;;
        --timeout)     TIMEOUT_S="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$DASHBOARD_URL" || -z "$PASSWORD" || -z "$STATE_FILE" ]]; then
    usage >&2
    exit 2
fi

mkdir -p "$(dirname "$STATE_FILE")"
COOKIES="$(mktemp -t yuzu-test-fixtures.XXXXXX)"
trap 'rm -f "$COOKIES"' EXIT

if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()   { printf "  ${G}\u2713${N} %s\n" "$*"; }
fl()   { printf "  ${R}\u2717${N} %s\n" "$*"; FAILED=$((FAILED + 1)); }
warn() { printf "  ${Y}\u26a0${N} %s\n" "$*"; }
info() { printf "  ${C}\u2192${N} %s\n" "$*"; }

FAILED=0
WROTE=0

# --- /readyz wait ---------------------------------------------------------
# Don't write fixtures while the server is still migrating. Poll /readyz
# until it returns "ready" (uses the #339 compound-fix readiness contract).

info "waiting for $DASHBOARD_URL/readyz to be ready"
WAITED=0
READYZ=""
while (( WAITED < TIMEOUT_S * 2 )); do
    READYZ=$(curl -sf --max-time 3 "$DASHBOARD_URL/readyz" 2>/dev/null || echo "")
    if [[ "$READYZ" == *'"ready"'* ]]; then
        ok "/readyz ready after ${WAITED}s"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
if [[ "$READYZ" != *'"ready"'* ]]; then
    fl "/readyz never became ready (last body: $READYZ)"
    echo "{\"error\":\"readyz timeout\"}" > "$STATE_FILE"
    exit 1
fi

# --- login ----------------------------------------------------------------

info "logging in as $USERNAME"
LOGIN_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" \
    --max-time "$TIMEOUT_S" \
    "$DASHBOARD_URL/login" \
    -d "username=${USERNAME}&password=${PASSWORD}" 2>/dev/null || echo "000")
if [[ "$LOGIN_HTTP" =~ ^[23] ]]; then
    ok "login HTTP $LOGIN_HTTP"
    WROTE=$((WROTE + 1))
    LOGIN_OK=1
else
    fl "login HTTP $LOGIN_HTTP — cannot continue"
    echo "{\"error\":\"login failed\",\"http\":$LOGIN_HTTP}" > "$STATE_FILE"
    exit 1
fi

# --- audit log baseline ---------------------------------------------------
# Capture the current count of audit log entries so the verifier can check
# that count was preserved (and ideally grew) post-upgrade.

info "capturing audit log baseline"
AUDIT_BASELINE=0
AUDIT_BODY=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
    "$DASHBOARD_URL/api/v1/audit?limit=1000" 2>/dev/null || echo "")
if [[ -n "$AUDIT_BODY" ]]; then
    AUDIT_BASELINE=$(echo "$AUDIT_BODY" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if isinstance(d, list):
        print(len(d))
    elif isinstance(d, dict):
        print(len(d.get('events', d.get('entries', d.get('data', [])))))
    else:
        print(0)
except: print(0)" 2>/dev/null || echo "0")
    ok "audit log baseline: $AUDIT_BASELINE entries"
    WROTE=$((WROTE + 1))
else
    warn "audit log endpoint did not respond — verifier will skip"
fi

# --- enrollment token -----------------------------------------------------

info "creating enrollment token"
ENROLL_BODY=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
    -X POST "$DASHBOARD_URL/api/settings/enrollment-tokens" \
    -d "label=fixture-${RANDOM}&max_uses=1&ttl=3600" 2>/dev/null || echo "")
ENROLL_TOKEN=$(echo "$ENROLL_BODY" | grep -oE '[a-f0-9]{64}' | head -1)
if [[ -n "$ENROLL_TOKEN" ]]; then
    ok "enrollment token created (sha256 prefix ${ENROLL_TOKEN:0:8}...)"
    WROTE=$((WROTE + 1))
else
    warn "enrollment token creation did not return a token (response: ${ENROLL_BODY:0:200})"
fi

# --- API token ------------------------------------------------------------

info "creating API token"
# Field names match settings_routes.cpp POST /api/settings/api-tokens:
# name=<label>, ttl_hours=<hours> — NOT label/ttl (those field names are
# for enrollment tokens). Getting these wrong silently produces a 200
# with an HTML error fragment, which looks like success until verify.
API_TOKEN_BODY=$(curl -s -w "\n__HTTP__%{http_code}" -b "$COOKIES" --max-time "$TIMEOUT_S" \
    -X POST "$DASHBOARD_URL/api/settings/api-tokens" \
    -d "name=fixture-api-${RANDOM}&ttl_hours=1" 2>/dev/null || echo "__HTTP__000")
API_TOKEN_HTTP=$(echo "$API_TOKEN_BODY" | sed -n 's/.*__HTTP__\([0-9][0-9]*\).*/\1/p' | tail -1)
API_TOKEN_RAW=$(echo "$API_TOKEN_BODY" | sed '/__HTTP__/d')
# The success fragment embeds the raw token once. It's long (>=32 url-safe
# chars). An error fragment contains "feedback-error" and no token.
if [[ "$API_TOKEN_HTTP" =~ ^[23] && "$API_TOKEN_RAW" != *"feedback-error"* ]]; then
    API_TOKEN_PREFIX=$(echo "$API_TOKEN_RAW" | grep -oE '[a-zA-Z0-9_-]{32,}' | head -1 || echo "")
    if [[ -n "$API_TOKEN_PREFIX" ]]; then
        ok "API token created"
        WROTE=$((WROTE + 1))
        HAS_API_TOKEN=1
    else
        warn "API token POST succeeded but no token in body: ${API_TOKEN_RAW:0:200}"
        HAS_API_TOKEN=0
    fi
else
    warn "API token creation HTTP $API_TOKEN_HTTP: ${API_TOKEN_RAW:0:200}"
    HAS_API_TOKEN=0
fi

# --- write state file -----------------------------------------------------
# Use a single-quoted heredoc and env var passing so operator-supplied
# --dashboard / --user / --state-file values containing quotes, backslashes
# or newlines cannot break out of the Python string literals. This mirrors
# the fix in test-upgrade-stack.sh's PBKDF2 config generator.

YUZU_FIXT_DASHBOARD="$DASHBOARD_URL" \
YUZU_FIXT_USER="$USERNAME" \
YUZU_FIXT_STATE_FILE="$STATE_FILE" \
YUZU_FIXT_AUDIT_BASELINE="${AUDIT_BASELINE:-0}" \
YUZU_FIXT_ENROLL_TOKEN="${ENROLL_TOKEN:-}" \
YUZU_FIXT_HAS_API_TOKEN="${HAS_API_TOKEN:-0}" \
YUZU_FIXT_LOGIN_OK="${LOGIN_OK:-0}" \
YUZU_FIXT_WROTE="$WROTE" \
YUZU_FIXT_FAILED="$FAILED" \
python3 - <<'PY'
import json, os, time
state = {
    'fixtures_written_at': int(time.time()),
    'dashboard_url': os.environ['YUZU_FIXT_DASHBOARD'],
    'username': os.environ['YUZU_FIXT_USER'],
    'audit_baseline': int(os.environ['YUZU_FIXT_AUDIT_BASELINE']),
    'enrollment_token_present': os.environ['YUZU_FIXT_ENROLL_TOKEN'] != '',
    'api_token_present': os.environ['YUZU_FIXT_HAS_API_TOKEN'] == '1',
    'login_ok': os.environ['YUZU_FIXT_LOGIN_OK'] == '1',
    'wrote_count': int(os.environ['YUZU_FIXT_WROTE']),
    'failed_count': int(os.environ['YUZU_FIXT_FAILED']),
}
state_file = os.environ['YUZU_FIXT_STATE_FILE']
with open(state_file, 'w') as f:
    json.dump(state, f, indent=2)
print(f'  \u2192 state written to {state_file}')
PY

if [[ $FAILED -gt 0 ]]; then
    echo -e "${R}fixtures: $FAILED failed, $WROTE wrote${N}"
    exit 1
fi
echo -e "${G}fixtures: $WROTE wrote${N}"
exit 0
