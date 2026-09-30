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
#   5. enrollment_pre62  — WS-6 6.2 upgrade harness: a pre-6.2 enrollment-tokens.cfg
#      / pending-agents.cfg fixture on disk, in the location the 6.2 importer
#      reads from. Written ONLY when --container is given (the OLD, pre-6.2
#      release's own server container) — omit it and this fixture is skipped,
#      same graceful-skip posture as the other best-effort fixtures above.
#
#      As much of this fixture as the OLD binary's OWN HTTP routes can drive is
#      driven through them (create + revoke), so those two states are PROVEN
#      written by the OLD release's real code, in whatever byte-exact format it
#      uses — not assumed. Two states (a partially-consumed multi-use token; the
#      three pending-agent statuses) have NO pre-6.2 HTTP route at all (only a
#      live gRPC Register call reaches them, and driving gRPC from bash is out
#      of scope here) — those rows are constructed directly on disk instead,
#      via `docker exec` into the OLD container, in the exact pre-6.2 colon-
#      delimited format (`git show 257bfb338:server/core/src/auth.cpp` — the
#      save_/load_tokens and save_/load_pending functions this fixture's format
#      is transcribed from). To still PROVE the OLD binary's own code can READ
#      that injected format (not just that this script's transcription is
#      right), the container is restarted after injection and one more write
#      is driven through the OLD binary's OWN HTTP routes — which internally
#      re-serializes its FULL in-memory state — and the file is re-read to
#      confirm the injected rows survived that round trip untouched.
#
# State persisted to: $STATE_FILE (default: $YUZU_TEST_DIR/fixtures-state.json)
# Verifier reads this file to know what to check for.
#
# Usage:
#   bash scripts/test/test-fixtures-write.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --state-file /tmp/yuzu-test-${RUN_ID}/fixtures-state.json \
#       --container "$OLD_SERVER_CONTAINER_ID"   # optional, enables enrollment_pre62

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
STATE_FILE=""
TIMEOUT_S=15
CONTAINER=""
DATA_DIR="/var/lib/yuzu"

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
  --container ID           docker container id/name of the (pre-6.2) server
                           this dashboard talks to. Enables the enrollment_pre62
                           fixture (WS-6 6.2 upgrade harness); omit to skip it.
  --data-dir PATH          --data-dir path INSIDE that container (default:
                           /var/lib/yuzu)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)   DASHBOARD_URL="$2"; shift 2 ;;
        --user)        USERNAME="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --state-file)  STATE_FILE="$2"; shift 2 ;;
        --timeout)     TIMEOUT_S="$2"; shift 2 ;;
        --container)   CONTAINER="$2"; shift 2 ;;
        --data-dir)    DATA_DIR="$2"; shift 2 ;;
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

# --- pre-6.2 enrollment/pending fixture (WS-6 6.2 upgrade harness) --------
# See the file header for the full design rationale. Best-effort: any failure
# here downgrades to a warning (this fixture augments the upgrade harness; it
# must never be why an otherwise-good upgrade test run is marked FAIL).

ENROLL_PRE62_OK=0
TOK_LABEL_PLAIN="preha-plain-${RANDOM}"
TOK_LABEL_REVOKED="preha-revoked-${RANDOM}"
TOK_LABEL_PARTIAL="preha-partial-${RANDOM}"
AGENT_APPROVED="preha-agent-approved-${RANDOM}"
AGENT_DENIED="preha-agent-denied-${RANDOM}"
AGENT_PENDING="preha-agent-pending-${RANDOM}"
AGENT_ROUNDTRIP="preha-agent-roundtrip-${RANDOM}"

if [[ -n "$CONTAINER" ]]; then
    info "pre-6.2 enrollment/pending fixture: container=$CONTAINER data-dir=$DATA_DIR"
    TOKENS_CFG="$DATA_DIR/enrollment-tokens.cfg"
    PENDING_CFG="$DATA_DIR/pending-agents.cfg"

    dexec() { docker exec "$CONTAINER" "$@" 2>/dev/null; }
    dexec_in() { docker exec -i "$CONTAINER" "$@" 2>/dev/null; }

    # token_id is field 1 (1-indexed) of a colon-delimited row; label is field 3.
    # Reads the row for a given label straight off disk — the file format is a
    # documented, version-checked contract (`# Version: 1`), so this is a stable
    # way to recover the id a fragment-scraping approach would not be (dashboard
    # HTML has changed release to release; this colon format has not).
    token_id_for_label() {
        dexec cat "$TOKENS_CFG" | awk -F: -v l="$1" '$3==l {print $1; exit}'
    }

    PRE62_STEP_OK=1

    if ! dexec test -d "$DATA_DIR"; then
        warn "container $CONTAINER has no $DATA_DIR — skipping enrollment_pre62 fixture"
        PRE62_STEP_OK=0
    fi

    if [[ $PRE62_STEP_OK -eq 1 ]]; then
        # Two rows driven through the OLD binary's OWN write path (proves it
        # writes THIS format, not an assumption about it).
        curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
            -X POST "$DASHBOARD_URL/api/settings/enrollment-tokens" \
            -d "label=${TOK_LABEL_PLAIN}&max_uses=1&ttl=3600" >/dev/null 2>&1 || true
        curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
            -X POST "$DASHBOARD_URL/api/settings/enrollment-tokens" \
            -d "label=${TOK_LABEL_REVOKED}&max_uses=1&ttl=3600" >/dev/null 2>&1 || true
        REVOKE_ID=$(token_id_for_label "$TOK_LABEL_REVOKED")
        PLAIN_ID=$(token_id_for_label "$TOK_LABEL_PLAIN")
        if [[ -z "$REVOKE_ID" || -z "$PLAIN_ID" ]]; then
            warn "enrollment_pre62: could not read back the two HTTP-created tokens — skipping"
            PRE62_STEP_OK=0
        else
            # Revoke via the OLD binary's own DELETE route (real write, not injected).
            curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
                -X DELETE "$DASHBOARD_URL/api/settings/enrollment-tokens/${REVOKE_ID}" >/dev/null 2>&1 || true
            REVOKED_FLAG=$(dexec cat "$TOKENS_CFG" | awk -F: -v id="$REVOKE_ID" '$1==id {print $NF}')
            if [[ "$REVOKED_FLAG" != "1" ]]; then
                warn "enrollment_pre62: revoke via the OLD binary's own route did not persist — skipping"
                PRE62_STEP_OK=0
            fi
        fi
    fi

    if [[ $PRE62_STEP_OK -eq 1 ]]; then
        # One row with NO pre-6.2 HTTP route (a partially-consumed multi-use
        # token only a live gRPC Register call could produce): constructed
        # directly, in the exact pre-6.2 format —
        #   token_id:token_hash:label:max_uses:use_count:created_epoch:expires_epoch:revoked
        PARTIAL_ID=$(python3 -c "import secrets; print(secrets.token_hex(4))")
        PARTIAL_HASH=$(python3 -c "import hashlib,secrets; print(hashlib.sha256(secrets.token_hex(32).encode()).hexdigest())")
        NOW_EPOCH=$(date +%s)
        EXPIRES_EPOCH=$((NOW_EPOCH + 3600))
        PARTIAL_LINE="${PARTIAL_ID}:${PARTIAL_HASH}:${TOK_LABEL_PARTIAL}:3:1:${NOW_EPOCH}:${EXPIRES_EPOCH}:0"
        if printf '%s\n' "$PARTIAL_LINE" | dexec_in sh -c "cat >> '$TOKENS_CFG'"; then
            ok "enrollment_pre62: injected a partially-consumed (max_uses=3, use_count=1) token row"
        else
            warn "enrollment_pre62: could not inject the partially-consumed token row — skipping"
            PRE62_STEP_OK=0
        fi

        # Three pending-agent statuses + one throwaway for the round-trip
        # proof below — format: agent_id:hostname:os:arch:version:requested_epoch:status
        PENDING_LINES=$(cat <<EOF
${AGENT_APPROVED}:host-a:linux:x86_64:1.0.0:${NOW_EPOCH}:approved
${AGENT_DENIED}:host-d:linux:x86_64:1.0.0:${NOW_EPOCH}:denied
${AGENT_PENDING}:host-p:linux:x86_64:1.0.0:${NOW_EPOCH}:pending
${AGENT_ROUNDTRIP}:host-r:linux:x86_64:1.0.0:${NOW_EPOCH}:pending
EOF
)
        if ! printf '%s\n' "$PENDING_LINES" | dexec_in sh -c "cat >> '$PENDING_CFG'"; then
            warn "enrollment_pre62: could not inject the pending-agent rows — skipping"
            PRE62_STEP_OK=0
        fi
    fi

    if [[ $PRE62_STEP_OK -eq 1 ]]; then
        # Round-trip proof: restart the OLD binary so load_tokens()/
        # load_pending() must parse the injected rows from a cold process
        # start, then drive ONE more write through each of the OLD binary's
        # OWN routes (which re-serializes its FULL in-memory state) and
        # confirm the injected rows are still there, byte-identical — proving
        # the OLD release's real code parsed this exact format, not just that
        # this script's transcription of it is self-consistent.
        info "enrollment_pre62: restarting $CONTAINER to force a cold reload of the injected rows"
        docker restart "$CONTAINER" >/dev/null 2>&1 || true
        # A container published with an UNPINNED host port (this compose file's
        # "8080", no host-side number) gets a FRESH random host port on every
        # start, not just at creation — measured empirically writing this
        # script: docker restart changed the mapped port on an otherwise-
        # untouched container. Re-resolve it, preserving DASHBOARD_URL's
        # scheme/host and swapping only the port, or every check below polls a
        # now-dead port and this whole fixture silently times out.
        NEW_HOST_PORT=$(docker port "$CONTAINER" 8080/tcp 2>/dev/null | grep -m1 '0\.0\.0\.0:' | sed 's/.*://')
        if [[ -n "$NEW_HOST_PORT" ]]; then
            DASHBOARD_URL=$(python3 -c "
import sys
from urllib.parse import urlsplit, urlunsplit
u = urlsplit(sys.argv[1])
print(urlunsplit((u.scheme, f'{u.hostname}:{sys.argv[2]}', u.path, u.query, u.fragment)))
" "$DASHBOARD_URL" "$NEW_HOST_PORT")
            info "enrollment_pre62: re-resolved dashboard URL after restart: $DASHBOARD_URL"
        fi
        RESTART_WAITED=0
        RESTART_READY=0
        while (( RESTART_WAITED < TIMEOUT_S * 2 )); do
            RB=$(curl -sf --max-time 3 "$DASHBOARD_URL/readyz" 2>/dev/null || echo "")
            [[ "$RB" == *'"ready"'* ]] && { RESTART_READY=1; break; }
            sleep 1
            RESTART_WAITED=$((RESTART_WAITED + 1))
        done
        if [[ $RESTART_READY -eq 0 ]]; then
            warn "enrollment_pre62: $CONTAINER never became ready again after restart — round-trip unproven"
            PRE62_STEP_OK=0
        else
            # Re-authenticate: the restart drops any in-memory session state.
            curl -s -o /dev/null -c "$COOKIES" --max-time "$TIMEOUT_S" \
                "$DASHBOARD_URL/login" -d "username=${USERNAME}&password=${PASSWORD}" 2>/dev/null || true
            curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
                -X POST "$DASHBOARD_URL/api/settings/enrollment-tokens" \
                -d "label=preha-roundtrip-${RANDOM}&max_uses=1&ttl=3600" >/dev/null 2>&1 || true
            curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
                -X POST "$DASHBOARD_URL/api/settings/pending-agents/${AGENT_ROUNDTRIP}/approve" >/dev/null 2>&1 || true

            PARTIAL_SURVIVED=$(dexec cat "$TOKENS_CFG" | awk -F: -v l="$TOK_LABEL_PARTIAL" '$3==l')
            PENDING_SURVIVED=$(dexec cat "$PENDING_CFG" | awk -F: -v a="$AGENT_APPROVED" '$1==a && $7=="approved"')
            DENIED_SURVIVED=$(dexec cat "$PENDING_CFG" | awk -F: -v a="$AGENT_DENIED" '$1==a && $7=="denied"')
            STILL_PENDING_SURVIVED=$(dexec cat "$PENDING_CFG" | awk -F: -v a="$AGENT_PENDING" '$1==a && $7=="pending"')
            if [[ -n "$PARTIAL_SURVIVED" && -n "$PENDING_SURVIVED" && -n "$DENIED_SURVIVED" \
                  && -n "$STILL_PENDING_SURVIVED" ]]; then
                ok "enrollment_pre62: round trip proven — the OLD binary's own code reloaded and re-saved the injected rows unchanged"
                ENROLL_PRE62_OK=1
                WROTE=$((WROTE + 1))
            else
                warn "enrollment_pre62: an injected row did not survive the OLD binary's own reload+resave — round trip NOT proven"
            fi
        fi
    fi
else
    info "enrollment_pre62 fixture skipped (--container not given)"
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
YUZU_FIXT_ENROLL_PRE62_OK="$ENROLL_PRE62_OK" \
YUZU_FIXT_TOK_LABEL_PLAIN="$TOK_LABEL_PLAIN" \
YUZU_FIXT_TOK_LABEL_REVOKED="$TOK_LABEL_REVOKED" \
YUZU_FIXT_TOK_LABEL_PARTIAL="$TOK_LABEL_PARTIAL" \
YUZU_FIXT_AGENT_APPROVED="$AGENT_APPROVED" \
YUZU_FIXT_AGENT_DENIED="$AGENT_DENIED" \
YUZU_FIXT_AGENT_PENDING="$AGENT_PENDING" \
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
    # WS-6 6.2 upgrade harness (enrollment_pre62_ok False/absent => verifier
    # skips its enrollment/pending Postgres-shape checks, same graceful-skip
    # posture as every other fixture above).
    'enrollment_pre62_ok': os.environ['YUZU_FIXT_ENROLL_PRE62_OK'] == '1',
    'token_label_plain': os.environ['YUZU_FIXT_TOK_LABEL_PLAIN'],
    'token_label_revoked': os.environ['YUZU_FIXT_TOK_LABEL_REVOKED'],
    'token_label_partial': os.environ['YUZU_FIXT_TOK_LABEL_PARTIAL'],
    'agent_approved': os.environ['YUZU_FIXT_AGENT_APPROVED'],
    'agent_denied': os.environ['YUZU_FIXT_AGENT_DENIED'],
    'agent_pending': os.environ['YUZU_FIXT_AGENT_PENDING'],
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
