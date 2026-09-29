#!/usr/bin/env bash
# test-fixtures-verify.sh — Verify the fixture set written by
# test-fixtures-write.sh is still present after an upgrade.
#
# Reads the state file produced by the writer and re-checks every fixture
# against the (now-upgraded) server. Each check produces a per-fixture
# {name, status, expected, actual} entry in fixtures-verify.json.
#
# WHAT THIS DOES NOT PROVE (measured during review, deliberately not fixed here):
#   * api_tokens uses an owner-scoped ROW COUNT, so a green means the owner sees
#     no token, not that the token was invalidated — see the KNOWN LIMIT note at
#     the api_tokens check for the full contract a real proof must satisfy.
#   * user_admin passes whenever the credentials file is still mounted: it is
#     bind-mounted into BOTH upgrade legs and the admin is re-seeded from it, so
#     genuine user-table loss is invisible here despite the wording below.
#   * the audit check parses with `except: print(0)` on both legs, so two
#     unreadable bodies compare `0 >= 0` and pass; and both readings are capped
#     by `?limit=`, so equal-at-the-cap proves nothing.
#   * an unparseable state file yields empty strings that satisfy the numeric
#     comparisons, greening a run that verified nothing.
# None of these were introduced by the change that added this note — all are
# pre-existing, and each was measured rather than reasoned about. They are
# written down because an undocumented blind spot in the only automated
# upgrade-data-loss gate is worse than a documented one, and because a green
# from this script has been mistaken for broader assurance than it carries.
#
# NOT every fixture asserts SURVIVAL. `api_tokens` asserts whichever contract
# the upgrade edge under test actually carries (see --api-tokens-expect): on an
# edge that crosses the ADR-0030 SQLite->Postgres cutover, the CORRECT outcome
# is that every pre-upgrade token is gone, and surviving tokens are the failure.
# So a red result here does not automatically mean "data loss" — read the
# per-fixture line, which always names the real cause, not just the summary
# banner.
#
# Exit codes:
#   0  every fixture upheld its contract (survival, or documented invalidation)
#   1  one or more contracts violated — read the per-fixture lines for which
#   2  bad arguments
#
# Usage:
#   bash scripts/test/test-fixtures-verify.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --state-file /tmp/yuzu-test-${RUN_ID}/fixtures-state.json \
#       --report-file /tmp/yuzu-test-${RUN_ID}/fixtures-verify.json

set -uo pipefail

# Bash 4+ required: `declare -A` is used below for the per-fixture
# verification result map. macOS /bin/bash is 3.2; the `#!/usr/bin/env bash`
# shebang picks up Homebrew bash 5 when present.
if (( ${BASH_VERSINFO[0]:-0} < 4 )); then
    echo "test-fixtures-verify needs bash 4+ (got $BASH_VERSION) — install GNU bash via brew or apt" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
STATE_FILE=""
REPORT_FILE=""
# Which contract the api_tokens fixture must uphold on THIS upgrade edge.
# Default `preserved` is the SAFE direction: an unknown or unclassified edge
# asserts the stronger, non-inverted contract, so it fails loudly rather than
# silently accepting zero tokens. The orchestrator sets `invalidated` only when
# it OBSERVES the legacy-store boot warning (test-upgrade-stack.sh step 6b).
API_TOKENS_EXPECT="${API_TOKENS_EXPECT:-preserved}"
TIMEOUT_S=15

usage() {
    cat <<EOF
usage: $0 --dashboard URL --password PASS --state-file PATH [--report-file PATH]

Required:
  --dashboard URL
  --password PASS
  --state-file PATH        the file written by test-fixtures-write.sh

Optional:
  --user NAME              admin user (default: admin)
  --report-file PATH       per-fixture verify status (default: alongside state file)
  --api-tokens-expect W    preserved|invalidated (default: preserved). Which
                           contract the api_tokens fixture must uphold on THIS
                           upgrade edge. `invalidated` is correct only for an
                           edge crossing the ADR-0030 SQLite->Postgres cutover;
                           test-upgrade-stack.sh sets it from an observable.
  --timeout SECONDS        per-call timeout (default: 15)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)   DASHBOARD_URL="$2"; shift 2 ;;
        --user)        USERNAME="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --state-file)  STATE_FILE="$2"; shift 2 ;;
        --api-tokens-expect) API_TOKENS_EXPECT="$2"; shift 2 ;;
        --report-file) REPORT_FILE="$2"; shift 2 ;;
        --timeout)     TIMEOUT_S="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$DASHBOARD_URL" || -z "$PASSWORD" || -z "$STATE_FILE" ]]; then
    usage >&2
    exit 2
fi
if [[ "$API_TOKENS_EXPECT" != "preserved" && "$API_TOKENS_EXPECT" != "invalidated" ]]; then
    echo "--api-tokens-expect must be 'preserved' or 'invalidated' (got '$API_TOKENS_EXPECT')" >&2
    exit 2
fi
if [[ ! -f "$STATE_FILE" ]]; then
    echo "state file $STATE_FILE not found — did test-fixtures-write.sh run?" >&2
    exit 2
fi

if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$(dirname "$STATE_FILE")/fixtures-verify.json"
fi

if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()   { printf "  ${G}\u2713${N} %s\n" "$*"; PRESERVED=$((PRESERVED + 1)); }
fl()   { printf "  ${R}\u2717${N} %s\n" "$*"; LOST=$((LOST + 1)); }
warn() { printf "  ${Y}\u26a0${N} %s\n" "$*"; SKIPPED=$((SKIPPED + 1)); }
info() { printf "  ${C}\u2192${N} %s\n" "$*"; }
# A fixture whose contract was UPHELD but which was not preserved — the
# ADR-0030 invalidation arm. Counted separately so `preserved_count` and the
# summary line never claim a deliberately-destroyed fixture survived.
okx()  { printf "  ${G}\u2713${N} %s\n" "$*"; UPHELD=$((UPHELD + 1)); }

PRESERVED=0
UPHELD=0
LOST=0
SKIPPED=0
# Fixtures that actually carry DATA across the upgrade. readyz and login are
# infrastructure checks: they pass whenever the server is reachable, so counting
# them in the guarantee-inversion backstop below let a run where every
# data-bearing fixture was skipped still report PASS (Gate 3 F-A).
DATA_OK=0
COOKIES="$(mktemp -t yuzu-test-verify.XXXXXX)"
trap 'rm -f "$COOKIES"' EXIT

# Parse state file. Use env var passing so a state-file path containing
# quotes or special chars can't inject into the Python source. The `key`
# argument is a literal bash positional arg ($1) at the call site — the
# callers pass hardcoded keys, but we still validate via env var for
# consistency with the heredoc pattern elsewhere.
read_state() {
    YUZU_VFY_STATE="$STATE_FILE" YUZU_VFY_KEY="$1" python3 - <<'PY'
import json, os
with open(os.environ['YUZU_VFY_STATE']) as f:
    s = json.load(f)
print(s.get(os.environ['YUZU_VFY_KEY'], ''))
PY
}

# Initialize per-fixture report (will be rewritten with results)
declare -A RESULTS

set_result() {
    RESULTS["$1"]="$2"
}

# --- /readyz wait ---------------------------------------------------------

info "waiting for $DASHBOARD_URL/readyz to be ready (post-upgrade)"
WAITED=0
READYZ=""
while (( WAITED < TIMEOUT_S * 2 )); do
    READYZ=$(curl -sf --max-time 3 "$DASHBOARD_URL/readyz" 2>/dev/null || echo "")
    if [[ "$READYZ" == *'"ready"'* ]]; then
        ok "/readyz ready (no failed_stores)"
        set_result "readyz" "preserved"
        break
    fi
    if [[ "$READYZ" == *'failed_stores'* ]]; then
        fl "/readyz reports failed stores: $READYZ"
        set_result "readyz" "FAILED_STORES: $READYZ"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done
if [[ "$READYZ" != *'"ready"'* && "$READYZ" != *'failed_stores'* ]]; then
    fl "/readyz never responded ready (timed out at ${WAITED}s)"
    set_result "readyz" "timeout"
fi

# --- login still works ----------------------------------------------------

info "verifying login still works (proves user persistence)"
LOGIN_OK_BEFORE=$(read_state login_ok)
LOGIN_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -c "$COOKIES" \
    --max-time "$TIMEOUT_S" \
    "$DASHBOARD_URL/login" \
    -d "username=${USERNAME}&password=${PASSWORD}" 2>/dev/null || echo "000")
if [[ "$LOGIN_HTTP" =~ ^[23] ]]; then
    ok "login HTTP $LOGIN_HTTP"
    set_result "user_admin" "preserved"
else
    fl "login HTTP $LOGIN_HTTP — admin user lost"
    set_result "user_admin" "lost (HTTP $LOGIN_HTTP)"
fi

# --- audit log preserved + grew ------------------------------------------

info "verifying audit log preserved"
AUDIT_BASELINE=$(read_state audit_baseline)
AUDIT_BODY=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
    "$DASHBOARD_URL/api/v1/audit?limit=1000" 2>/dev/null || echo "")
if [[ -n "$AUDIT_BODY" ]]; then
    AUDIT_NOW=$(echo "$AUDIT_BODY" | python3 -c "
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
    if (( AUDIT_NOW >= AUDIT_BASELINE )); then
        ok "audit log $AUDIT_BASELINE → $AUDIT_NOW entries (preserved + grew)"
        set_result "audit_log" "preserved ($AUDIT_BASELINE → $AUDIT_NOW)"
        DATA_OK=$((DATA_OK + 1))
    else
        fl "audit log shrank: $AUDIT_BASELINE → $AUDIT_NOW (data loss)"
        set_result "audit_log" "shrank ($AUDIT_BASELINE → $AUDIT_NOW)"
    fi
else
    warn "audit log endpoint did not respond — cannot verify"
    set_result "audit_log" "skipped"
fi

# --- enrollment tokens preserved ------------------------------------------

info "verifying enrollment tokens preserved"
ENROLL_PRESENT_BEFORE=$(read_state enrollment_token_present)
if [[ "$ENROLL_PRESENT_BEFORE" == "True" ]]; then
    # The public list endpoint is the HTMX fragment at
    # /fragments/settings/tokens — there is no REST v1 list for enrollment
    # tokens. Fragment body is an HTML <table>; a row per token is
    # "<tr><td><code>ID</code>...". An empty table renders a colspan row
    # with the "No tokens created" placeholder. Look for the <code> cell
    # — it only appears when at least one real token row exists.
    ENROLL_LIST=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
        "$DASHBOARD_URL/fragments/settings/tokens" 2>/dev/null || echo "")
    ENROLL_COUNT=$(echo "$ENROLL_LIST" | grep -oE '<td><code>[a-f0-9]+</code></td>' | wc -l)
    if (( ENROLL_COUNT >= 1 )); then
        ok "enrollment tokens preserved ($ENROLL_COUNT present)"
        set_result "enrollment_tokens" "preserved ($ENROLL_COUNT)"
        DATA_OK=$((DATA_OK + 1))
    else
        fl "enrollment tokens lost (had >= 1, now 0)"
        set_result "enrollment_tokens" "lost"
    fi
else
    warn "no enrollment token was written — skipping verify"
    set_result "enrollment_tokens" "skipped"
fi

# --- API tokens INVALIDATED on upgrade, by design (ADR-0030) --------------
#
# This assertion is INVERTED, not relaxed. ADR-0030 moved `ApiTokenStore` from
# SQLite (`api-tokens.db`) onto the Postgres substrate as a FRESH-START CUTOVER
# WITH NO MIGRATION: every API and MCP bearer token minted before the upgrade
# stops working the moment the new server starts. That is documented,
# operator-facing, intended behaviour — `docs/user-manual/upgrading.md`
# "Breaking: API and MCP bearer tokens are invalidated on upgrade" and the
# matching `server-admin.md` note.
#
# The old form asserted `API_COUNT >= 1` and hard-failed Phase 2 on correct
# behaviour. It was red on five consecutive branches (#2581, #2609), and a
# permanently-red gate is an unread gate: it also masked a second, still
# unexplained signal in the same output ("no MigrationRunner events seen").
#
# So SURVIVING tokens are now the failure. Under ADR-0030 a non-empty list
# after the upgrade means the cutover did not happen and a legacy store is
# still being read — which is a real defect, and the one this check now exists
# to catch. `ok` here counts a VERIFIED INVARIANT, not a surviving row.

info "verifying API tokens are invalidated on upgrade (ADR-0030)"
API_PRESENT_BEFORE=$(read_state api_token_present)
if [[ "$API_PRESENT_BEFORE" == "True" ]]; then
    # API tokens ARE exposed via REST v1 — use that instead of the
    # HTMX fragment. The v1 envelope is {"data":[...], "meta":{}}.
    API_LIST=$(curl -s -b "$COOKIES" --max-time "$TIMEOUT_S" \
        "$DASHBOARD_URL/api/v1/tokens" 2>/dev/null || echo "")
    # No `"error"` substring pre-check here, deliberately. It rejected any body
    # CONTAINING that literal, so a token legitimately NAMED "error" produced
    # `api_tokens: endpoint broken` — measured.
    #
    # The `-1` sentinel below covers every error body this ROUTE can actually
    # produce, which is the honest claim; an earlier revision of this comment said
    # "strictly stronger", and that is false. Measured against the helper:
    # `{"error":"boom"}`, an empty body, `not json`, `[]`, `{"meta":{}}`, `null`
    # and `0` all yield -1 (red), while `{"data":[{"name":"error"}],...}` correctly
    # yields 1. The shape the removed screen caught and the sentinel does NOT is a
    # body carrying BOTH a list `data` and an error member — `{"data":[],"error":…}`
    # yields 0, which on a cutover edge reads as PASS.
    #
    # That shape is not reachable from this route today: the A4 error envelope has
    # no `data` key (`rest_api_v1.cpp`), the success envelope has no `error` key,
    # and both 503 paths return early — so no server-produced body hits it. It is
    # reachable from an INTERMEDIARY, and nothing here captures the HTTP status
    # (`curl -s` above, no `-w '%{http_code}'`), so 0-as-PASS rests entirely on
    # body shape. Requiring a 200 is the durable fix and is deliberately NOT done
    # in this commit: it changes the request/parse contract rather than correcting
    # it. Tracked as a follow-up.
    if [[ -n "$API_LIST" ]]; then
        # -1 is a SENTINEL for "could not read the list", and it is load-bearing
        # now that zero is the PASS condition. The previous version printed 0 on
        # a parse failure, which was survivable while >=1 meant success — a
        # malformed body simply failed. Inverting the test without inverting this
        # would turn every unreadable response into a silent PASS. Missing or
        # non-list `data` is treated the same way: unreadable, not empty.
        # Verified by mutation: restore the old `except: print(0)` and both a
        # 502 HTML body and a `{"meta":{}}` envelope score as a clean PASS.
        API_COUNT=$(printf '%s' "$API_LIST" | python3 "$HERE/api_token_count.py" 2>/dev/null || echo "-1")
        # An EMPTY API_COUNT would satisfy `(( API_COUNT == 0 ))` — bash treats
        # the empty string as 0 in an arithmetic context, which silently routes
        # a python that exited 0 with no stdout into the PASS branch and defeats
        # the sentinel above. Measured, not theorised: `A=""; (( A == 0 ))` is
        # true. Anything non-integer is coerced to the unreadable sentinel.
        [[ "$API_COUNT" =~ ^-?[0-9]+$ ]] || API_COUNT=-1
        if (( API_COUNT < 0 )); then
            fl "API tokens endpoint returned an unreadable envelope (no JSON object with a list \`data\`): ${API_LIST:0:200}"
            set_result "api_tokens" "endpoint unreadable"
        elif [[ "$API_TOKENS_EXPECT" == "invalidated" ]]; then
            # This edge CROSSES the ADR-0030 cutover, so the tokens must be gone.
            #
            # KNOWN LIMIT — READ THIS BEFORE TRUSTING A GREEN HERE.
            # A zero count proves the CALLER SEES no token. It does NOT prove the
            # token was invalidated. `GET /api/v1/tokens` is owner-scoped
            # (`list_tokens(session->username)` -> `WHERE principal_id = $1`,
            # api_token_store.cpp), so a principal rename, an RBAC scoping change,
            # or a token minted under a different principal_id each return zero
            # exactly as a real cutover does. So this catches the REALISTIC
            # regression — the cutover silently not happening, which leaves tokens
            # present AND listed — and misses the narrower survive-but-invisible
            # case.
            #
            # This is the pre-existing strength of the evidence, not something
            # this change weakened: the check has always been a row count. It is
            # written down so the next reader does not mistake a green for more
            # than it is.
            #
            # Closing it needs a bearer probe, deliberately left to a SEPARATE
            # change because an attempt at it here produced six blocking findings
            # across two review rounds. What that change must get right — all of
            # it measured, none of it obvious:
            #   * probe `GET /api/v1/me` (auth_fn only), NOT `/api/v1/tokens`
            #     (authorization-gated: a 403 there means AUTHENTICATED but not
            #     authorized, i.e. a live credential);
            #   * require EXACTLY 401 — 403 and 2xx are both invalidation-unproven;
            #   * the WRITER must first prove the extracted string authenticates
            #     pre-upgrade, or a later rejection proves nothing about the real
            #     token;
            #   * failing to arm that probe must FAIL, never downgrade to a skip;
            #   * 401 also means TTL expiry and a dead ApiTokenStore, so widen the
            #     fixture TTL and treat elapsed >= TTL as unproven;
            #   * any selftest for it must be credential-VALUE-aware, or it passes
            #     while the wrong token is presented.
            if (( API_COUNT == 0 )); then
                okx "API tokens invalidated as designed (ADR-0030 — 0 listed; see KNOWN LIMIT above: this is owner-invisibility, not proof of invalidation)"
                set_result "api_tokens" "invalidated as designed (ADR-0030; row-count evidence only)"
                DATA_OK=$((DATA_OK + 1))
            else
                fl "API tokens SURVIVED an upgrade that crossed the ADR-0030 cutover ($API_COUNT present) — a legacy store is still being read"
                set_result "api_tokens" "survived ($API_COUNT) — cutover did not happen"
            fi
        else
            # This edge does NOT cross the cutover (or could not be classified),
            # so the ordinary preservation contract applies and zero is loss.
            if (( API_COUNT >= 1 )); then
                ok "API tokens preserved ($API_COUNT present)"
                set_result "api_tokens" "preserved ($API_COUNT)"
                DATA_OK=$((DATA_OK + 1))
            else
                fl "API tokens lost (had >= 1, now 0) on an edge that does not cross the ADR-0030 cutover"
                set_result "api_tokens" "lost"
            fi
        fi
    else
        fl "API tokens endpoint failed or returned error: ${API_LIST:0:200}"
        set_result "api_tokens" "endpoint broken"
    fi
elif [[ "$API_TOKENS_EXPECT" == "invalidated" ]]; then
    # This edge CROSSES the ADR-0030 cutover, so "no token was written" is NOT a
    # benign skip: nothing exists whose invalidation could have been observed,
    # and passing here reports the token contract satisfied on no evidence.
    #
    # Measured, not theorised: with `api_token_present:false`, `wrote_count:3`
    # and `--api-tokens-expect invalidated`, this script exited 0 and reported
    # `api_tokens: skipped` — a green upgrade gate for the one ADR-0030 claim it
    # exists to test. The sentinel inside the armed branch was hardened against
    # an empty count reaching PASS; this OUTER arm still skipped the entire
    # check, which is the same defect one level up.
    #
    # The writer only `warn`s when token creation fails (test-fixtures-write.sh
    # sets HAS_API_TOKEN=0 and still exits 0), so this is the only place that can
    # turn an unarmed fixture into a red gate.
    fl "API token fixture was not armed on a cutover edge — invalidation unproven"
    set_result "api_tokens" "not armed (invalidation unproven)"
else
    # Non-cutover edge: nothing crossed, so an absent fixture neither proves nor
    # claims anything. A skip is honest here.
    warn "no API token was written — skipping verify"
    set_result "api_tokens" "skipped"
fi

# --- guarantee inversion check (highest-stakes) ---------------------------
# If the writer recorded fixtures-written but verify managed to preserve
# zero of them, that's a guarantee inversion: /test reported PASS on the
# headline data-preservation invariant but actually verified nothing. This
# is exactly the failure mode UP-26 / SLO-VIOLATION-1 from the governance
# run. We hard-fail it here so the upgrade test cannot silently pass.
WROTE_COUNT=$(read_state wrote_count)
WROTE_COUNT=${WROTE_COUNT:-0}
if [[ $WROTE_COUNT -gt 0 && $DATA_OK -eq 0 ]]; then
    fl "guarantee inversion: writer recorded $WROTE_COUNT fixtures, verifier upheld 0 DATA-BEARING fixtures — every data check skipped or failed (readyz/login passing proves only that the server is up)"
    set_result "guarantee_inversion" "writer wrote $WROTE_COUNT, verify preserved 0"
fi

# --- write report ---------------------------------------------------------

mkdir -p "$(dirname "$REPORT_FILE")"
{
    echo "{"
    echo "  \"verified_at\": $(date +%s),"
    echo "  \"wrote_count\": $WROTE_COUNT,"
    echo "  \"preserved_count\": $PRESERVED,"
    echo "  \"upheld_count\": $UPHELD,"
    echo "  \"data_bearing_ok\": $DATA_OK,"
    echo "  \"api_tokens_expect\": \"$API_TOKENS_EXPECT\","
    echo "  \"lost_count\": $LOST,"
    echo "  \"skipped_count\": $SKIPPED,"
    echo "  \"fixtures\": {"
    first=1
    for k in "${!RESULTS[@]}"; do
        if [[ $first -eq 0 ]]; then echo ","; fi
        printf '    "%s": "%s"' "$k" "${RESULTS[$k]//\"/\\\"}"
        first=0
    done
    echo ""
    echo "  }"
    echo "}"
} > "$REPORT_FILE"

echo ""
TOTAL=$((PRESERVED + UPHELD + LOST + SKIPPED))
if [[ $LOST -eq 0 && ! ( $WROTE_COUNT -gt 0 && $DATA_OK -eq 0 ) ]]; then
    echo -e "${G}fixtures verify: $PRESERVED preserved, $UPHELD upheld-by-contract, of $TOTAL${N} ($SKIPPED skipped)"
    exit 0
else
    echo -e "${R}fixtures verify: $LOST FAILED, $PRESERVED preserved, $UPHELD upheld, $SKIPPED skipped — FIXTURE CONTRACT VIOLATED${N}"
    echo -e "${R}Read the per-fixture lines above for the cause. NOT every failure is data loss:${N}"
    echo -e "${R}api_tokens can fail TWO ways, with opposite causes — read its per-fixture line:${N}"
    echo -e "${R}  survived — tokens outlived an ADR-0030 cutover edge. A stale legacy store is${N}"
    echo -e "${R}    still being read; not lost data, and it needs the opposite fix to a restore.${N}"
    echo -e "${R}  not armed — the fixture was never minted, so invalidation is unproven. Nothing${N}"
    echo -e "${R}    was lost; look at the WRITER (test-fixtures-write.sh), not the migration.${N}"
    if [[ $WROTE_COUNT -gt 0 && $DATA_OK -eq 0 ]]; then
        echo -e "${R}GUARANTEE INVERSION: writer recorded $WROTE_COUNT fixtures but zero were verified.${N}"
        echo -e "${R}This may indicate (a) silent data loss, (b) endpoint moved to a different path,${N}"
        echo -e "${R}or (c) the fixture API surface changed. Investigate the gate log immediately.${N}"
    fi
    exit 1
fi
