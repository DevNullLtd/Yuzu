#!/usr/bin/env bash
# test-upgrade-stack.sh — Phase 2 of the /test pipeline.
#
# Stand up the previous-released yuzu-server image (default: GitHub's
# current "Latest release" tag, resolved at runtime via `gh api`; override
# with --old-version, or set YUZU_RELEASE_REPO to point at a fork), populate
# fixtures, swap to the local HEAD image (built in
# Phase 1, tagged yuzu-server:test-${RUN_ID}), verify migrations ran and
# fixtures survived, and run the synthetic UAT test set against the
# upgraded stack. Records sub-step timings into the test-runs DB.
#
# This is the user's stated headline priority for /test: "first stand up
# the last version of the UAT environment, and then upgrade it, and then
# test that — because that is what most users will want to do."
#
# Required arguments:
#   --run-id ID           — links sub-step timings to the test-runs row
#
# Optional arguments:
#   --old-version V       — image tag to upgrade FROM (default: 0.10.0)
#   --new-version V       — image tag to upgrade TO   (default: 0.10.1-test-${RUN_ID})
#   --new-image-loaded 0|1 — 1 if the new image is already in the local
#                            daemon (built locally in Phase 1); 0 to docker pull
#                            (default: 1)
#   --test-dir DIR        — scratch dir (default: /tmp/yuzu-test-${RUN_ID})
#   --keep-stack          — leave the stack up after the test (debugging)
#   --user NAME           — admin username (default: testadmin)
#   --password PASS       — admin password (default: random per run)
#
# Records the following timings (gate=phase2):
#   pull-old-images, stack-up-old, fixtures-write,
#   image-swap, ready-after-upgrade, fixtures-verify,
#   synthetic-uat-against-upgraded
#
# Records the gate row 'Upgrade vOLD->NEW' to test_gates with overall PASS/FAIL.
#
# Exit code is the gate result: 0 PASS, 1 FAIL.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
YUZU_ROOT="$(cd "$HERE/../.." && pwd)"

RUN_ID=""
OLD_VERSION=""
NEW_VERSION=""
NEW_IMAGE_LOADED=1
TEST_DIR=""
KEEP_STACK=0
USERNAME="testadmin"
PASSWORD=""

usage() {
    cat <<EOF
usage: $0 --run-id ID [options]

Required:
  --run-id ID

Optional:
  --old-version V        (default: GitHub's "Latest release" tag via
                          \`gh api repos/:owner/:repo/releases/latest\`,
                          with the leading \`v\` stripped; falls back to
                          0.10.0 if the gh CLI is unavailable or the
                          repo has no non-prerelease releases)
  --new-version V        (default: 0.10.1-test-\${RUN_ID})
  --new-image-loaded 0|1 (default: 1 — assumes Phase 1 built it)
  --test-dir DIR         (default: /tmp/yuzu-test-\${RUN_ID})
  --keep-stack           leave the stack running after the test
  --user NAME            (default: testadmin)
  --password PASS        (default: randomly generated per run)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)            RUN_ID="$2"; shift 2 ;;
        --old-version)       OLD_VERSION="$2"; shift 2 ;;
        --new-version)       NEW_VERSION="$2"; shift 2 ;;
        --new-image-loaded)  NEW_IMAGE_LOADED="$2"; shift 2 ;;
        --test-dir)          TEST_DIR="$2"; shift 2 ;;
        --keep-stack)        KEEP_STACK=1; shift ;;
        --user)              USERNAME="$2"; shift 2 ;;
        --password)          PASSWORD="$2"; shift 2 ;;
        -h|--help)           usage; exit 0 ;;
        *)                   echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "missing --run-id" >&2
    usage >&2
    exit 2
fi

# Cross-platform helpers (docker_available, ensure_docker_path).
# shellcheck source=scripts/test/_portable.sh
. "$HERE/_portable.sh"

# The api_token_count helper decides whether a token list is EMPTY or UNREADABLE,
# and fixtures-verify reads "empty" as a PASS on a cutover edge. If that helper is
# wrong, this whole phase's verdict is meaningless — so prove it before standing
# anything up. <1s, no docker. (Only tests/test_changelog_order.py is wired into a
# workflow today, by explicit name in docs-lint.yml; proper CI wiring for this one
# is filed separately.)
if ! python3 "$YUZU_ROOT/tests/test_api_token_count.py" >/dev/null 2>&1; then
    echo "test-upgrade-stack: api_token_count table test FAILED — refusing to run Phase 2" >&2
    python3 "$YUZU_ROOT/tests/test_api_token_count.py" >&2
    exit 1
fi

# Phase 2 fundamentally needs a working dockerd — every step is docker
# compose. If docker is missing/down, soft-skip with a SKIP gate row so
# the rest of /test continues. The skill prompt warns operators on macOS
# that this happens when OrbStack/Docker Desktop isn't running.
if ! docker_available; then
    echo "test-upgrade-stack: docker not reachable — recording SKIP and exiting cleanly" >&2
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" --phase 2 --gate "Upgrade test" \
        --status SKIP --duration 0 \
        --notes "docker not available — install/start OrbStack or Docker Desktop" || true
    exit 0
fi

# Resolve --old-version default from GitHub's "Latest release" (which excludes
# prereleases) if the operator didn't pin one. This lets /test track whatever
# the last published stable tag is rather than an ever-staler hardcoded pin.
# Fallback to 0.10.0 if gh is unavailable or the API call fails, so the
# pipeline still runs on a fresh clone without gh configured.
if [[ -z "$OLD_VERSION" ]]; then
    if command -v gh >/dev/null 2>&1; then
        resolved=$(gh api "repos/${YUZU_RELEASE_REPO:-Tr3kkR/Yuzu}/releases/latest" \
                      --jq '.tag_name' 2>/dev/null | sed 's/^v//') || resolved=""
    fi
    if [[ -n "${resolved:-}" ]]; then
        OLD_VERSION="$resolved"
        echo "test-upgrade-stack: resolved --old-version=$OLD_VERSION (latest release)"
    else
        OLD_VERSION="0.10.0"
        echo "test-upgrade-stack: gh unavailable or no releases — falling back to --old-version=$OLD_VERSION" >&2
    fi
fi

NEW_VERSION="${NEW_VERSION:-0.10.1-test-${RUN_ID}}"
TEST_DIR="${TEST_DIR:-/tmp/yuzu-test-${RUN_ID}}"
PROJECT_NAME="yuzu-test-${RUN_ID}-upgrade"
PHASE2_DIR="$TEST_DIR/upgrade"

# Fail loudly if scratch dir cannot be created — running on a read-only
# filesystem or with bad permissions should not silently fall through.
if ! mkdir -p "$PHASE2_DIR" 2>&1; then
    echo "test-upgrade-stack: cannot create $PHASE2_DIR" >&2
    exit 1
fi

# Generate a random admin password if not provided. token_urlsafe is
# base64url so it has no shell metacharacters — but we still pass it via
# environment variables to all subsequent Python invocations to avoid any
# possibility of injection if a future caller passes --password with
# special characters.
if [[ -z "$PASSWORD" ]]; then
    PASSWORD=$(python3 -c "import secrets; print('Yz!' + secrets.token_urlsafe(16))")
fi

# Generate the credentials file (PBKDF2-SHA256 — same as linux-start-UAT.sh).
# Pass username and password via env vars so single-quote, backslash, or
# newline characters in operator-supplied passwords cannot break out of a
# Python string literal.
CONFIG_FILE="$PHASE2_DIR/yuzu-server.cfg"
YUZU_TEST_USER="$USERNAME" YUZU_TEST_PASS="$PASSWORD" python3 - <<'PY' > "$CONFIG_FILE"
import hashlib, os, sys
user = os.environ['YUZU_TEST_USER']
password = os.environ['YUZU_TEST_PASS']
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
sys.stdout.write(f'{user}:admin:{salt.hex()}:{dk.hex()}\n')
PY
# 644 is required, not 600: Dockerfile.server drops to USER yuzu
# (unprivileged) before reading the config. A 600 file owned by the
# test runner's UID is invisible to the in-container yuzu user even
# though dockerd is root. The parent /tmp/yuzu-test-${RUN_ID}/ is
# already 700 owned by the test runner, so 644 on the config file
# inside that dir does not expose it to other host users.
chmod 644 "$CONFIG_FILE"
chmod 700 "$PHASE2_DIR"

# Output helpers + colours
if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()    { printf "  ${G}\u2713${N} %s\n" "$*"; }
fl()    { printf "  ${R}\u2717${N} %s\n" "$*"; }
warn()  { printf "  ${Y}\u26a0${N} %s\n" "$*"; }
info()  { printf "  ${C}\u2192${N} %s\n" "$*"; }
phase() { printf "\n${C}=== %s ===${N}\n" "$*"; }

now_ms() { python3 -c "import time; print(int(time.time()*1000))"; }
elapsed_ms() { local s=$1; local e=$(now_ms); echo $((e - s)); }

record_timing() {
    bash "$HERE/test-db-write.sh" timing \
        --run-id "$RUN_ID" --gate "phase2" --step "$1" --ms "$2" >/dev/null || true
}

record_gate() {
    local status="$1" duration_s="$2" notes="${3:-}"
    bash "$HERE/test-db-write.sh" gate \
        --run-id "$RUN_ID" --phase 2 \
        --gate "Upgrade ${OLD_VERSION}->${NEW_VERSION}" \
        --status "$status" --duration "$duration_s" \
        --log "upgrade.log" \
        --notes "$notes" >/dev/null || true
}

GATE_START=$(now_ms)
LOG_FILE="$PHASE2_DIR/upgrade.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Cleanup hook
cleanup() {
    if [[ $KEEP_STACK -eq 1 ]]; then
        warn "leaving stack up: $PROJECT_NAME (--keep-stack)"
        return
    fi
    info "tearing down compose project $PROJECT_NAME"
    YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
        docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
        --project-name "$PROJECT_NAME" \
        down -v >/dev/null 2>&1 || true
}
if [[ $KEEP_STACK -eq 0 ]]; then
    trap cleanup EXIT
fi

phase "Phase 2 — Upgrade Test (${OLD_VERSION} -> ${NEW_VERSION})"
info "RUN_ID=$RUN_ID  PROJECT=$PROJECT_NAME  TEST_DIR=$TEST_DIR"
info "admin user: $USERNAME (random password, ${#PASSWORD} chars, not logged)"
info "compose: $HERE/docker-compose.upgrade-test.yml"

# --- Step 1: pull old images ----------------------------------------------

phase "step: pull old images (${OLD_VERSION})"
T_START=$(now_ms)
if ! YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    pull >> "$LOG_FILE" 2>&1; then
    fl "docker compose pull failed for ${OLD_VERSION}"
    record_timing "pull-old-images" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "pull failed"
    exit 1
fi
record_timing "pull-old-images" "$(elapsed_ms "$T_START")"
ok "pulled ghcr.io/tr3kkr/yuzu-server:${OLD_VERSION}"

# --- Step 2: stack up at OLD version --------------------------------------

phase "step: stack up at OLD ${OLD_VERSION}"
T_START=$(now_ms)
if ! YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    up -d >> "$LOG_FILE" 2>&1; then
    fl "compose up failed at OLD version"
    record_timing "stack-up-old" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "compose up old failed"
    exit 1
fi

# Find the host port for 8080
SERVER_HOST_PORT=$(YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    port server 8080 2>/dev/null | awk -F: '{print $NF}')
if [[ -z "$SERVER_HOST_PORT" ]]; then
    fl "could not determine server host port"
    record_timing "stack-up-old" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "no host port"
    exit 1
fi
DASHBOARD_URL="http://localhost:${SERVER_HOST_PORT}"
info "dashboard at $DASHBOARD_URL"

# Wait for /readyz to come back ready
WAITED=0
READY=0
while (( WAITED < 60 )); do
    BODY=$(curl -sf --max-time 3 "${DASHBOARD_URL}/readyz" 2>/dev/null || echo "")
    if [[ "$BODY" == *'"ready"'* ]]; then
        READY=1
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done
record_timing "stack-up-old" "$(elapsed_ms "$T_START")"
if [[ $READY -eq 0 ]]; then
    fl "OLD stack never reported /readyz ready (waited ${WAITED}s)"
    YUZU_VERSION="$OLD_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
        docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
        --project-name "$PROJECT_NAME" logs server 2>&1 | tail -50 >> "$LOG_FILE"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "old /readyz timeout"
    exit 1
fi
ok "OLD stack ready (waited ${WAITED}s)"

# --- Step 3: fixtures-write -----------------------------------------------

phase "step: fixtures-write (against OLD ${OLD_VERSION})"
T_START=$(now_ms)
STATE_FILE="$PHASE2_DIR/fixtures-state.json"
if bash "$HERE/test-fixtures-write.sh" \
    --dashboard "$DASHBOARD_URL" \
    --user "$USERNAME" --password "$PASSWORD" \
    --state-file "$STATE_FILE" >> "$LOG_FILE" 2>&1; then
    ok "fixtures written"
    FIXTURE_WRITE_OK=1
else
    fl "fixtures-write failed (see $LOG_FILE)"
    FIXTURE_WRITE_OK=0
fi
record_timing "fixtures-write" "$(elapsed_ms "$T_START")"

if [[ $FIXTURE_WRITE_OK -eq 0 ]]; then
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "fixtures write failed"
    exit 1
fi

# --- Step 4: image swap to NEW --------------------------------------------

phase "step: image swap to NEW ${NEW_VERSION}"
if [[ "$NEW_IMAGE_LOADED" != "1" ]]; then
    info "pulling new image (--new-image-loaded 0)"
    if ! docker pull "ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION}" >> "$LOG_FILE" 2>&1; then
        fl "docker pull of new image failed"
        record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "new image pull failed"
        exit 1
    fi
fi

# Verify the new image is locally available
if ! docker image inspect "ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION}" >/dev/null 2>&1; then
    # fall back: maybe the image is just `yuzu-server:test-${RUN_ID}` without ghcr prefix
    if docker image inspect "yuzu-server:${NEW_VERSION}" >/dev/null 2>&1; then
        info "using local image yuzu-server:${NEW_VERSION} (no ghcr prefix)"
        # Tag it with the ghcr prefix so the compose file picks it up
        docker tag "yuzu-server:${NEW_VERSION}" "ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION}"
    else
        fl "new image ghcr.io/tr3kkr/yuzu-server:${NEW_VERSION} not in local daemon"
        warn "Phase 1 should have built it as 'yuzu-server:${NEW_VERSION}' or pulled it"
        record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "new image missing"
        exit 1
    fi
fi

T_START=$(now_ms)
if ! YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    up -d >> "$LOG_FILE" 2>&1; then
    fl "compose up failed at NEW version"
    record_timing "image-swap" "$(elapsed_ms "$T_START")"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "compose up new failed"
    exit 1
fi
record_timing "image-swap" "$(elapsed_ms "$T_START")"
ok "image swap done"

# --- Step 5: ready-after-upgrade ------------------------------------------

phase "step: wait for /readyz after upgrade"
# Re-find the port — compose may have rebound it
SERVER_HOST_PORT=$(YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" \
    port server 8080 2>/dev/null | awk -F: '{print $NF}')
DASHBOARD_URL="http://localhost:${SERVER_HOST_PORT}"
info "post-upgrade dashboard at $DASHBOARD_URL"

T_START=$(now_ms)
WAITED=0
READY=0
FAILED_STORES=""
while (( WAITED < 90 )); do
    BODY=$(curl -sf --max-time 3 "${DASHBOARD_URL}/readyz" 2>/dev/null || echo "")
    if [[ "$BODY" == *'"ready"'* ]]; then
        READY=1
        break
    fi
    if [[ "$BODY" == *'failed_stores'* ]]; then
        FAILED_STORES="$BODY"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done
record_timing "ready-after-upgrade" "$(elapsed_ms "$T_START")"

if [[ $READY -ne 1 ]]; then
    if [[ -n "$FAILED_STORES" ]]; then
        fl "/readyz reports failed stores: $FAILED_STORES"
    else
        fl "/readyz never recovered after upgrade (waited ${WAITED}s)"
    fi
    YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
        docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
        --project-name "$PROJECT_NAME" logs server | tail -100 >> "$LOG_FILE"
    record_gate "FAIL" "$(($(elapsed_ms "$GATE_START") / 1000))" "post-upgrade not ready"
    exit 1
fi
ok "/readyz ready after upgrade (waited ${WAITED}s)"

# --- Step 6: count migration runner events --------------------------------

phase "step: count MigrationRunner events in server log"
# The env prefix is REQUIRED, not decorative: without YUZU_TEST_CONFIG the
# compose file's cred bind-mount spec is `:/etc/yuzu/yuzu-server.cfg:ro`, which
# compose rejects outright. `2>/dev/null` then swallows the error, `grep -c`
# returns 0, and this step reports "no MigrationRunner events seen" having never
# read a log line. That is the root cause of #2609's second, unexplained signal:
# measured at 0 here, and 13 with the prefix restored against the same stack.
MIGR_COUNT=$(YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" logs server \
    | grep -c "MigrationRunner: .* migrated to v" || true)
if (( MIGR_COUNT > 0 )); then
    ok "MigrationRunner events: $MIGR_COUNT (expected ~30)"
    bash "$HERE/test-db-write.sh" metric --run-id "$RUN_ID" \
        --name "phase2_migration_events" --value "$MIGR_COUNT" --unit "count" >/dev/null || true
else
    warn "no MigrationRunner events seen — maybe DB was already at HEAD schema?"
fi

# --- Step 6b: did THIS upgrade edge cross the ApiTokenStore cutover? -------
#
# ADR-0030 moved ApiTokenStore from SQLite to Postgres as a fresh-start cutover
# with no migration, so whether API tokens SHOULD survive depends entirely on
# which edge is under test — and `--old-version` FLOATS to GitHub's current
# "Latest release". Today v0.13.0 (2026-07-11) predates the cutover (4a05df88,
# 2026-07-15), so tokens are correctly invalidated. The moment a release
# CONTAINING the cutover becomes Latest, Phase 2 becomes a Postgres->Postgres
# edge over a `postgres-data` volume this compose file deliberately preserves
# across the image swap: tokens survive, and a hardcoded "expect invalidated"
# would fail the gate while announcing something false.
#
# So derive the arm from an OBSERVABLE rather than a version table. The new
# server warns at boot when it finds a legacy api-tokens.db in the surviving
# data volume (server.cpp: "[auth] Legacy SQLite api-tokens.db found at").
# That fires if and only if this edge crossed the cutover, and it keeps working
# unedited as releases move.
#
# The default is `preserved` — the SAFE direction. If the observable is absent
# or the grep fails, we assert the stronger, NON-inverted contract, so an
# unknown edge reads as a loud failure rather than a silent pass.

phase "step: classify the API-token upgrade edge"
API_TOKENS_EXPECT="preserved"
# Probe the FILESYSTEM, not the boot log. The server does log a "Legacy SQLite
# api-tokens.db found at" warning on a crossing edge, and an earlier revision of
# this step grepped for it — but `docker compose logs` lags the process, so the
# line is reliably present minutes later and intermittently absent at the moment
# this step runs. A log grep here is a race; the file either exists in the
# preserved data volume or it does not.
PROBE_ERR=$(YUZU_VERSION="$NEW_VERSION" YUZU_TEST_CONFIG="$CONFIG_FILE" \
    docker compose -f "$HERE/docker-compose.upgrade-test.yml" \
    --project-name "$PROJECT_NAME" exec -T server \
    test -f /var/lib/yuzu/api-tokens.db 2>&1)
PROBE_RC=$?
if (( PROBE_RC == 0 )); then
    API_TOKENS_EXPECT="invalidated"
    ok "edge CROSSES the ADR-0030 cutover — API tokens must be invalidated"
elif (( PROBE_RC == 1 )) && [[ -z "$PROBE_ERR" ]]; then
    # `test -f` writes nothing and exits 1 for a genuinely absent file. Anything
    # else — 125/126/127, or any stderr — is the PROBE failing, not an answer.
    ok "edge does NOT cross the ADR-0030 cutover — API tokens must be preserved"
else
    # Distinguished deliberately: falling through to `preserved` here is still the
    # safe direction, but reporting it as "the edge does not cross the cutover"
    # would be a confident wrong diagnosis — the #2581 defect in miniature.
    warn "cutover probe FAILED (rc=$PROBE_RC): ${PROBE_ERR:-no stderr} — assuming 'preserved' (safe direction); a red api_tokens below may be this probe, not the data"
fi

# --- Step 7: fixtures-verify ----------------------------------------------

phase "step: fixtures-verify (against NEW ${NEW_VERSION})"
T_START=$(now_ms)
REPORT_FILE="$PHASE2_DIR/fixtures-verify.json"
if bash "$HERE/test-fixtures-verify.sh" \
    --dashboard "$DASHBOARD_URL" \
    --user "$USERNAME" --password "$PASSWORD" \
    --state-file "$STATE_FILE" \
    --api-tokens-expect "$API_TOKENS_EXPECT" \
    --report-file "$REPORT_FILE" >> "$LOG_FILE" 2>&1; then
    ok "fixtures verified"
    FIXTURE_VERIFY_OK=1
else
    fl "fixtures-verify reported losses (see $REPORT_FILE)"
    FIXTURE_VERIFY_OK=0
fi
record_timing "fixtures-verify" "$(elapsed_ms "$T_START")"

# --- Step 8: synthetic UAT against upgraded stack -------------------------

phase "step: synthetic UAT against upgraded stack"
T_START=$(now_ms)
# --no-agent: the upgrade-test compose has no agent service (intentional —
# data-preservation tests don't need one). Pass --no-agent so the 4
# agent-dependent tests (3 server agent metric, 4 gateway agent metric,
# 5 help command, 6 os_info round-trip) skip cleanly instead of failing.
# Tests 1 (dashboard reachable) and 2 (gateway readyz, also auto-skipped
# because no --gateway-health URL) still run.
if bash "$HERE/synthetic-uat-tests.sh" \
    --dashboard "$DASHBOARD_URL" \
    --user "$USERNAME" --password "$PASSWORD" \
    --no-agent \
    --run-id "$RUN_ID" \
    --gate-name "phase2-synthetic-uat" >> "$LOG_FILE" 2>&1; then
    ok "synthetic UAT passed against upgraded stack"
    UAT_OK=1
else
    fl "synthetic UAT failed against upgraded stack"
    UAT_OK=0
fi
record_timing "synthetic-uat-against-upgraded" "$(elapsed_ms "$T_START")"

# --- Final gate result ----------------------------------------------------

GATE_DURATION=$((($(now_ms) - GATE_START) / 1000))
if [[ $FIXTURE_VERIFY_OK -eq 1 && $UAT_OK -eq 1 ]]; then
    ok "Phase 2 PASS"
    record_gate "PASS" "$GATE_DURATION" \
        "fixtures upheld (api_tokens=${API_TOKENS_EXPECT}), /readyz green, ${MIGR_COUNT} migrations stamped"
    exit 0
else
    fl "Phase 2 FAIL (fixture_verify=$FIXTURE_VERIFY_OK uat=$UAT_OK)"
    record_gate "FAIL" "$GATE_DURATION" \
        "fixture_verify=$FIXTURE_VERIFY_OK uat=$UAT_OK"
    exit 1
fi
