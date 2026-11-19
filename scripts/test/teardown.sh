#!/usr/bin/env bash
# teardown.sh — Phase 8 of the /test pipeline.
#
# Stop every compose project the run created, remove the scratch directory
# under /tmp/yuzu-test-${RUN_ID}, and finalize the test_runs row in the DB
# (set finished_at, compute overall_status from gate aggregates).
#
# Required arguments:
#   --run-id ID          — the run to finalize
#
# Optional:
#   --keep-stack         — leave docker compose projects up (debugging)
#   --keep-test-dir      — leave /tmp/yuzu-test-${RUN_ID}/ behind (debugging)
#   --status STATUS      — persist a status floor; can worsen, never improve, the verdict
#   --test-dir DIR       — scratch dir to remove (default: /tmp/yuzu-test-${RUN_ID})
#
# Idempotent: safe to re-invoke after a partial cleanup.
#
# Usage:
#   bash scripts/test/teardown.sh --run-id "$RUN_ID"
#   bash scripts/test/teardown.sh --run-id "$RUN_ID" --keep-stack    # keep docker up
#   bash scripts/test/teardown.sh --run-id "$RUN_ID" --status ABORTED

set -uo pipefail

# Bash 4+ required: `mapfile` is used below for the compose-project enumeration.
# macOS /bin/bash is 3.2; `#!/usr/bin/env bash` picks up Homebrew bash 5.
if (( ${BASH_VERSINFO[0]:-0} < 4 )); then
    echo "teardown needs bash 4+ (got $BASH_VERSION) — install GNU bash via brew or apt" >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

RUN_ID=""
KEEP_STACK=0
KEEP_TEST_DIR=0
STATUS_OVERRIDE=""
TEST_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)         RUN_ID="$2"; shift 2 ;;
        --keep-stack)     KEEP_STACK=1; shift ;;
        --keep-test-dir)  KEEP_TEST_DIR=1; shift ;;
        --status)         STATUS_OVERRIDE="$2"; shift 2 ;;
        --test-dir)       TEST_DIR="$2"; shift 2 ;;
        -h|--help)        echo "usage: $0 --run-id ID [options]"; exit 0 ;;
        *)                echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$RUN_ID" ]]; then
    echo "missing --run-id" >&2
    exit 2
fi

TEST_DIR="${TEST_DIR:-/tmp/yuzu-test-${RUN_ID}}"

# Sanity: refuse to rm -rf anything that isn't under the documented prefix.
# An operator typo like --test-dir / would otherwise be catastrophic.
case "$TEST_DIR" in
    /tmp/yuzu-test-*) ;;
    *)
        echo "teardown: refusing to rm -rf '$TEST_DIR' — not under /tmp/yuzu-test-*" >&2
        exit 2
        ;;
esac

if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; N=''
fi
ok()   { printf "  ${G}\u2713${N} %s\n" "$*"; }
warn() { printf "  ${Y}\u26a0${N} %s\n" "$*"; }
info() { printf "  ${C}\u2192${N} %s\n" "$*"; }

echo ""
echo "Phase 8 — Teardown (run $RUN_ID)"
echo "================================"

# --- compose projects -----------------------------------------------------

if [[ $KEEP_STACK -eq 1 ]]; then
    warn "--keep-stack: leaving compose projects running"
elif ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    info "docker unavailable — no compose projects to stop"
else
    info "stopping compose projects matching yuzu-test-${RUN_ID}-*"
    # Collect every container labelled with this run's project prefix.
    # The suffix regex accepts [a-z0-9-]+ so future phase project names
    # like 'yuzu-test-${RUN_ID}-ota-windows' or '-phase7-perf' work.
    # Escape literal dots so they only match com.docker.compose.project,
    # not com_docker_compose_project or other label drift. Use -oE (POSIX
    # extended) rather than -oP (Perl) so this works with BSD grep on
    # macOS — the regex uses no Perl-specific features.
    mapfile -t projects_arr < <(
        docker ps -a --format "{{.Labels}}" 2>/dev/null \
        | grep -oE "com\\.docker\\.compose\\.project=yuzu-test-${RUN_ID}-[a-z0-9-]+" \
        | sort -u | cut -d= -f2 || true
    )
    if [[ ${#projects_arr[@]} -eq 0 ]]; then
        ok "no compose projects to stop"
    else
        for p in "${projects_arr[@]}"; do
            if docker compose -p "$p" down -v >/dev/null 2>&1; then
                ok "stopped $p"
            else
                warn "could not cleanly stop $p (may already be down)"
            fi
        done
    fi
fi

# --- scratch dir ----------------------------------------------------------

if [[ $KEEP_TEST_DIR -eq 1 ]]; then
    warn "--keep-test-dir: leaving $TEST_DIR behind"
elif [[ -d "$TEST_DIR" ]]; then
    info "removing $TEST_DIR"
    rm -rf "$TEST_DIR"
    ok "removed $TEST_DIR"
fi

# --- finalize the test_runs row -------------------------------------------

info "finalizing test_runs row"
if [[ -n "$STATUS_OVERRIDE" ]]; then
    bash "$HERE/test-db-write.sh" run-finish --run-id "$RUN_ID" --status "$STATUS_OVERRIDE"
else
    bash "$HERE/test-db-write.sh" run-finish --run-id "$RUN_ID"
fi

ok "teardown complete for $RUN_ID"
