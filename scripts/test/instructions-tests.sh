#!/usr/bin/env bash
# instructions-tests.sh — exercise every (safe + mutating) InstructionDefinition
# against a live UAT stack via the REST API.
#
# This is the bash entry point for the /test --instructions gate. The
# real work is in scripts/test/instructions_runner.py — this script just
# argument-parses, sources _portable.sh for cross-platform helpers, then
# delegates. Argument shape mirrors scripts/test/synthetic-uat-tests.sh
# so /test orchestration treats it like any other Phase 5 gate.
#
# Defaults run only the safe+mutating definitions the runner can dispatch (it
# prints the exact counts). Opt-in classes, via --risks: destructive and forensic
# (the server refuses a broadcast for these and the runner broadcasts),
# server-internal (catalog-only definitions the dispatch chokepoint denies),
# interactive, and network-disrupt (the quarantine ceremony, PR B). The runner
# supplies no explicit targets, so selecting destructive, forensic or server-internal
# is expected to fail (HTTP 400/503) until it can. The destructive
# instructions are the candidate pool for PR C's hand-written semantic-correctness
# overrides. scripts/test/instructions-risk-classification.json is the authority.
#
# Usage:
#   bash scripts/test/instructions-tests.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --run-id "$RUN_ID" --gate-name instructions
#
# Returns:
#   0  every runnable instruction passed (or returned expected pending_approval)
#   1  one or more failed / errored
#   2  argument or infrastructure error (login, content-dir empty)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
RUN_ID=""
GATE_NAME="instructions"
RISKS=("safe" "mutating")
MATCH=""
ONLY_ID=""
PARALLELISM="4"
POLL_TIMEOUT="30"
PARAMS_OVERRIDE=""
OUTPUT=""
VERBOSE=0

usage() {
    cat <<EOF
usage: $0 --dashboard URL --password PASS [options]

Required:
  --dashboard URL          Yuzu server dashboard root, e.g. http://localhost:8080
  --password PASS          admin password

Optional:
  --user NAME              admin user (default: admin)
  --run-id ID              record per-instruction timings to test-runs DB
  --gate-name NAME         gate name to scope timings under (default: instructions)
  --risks LIST             comma-separated risk classes to run
                           (default: safe,mutating; choices: safe, mutating,
                           destructive, forensic, server-internal,
                           network-disrupt, interactive; destructive,
                           forensic and server-internal cannot pass yet:
                           the runner sends no explicit targets)
  --match REGEX            run only definition ids matching this regex
  --only-id ID             run exactly one definition (debugging)
  --parallelism N          concurrent dispatches (default: 4)
  --poll-timeout SECONDS   per-instruction response poll cap (default: 30)
  --params-override FILE   JSON mapping {definition_id: {param: value}} —
                           hand-written overrides for the schema-synthesised
                           defaults (used by PR C semantic-correctness suite)
  --output FILE            write per-instruction outcomes JSON
  --verbose                print every outcome (default: fail/error only)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)        DASHBOARD_URL="$2"; shift 2 ;;
        --user)             USERNAME="$2"; shift 2 ;;
        --password)         PASSWORD="$2"; shift 2 ;;
        --run-id)           RUN_ID="$2"; shift 2 ;;
        --gate-name)        GATE_NAME="$2"; shift 2 ;;
        --risks)            IFS=',' read -ra RISKS <<< "$2"; shift 2 ;;
        --match)            MATCH="$2"; shift 2 ;;
        --only-id)          ONLY_ID="$2"; shift 2 ;;
        --parallelism)      PARALLELISM="$2"; shift 2 ;;
        --poll-timeout)     POLL_TIMEOUT="$2"; shift 2 ;;
        --params-override)  PARAMS_OVERRIDE="$2"; shift 2 ;;
        --output)           OUTPUT="$2"; shift 2 ;;
        --verbose)          VERBOSE=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$DASHBOARD_URL" ]]; then
    echo "error: --dashboard is required" >&2
    usage >&2
    exit 2
fi
if [[ -z "$PASSWORD" ]]; then
    echo "error: --password is required" >&2
    usage >&2
    exit 2
fi

# PyYAML is a hard requirement — embed_content.py also depends on it, so
# the project's existing build prereqs already cover it.
if ! python3 -c "import yaml" 2>/dev/null; then
    echo "error: PyYAML missing for 'python3'. On a developer machine, install it "\
"with 'pip install pyyaml' (or 'pacman -S python-yaml' on MSYS2). On a shared "\
"self-hosted CI runner, do not install it here: fix the runner's provisioning." >&2
    exit 2
fi

ARGS=(
    --dashboard "$DASHBOARD_URL"
    --user "$USERNAME"
    --password "$PASSWORD"
    --risks "${RISKS[@]}"
    --parallelism "$PARALLELISM"
    --poll-timeout "$POLL_TIMEOUT"
    --gate-name "$GATE_NAME"
)
[[ -n "$RUN_ID" ]]          && ARGS+=(--run-id "$RUN_ID")
[[ -n "$MATCH" ]]           && ARGS+=(--match "$MATCH")
[[ -n "$ONLY_ID" ]]         && ARGS+=(--only-id "$ONLY_ID")
[[ -n "$PARAMS_OVERRIDE" ]] && ARGS+=(--params-override "$PARAMS_OVERRIDE")
[[ -n "$OUTPUT" ]]          && ARGS+=(--output "$OUTPUT")
[[ "$VERBOSE" -eq 1 ]]      && ARGS+=(--verbose)

exec python3 "$HERE/instructions_runner.py" "${ARGS[@]}"
