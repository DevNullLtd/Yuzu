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
# (the server refuses a broadcast for these, so a run needs --target-agent-id,
# --confirm-target (that agent's hostname), --run-id and a --params-override file,
# and a non-loopback --dashboard also needs --allow-remote; the runner's --help
# has the full rules and the side effects),
# server-internal (catalog-only definitions the dispatch chokepoint denies, so they
# cannot pass),
# interactive, and network-disrupt (the quarantine ceremony, PR B).
# scripts/test/instructions-risk-classification.json is the authority.
#
# A destructive/forensic run is by hand, on a dedicated disposable stack. NOTE: --risks
# here is a comma list (--risks destructive,forensic); the Python runner it calls takes
# the classes space-separated. --confirm-target is a wrong-target typo guard against
# what the connected server reports; it cannot detect an ssh -L tunnel or a port forward
# to a different stack, and it is not an authorisation control. The password on the
# command line is visible in ps; http:// with --allow-remote sends it in cleartext.
#
# Usage:
#   bash scripts/test/instructions-tests.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --run-id "$RUN_ID" --gate-name instructions
#
# Returns:
#   0    every runnable instruction passed (or returned expected pending_approval)
#   1    one or more failed / errored, the run stopped early, or a destructive/forensic
#        run executed nothing (every row skipped or pending approval)
#   2    argument, infrastructure or pre-flight error (login, content-dir empty,
#        destructive/forensic targeting, --params-override, --run-id); nothing dispatched
#   130  interrupted (Ctrl-C or SIGTERM)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
RUN_ID=""
GATE_NAME="instructions"
RISKS=("safe" "mutating")
TARGET_AGENT_ID=""
CONFIRM_TARGET=""
MANIFEST=""
ALLOW_REMOTE=0
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
  --run-id ID              record per-instruction timings to test-runs DB; also
                           names the User-Agent and the manifest (required for
                           destructive/forensic; [A-Za-z0-9][A-Za-z0-9._-]{0,63})
  --gate-name NAME         gate name to scope timings under (default: instructions)
  --risks LIST             COMMA-separated risk classes to run (the Python
                           runner takes them space-separated)
                           (default: safe,mutating; choices: safe, mutating,
                           destructive, forensic, server-internal,
                           network-disrupt, interactive; destructive and
                           forensic need --target-agent-id, --confirm-target,
                           --run-id and --params-override, and
                           server-internal cannot pass)
  --target-agent-id ID     the id of the one connected agent sent as the target
                           of destructive and forensic dispatches
  --confirm-target HOST    that agent's hostname (must match the server's agent
                           list; required whenever destructive or forensic is
                           selected, with --target-agent-id and --run-id)
  --manifest PATH          destructive/forensic dispatch record, written before
                           each dispatch (default: in the current directory)
  --allow-remote           permit destructive/forensic against a non-loopback
                           --dashboard (refused by default)
  --match REGEX            run only definition ids matching this regex
  --only-id ID             run exactly one definition (debugging)
  --parallelism N          concurrent dispatches (default: 4; forced to 1 when
                           destructive or forensic is selected)
  --poll-timeout SECONDS   per-instruction response poll cap (default: 30; 120 for
                           destructive/forensic rows unless given; a targeted row
                           still running at the deadline fails and stops the run)
  --params-override FILE   JSON mapping {definition_id: {param: value}} (strings
                           or integers) — overrides for the schema-synthesised
                           defaults; for destructive/forensic it is required and
                           is the whole params object. See the runner's --help.
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
        --target-agent-id)  TARGET_AGENT_ID="$2"; shift 2 ;;
        --confirm-target)   CONFIRM_TARGET="$2"; shift 2 ;;
        --manifest)         MANIFEST="$2"; shift 2 ;;
        --allow-remote)     ALLOW_REMOTE=1; shift ;;
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
[[ -n "$TARGET_AGENT_ID" ]] && ARGS+=(--target-agent-id "$TARGET_AGENT_ID")
[[ -n "$CONFIRM_TARGET" ]]  && ARGS+=(--confirm-target "$CONFIRM_TARGET")
[[ -n "$MANIFEST" ]]        && ARGS+=(--manifest "$MANIFEST")
[[ "$ALLOW_REMOTE" -eq 1 ]] && ARGS+=(--allow-remote)
[[ -n "$MATCH" ]]           && ARGS+=(--match "$MATCH")
[[ -n "$ONLY_ID" ]]         && ARGS+=(--only-id "$ONLY_ID")
[[ -n "$PARAMS_OVERRIDE" ]] && ARGS+=(--params-override "$PARAMS_OVERRIDE")
[[ -n "$OUTPUT" ]]          && ARGS+=(--output "$OUTPUT")
[[ "$VERBOSE" -eq 1 ]]      && ARGS+=(--verbose)

exec python3 "$HERE/instructions_runner.py" "${ARGS[@]}"
