#!/usr/bin/env bash
# test_runner.sh — Run Erlang gateway tests
#
# Usage:
#   ./test_runner.sh                 # Run all tests
#   ./test_runner.sh eunit           # Run only EUnit tests
#   ./test_runner.sh ct              # Run only Common Test suites
#   ./test_runner.sh cover           # Run with coverage
#
# `ct` includes yuzu_gw_perf_SUITE at its FULL default sizing (10k agents,
# 50k heartbeats, 300 s endurance) unless YUZU_PERF_* is set, so expect it
# to run for many minutes -- it is not hung. For a quick functional pass use
# the reduced sizing the Meson gate uses (scripts/test_gateway.py), e.g.
#   YUZU_PERF_AGENTS=10 YUZU_PERF_HEARTBEATS=100 YUZU_PERF_FANOUT=10 \
#   YUZU_PERF_CHURN_AGENTS=10 YUZU_PERF_CHURN_CYCLES=1 \
#   YUZU_PERF_ENDURANCE_AGENTS=10 YUZU_PERF_ENDURANCE_SECS=1 ./test_runner.sh ct
# The full-sizing run is tracked in #4821.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Ensure rebar3 is available
if ! command -v rebar3 &>/dev/null; then
    echo "ERROR: rebar3 not found in PATH"
    exit 1
fi
# The verdict comes from the shared summary parser, not rebar3's exit code.
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found in PATH (needed for the summary parser)"
    exit 1
fi
SUMMARY_PARSER="$SCRIPT_DIR/../scripts/gateway_test_summary.py"

# gated MODE LABEL CMD...  Run CMD, show its output, then judge the run with
# scripts/gateway_test_summary.py instead of trusting rebar3's exit code,
# which is 0 when nothing ran (#4800: a ct run with no suites printed
# "All 0 tests passed." and exited 0). MODE is `cancel-tolerant` (eunit: a
# non-zero exit with "Failed: 0" and tests executed is tolerated, #1005, the
# same rule as scripts/test/eunit-gate.sh) or `strict` (ct: rebar3's own
# non-zero exit stays a failure, and a green exit must have executed >= 1
# test). Returns the verdict's exit code. Pinned by
# tests/test_gateway_test_summary.py.
gated() {
    local mode="$1" label="$2" capture rebar_rc verdict
    shift 2
    capture=$(mktemp "${TMPDIR:-/tmp}/yuzu_test_gateway_${label}.XXXXXX") || return 2
    set +e
    "$@" 2>&1 | tee "$capture"
    rebar_rc=${PIPESTATUS[0]}
    if [[ "$mode" == "strict" ]]; then
        python3 "$SUMMARY_PARSER" strict "$label" "$rebar_rc" "$capture"
    else
        python3 "$SUMMARY_PARSER" "$mode" "$rebar_rc" "$capture"
    fi
    verdict=$?
    set -e
    rm -f "$capture"
    return "$verdict"
}

# Default: run both
RUN_EUNIT=true
RUN_CT=true
RUN_COVER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        eunit)
            RUN_CT=false
            shift
            ;;
        ct)
            RUN_EUNIT=false
            shift
            ;;
        cover)
            RUN_COVER=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [eunit|ct|cover]"
            echo ""
            echo "  eunit  — Run only EUnit tests"
            echo "  ct     — Run only Common Test suites"
            echo "  cover  — Enable coverage reporting"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Compile first
log "Compiling..."
rebar3 compile

FAILURES=0

# Run EUnit tests. In `do`, the comma that ends a task's args must be followed
# by the next task as its OWN word (`--dir X, cover`); `--dir X,cover` is read
# as a single --dir value and the cover task never runs.
if $RUN_EUNIT; then
    log "Running EUnit tests..."
    if $RUN_COVER; then
        gated cancel-tolerant eunit rebar3 as test do eunit --dir apps/yuzu_gw/test, cover || FAILURES=$((FAILURES + 1))
    else
        gated cancel-tolerant eunit rebar3 as test eunit --dir apps/yuzu_gw/test || FAILURES=$((FAILURES + 1))
    fi
fi

# Run Common Test suites. They live in apps/yuzu_gw/test/ct/ and ct does not
# recurse: without this --dir, rebar3 discovers zero suites, prints
# "All 0 tests passed." and exits 0, and this script would report ALL TESTS
# PASSED having run nothing (#4800).
if $RUN_CT; then
    log "Running Common Test suites..."
    if $RUN_COVER; then
        gated strict ct rebar3 as test do ct --dir apps/yuzu_gw/test/ct, cover || FAILURES=$((FAILURES + 1))
    else
        gated strict ct rebar3 as test ct --dir apps/yuzu_gw/test/ct || FAILURES=$((FAILURES + 1))
    fi
fi

# Summary
echo ""
log "═══════════════════════════════════════════"
if [[ $FAILURES -eq 0 ]]; then
    log "  ALL TESTS PASSED"
else
    log "  SOME TESTS FAILED"
fi
log "═══════════════════════════════════════════"

exit $FAILURES
