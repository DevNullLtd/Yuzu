#!/usr/bin/env bash
# run-tests.sh — Orchestrate all Yuzu test suites
#
# Usage:
#   ./scripts/run-tests.sh                    # Run all test tiers
#   ./scripts/run-tests.sh checks             # Static checks only (hookify rules)
#   ./scripts/run-tests.sh unit               # C++ unit tests only
#   ./scripts/run-tests.sh agent-shutdown     # Agent graceful-shutdown smoke (SIGTERM)
#   ./scripts/run-tests.sh erlang-unit        # Erlang EUnit tests only
#   ./scripts/run-tests.sh erlang-ct          # Erlang Common Test suites only
#   ./scripts/run-tests.sh erlang-perf        # Erlang performance tests only
#   ./scripts/run-tests.sh integration        # Full-stack integration tests
#   ./scripts/run-tests.sh all                # Everything (same as no args)
#
# Not run here: scripts/test/agent-unit-capcheck.sh is CI-only (needs systemd as PID 1 and root), see ci.yml.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Per-OS canonical build dir (see CLAUDE.md "Per-OS build directory convention").
# Override with YUZU_BUILDDIR=path if you maintain a non-standard layout.
if [[ -n "${YUZU_BUILDDIR:-}" ]]; then
    BUILDDIR="$YUZU_BUILDDIR"
elif [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
    BUILDDIR="$PROJECT_ROOT/build-windows"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    BUILDDIR="$PROJECT_ROOT/build-macos"
else
    BUILDDIR="$PROJECT_ROOT/build-linux"
fi
GATEWAY_DIR="$PROJECT_ROOT/gateway"
TIER="${1:-all}"

PASS=0
FAIL=0
SKIP=0

banner() { echo ""; echo "══════════════════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════════════════"; }
pass()   { PASS=$((PASS + 1)); echo "  ✓ $1"; }
fail()   { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }
skip()   { SKIP=$((SKIP + 1)); echo "  ⊘ $1 (skipped)"; }

# Native server targets are available only on Linux (ADR-0035).
server_supported() { [[ "$(uname -s)" == "Linux" ]]; }

# Resolve a working Python 3 once, on first use, into $YUZU_RUN_PYTHON: try
# `python3`, then `python`, and keep the first that actually runs. A Windows
# runner has no `python3`, or only the Store stub, which exists but fails to
# run, so a lookup by name alone is not enough. Returns 1 with a loud error
# when neither works; the calling tier then fails rather than skipping.
YUZU_RUN_PYTHON=""
resolve_python() {
    [[ -n "$YUZU_RUN_PYTHON" ]] && return 0
    local candidate
    for candidate in python3 python; do
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' >/dev/null 2>&1; then
            YUZU_RUN_PYTHON="$candidate"
            return 0
        fi
    done
    echo "  ERROR: no working Python 3 interpreter (tried python3, python)" >&2
    return 1
}

# ── Tier 1: C++ Unit Tests ──────────────────────────────────────────
run_checks() {
    banner "STATIC CHECKS"
    echo "  Validating hookify guardrail rules..."
    if resolve_python && "$YUZU_RUN_PYTHON" "$PROJECT_ROOT/scripts/check-hookify-rules.py"; then
        pass "hookify rules valid"
    else
        fail "hookify rules invalid"
    fi
}

run_cpp_unit() {
    banner "C++ UNIT TESTS (Catch2)"

    if [[ ! -d "$BUILDDIR" ]]; then
        fail "Build directory not found at $BUILDDIR. Run: ./scripts/setup.sh --tests"
        return
    fi

    # Compile tests
    echo "  Building test executables..."
    local targets=(yuzu_agent_tests)
    if server_supported; then
        targets+=(yuzu_server_tests)
    fi
    if ! meson compile -C "$BUILDDIR" "${targets[@]}" 2>&1 | tail -5; then
        fail "C++ test compilation failed"
        return
    fi

    # Bind fixture discovery to this build, including when the caller exports
    # MESON_BUILD_ROOT for an unrelated checkout.
    # Run agent tests
    echo ""
    echo "  Running agent unit tests..."
    if MESON_BUILD_ROOT="$BUILDDIR" "$BUILDDIR/tests/yuzu_agent_tests" --reporter compact 2>&1; then
        pass "Agent unit tests"
    else
        fail "Agent unit tests"
    fi

    # Run server tests
    if ! server_supported; then
        skip "Server unit tests (native server is Linux-only, ADR-0035)"
        return
    fi
    echo ""
    echo "  Running server unit tests..."
    if MESON_BUILD_ROOT="$BUILDDIR" "$BUILDDIR/tests/yuzu_server_tests" --reporter compact 2>&1; then
        pass "Server unit tests"
    else
        fail "Server unit tests"
    fi
}

# ── Agent graceful shutdown (process-level; the Catch2 suite never drives main()) ──
run_agent_shutdown() {
    banner "AGENT GRACEFUL SHUTDOWN (SIGTERM)"

    # POSIX only: the script drives real signals. Windows keeps the direct-call handler and has
    # no equivalent coverage — tracked separately.
    if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* || "$(uname -s)" == CYGWIN* ]]; then
        skip "Agent shutdown smoke (POSIX only)"
        return
    fi

    # DARWIN: SKIPPED, DELIBERATELY, AND THIS IS THE HONEST POSTURE.
    # The script is written to be portable (it probes with ss/lsof/netstat, strips BSD's full-path
    # `ps -o comm=`, and templates every mktemp) — but NO CI leg has ever executed it on macOS, and
    # docs/darwin-compat.md MANDATES `run-tests.sh all` after any cross-platform change. That made
    # every Mac contributor the first person ever to run it, on an unvalidated path, while the
    # output implied it was vetted. Skip it here and wire it into the macOS CI leg as a follow-up (.spark-issues/governance-followups.md item 20, pending an issue number):
    # "mandated but never validated" is the worst of the three options.
    # (governance: build-ci, quality-engineer, cross-platform.)
    if [[ "$(uname -s)" == "Darwin" ]]; then
        skip "Agent shutdown smoke (unvalidated on macOS — not yet wired into the macOS CI leg)"
        return
    fi

    local agent="$BUILDDIR/agents/core/yuzu-agent"
    if [[ ! -x "$agent" ]]; then
        skip "Agent shutdown smoke (agent binary not built)"
        return
    fi

    if YUZU_AGENT_BIN="$agent" YUZU_PLUGIN_DIR="$BUILDDIR/agents/plugins" \
        bash "$(dirname "$0")/test/agent-shutdown-smoke.sh"; then
        pass "Agent graceful shutdown"
    else
        fail "Agent graceful shutdown"
    fi
}

# ── Tier 2: Erlang EUnit Tests ──────────────────────────────────────
run_erlang_unit() {
    banner "ERLANG EUNIT TESTS"

    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi

    echo "  Running EUnit tests..."
    # eunit-gate.sh requires successful process exit and a nonempty passing
    # summary. Cancellation means incomplete execution and fails this gate,
    # even when all cases that actually ran passed.
    if bash "$PROJECT_ROOT/scripts/test/eunit-gate.sh" 2>&1 | tail -20; then
        pass "Erlang EUnit tests"
    else
        fail "Erlang EUnit tests"
    fi
    cd "$PROJECT_ROOT"
}

# A successful rebar exit alone does not establish that CT executed anything.
# Keep a unique full transcript on failure; judge the entire capture before
# displaying its tail so diagnostics cannot become the execution evidence.
run_ct_suite() {
    local label="$1" suite="$2" capture rc
    shift 2
    if ! capture=$(mktemp "${TMPDIR:-/tmp}/yuzu_test_ct_gate.XXXXXX"); then
        fail "$label (cannot capture output)"
        return
    fi
    if (cd "$GATEWAY_DIR" && rebar3 ct --dir apps/yuzu_gw/test/ct --suite="$suite" "$@") >"$capture" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    tail -10 "$capture"
    if resolve_python && "$YUZU_RUN_PYTHON" "$SCRIPT_DIR/gateway_test_summary.py" strict "$suite" "$rc" "$capture"; then
        rm -f "$capture"
        pass "$label"
    else
        echo "  Full Common Test output: $capture"
        fail "$label"
    fi
}

# ── Tier 3: Erlang Common Test Suites ───────────────────────────────
run_erlang_ct() {
    banner "ERLANG COMMON TEST SUITES"
    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi
    run_ct_suite "Gateway E2E suite" yuzu_gw_e2e_SUITE
    run_ct_suite "Gateway integration suite" yuzu_gw_integration_SUITE
    run_ct_suite "Gateway metrics E2E suite" yuzu_gw_metrics_e2e_SUITE
    run_ct_suite "Gateway Prometheus endpoint suite" yuzu_gw_prometheus_SUITE
}

# ── Tier 4: Erlang Performance Tests ───────────────────────────────
run_erlang_perf() {
    banner "ERLANG PERFORMANCE TESTS"
    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi
    echo "  Configure with: YUZU_PERF_AGENTS=N YUZU_PERF_HEARTBEATS=N"
    run_ct_suite "Gateway performance tests" yuzu_gw_perf_SUITE --verbose
}

# ── Tier 5: Full-Stack Integration Tests ────────────────────────────
run_integration() {
    banner "FULL-STACK INTEGRATION TESTS"

    if ! server_supported; then
        skip "Full-stack integration test (native server is Linux-only, ADR-0035)"
        return
    fi

    if [[ ! -x "$SCRIPT_DIR/integration-test.sh" ]]; then
        fail "integration-test.sh not found"
        return
    fi

    echo "  Running full-stack integration test (Agent → Gateway → Server)..."
    if "$SCRIPT_DIR/integration-test.sh" --agents 2 2>&1; then
        pass "Full-stack integration test"
    else
        fail "Full-stack integration test"
    fi
}

# ── Dispatch ────────────────────────────────────────────────────────
case "$TIER" in
    checks)        run_checks ;;
    unit)          run_cpp_unit ;;
    agent-shutdown) run_agent_shutdown ;;
    erlang-unit)   run_erlang_unit ;;
    erlang-ct)     run_erlang_ct ;;
    erlang-perf)   run_erlang_perf ;;
    integration)   run_integration ;;
    all)
        run_checks
        run_cpp_unit
        run_agent_shutdown
        run_erlang_unit
        run_erlang_ct
        run_integration
        # Perf tests are opt-in (slow)
        echo ""
        echo "  Note: Performance tests skipped by default."
        echo "  Run:  ./scripts/run-tests.sh erlang-perf"
        ;;
    *)
        echo "Unknown tier: $TIER"
        echo "Usage: $0 [checks|unit|erlang-unit|erlang-ct|erlang-perf|integration|all]"
        exit 1
        ;;
esac

# ── Summary ─────────────────────────────────────────────────────────
banner "TEST SUMMARY"
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo "  Total:   $TOTAL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "  RESULT: FAILED"
    exit 1
else
    echo "  RESULT: PASSED"
    exit 0
fi
