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

# ── Tier 1: C++ Unit Tests ──────────────────────────────────────────
run_checks() {
    banner "STATIC CHECKS"
    echo "  Validating hookify guardrail rules..."
    if python3 "$PROJECT_ROOT/scripts/check-hookify-rules.py"; then
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
    if ! meson compile -C "$BUILDDIR" yuzu_agent_tests yuzu_server_tests 2>&1 | tail -5; then
        fail "C++ test compilation failed"
        return
    fi

    # Run agent tests
    echo ""
    echo "  Running agent unit tests..."
    if "$BUILDDIR/tests/yuzu_agent_tests" --reporter compact 2>&1; then
        pass "Agent unit tests"
    else
        fail "Agent unit tests"
    fi

    # Run server tests
    echo ""
    echo "  Running server unit tests..."
    if "$BUILDDIR/tests/yuzu_server_tests" --reporter compact 2>&1; then
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
    # eunit-gate.sh wraps rebar3 eunit so the script's exit code reflects
    # the EUnit summary (Failed: N), not rebar3's process-exit-on-cancel
    # behavior. Cancellations come from EUnit discovering non-test helper
    # modules and from order-dependent registry_tests flakes — they're
    # not regressions worth gating on. See scripts/test/eunit-gate.sh for
    # the full rationale (#1005).
    if bash "$PROJECT_ROOT/scripts/test/eunit-gate.sh" 2>&1 | tail -20; then
        pass "Erlang EUnit tests"
    else
        fail "Erlang EUnit tests"
    fi
    cd "$PROJECT_ROOT"
}

# ── Tier 3: Erlang Common Test Suites ───────────────────────────────
run_erlang_ct() {
    banner "ERLANG COMMON TEST SUITES"

    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi

    cd "$GATEWAY_DIR"

    # #1005: CT *_SUITE.erl files live in test/ct/ (separate from
    # *_tests.erl in test/) so EUnit's dir-scan no longer discovers
    # them and emits "tests were cancelled" trailers that fail the gate.
    CT_DIR="apps/yuzu_gw/test/ct"

    # E2E suite
    echo "  Running e2e suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_e2e_SUITE 2>&1 | tail -10; then
        pass "Gateway E2E suite"
    else
        fail "Gateway E2E suite"
    fi

    # Integration suite
    echo ""
    echo "  Running integration suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_integration_SUITE 2>&1 | tail -10; then
        pass "Gateway integration suite"
    else
        fail "Gateway integration suite"
    fi

    # Metrics E2E suite
    echo ""
    echo "  Running metrics E2E suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_metrics_e2e_SUITE 2>&1 | tail -10; then
        pass "Gateway metrics E2E suite"
    else
        fail "Gateway metrics E2E suite"
    fi

    # Prometheus endpoint suite
    echo ""
    echo "  Running Prometheus endpoint suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_prometheus_SUITE 2>&1 | tail -10; then
        pass "Gateway Prometheus endpoint suite"
    else
        fail "Gateway Prometheus endpoint suite"
    fi

    cd "$PROJECT_ROOT"
}

# ── Tier 4: Erlang Performance Tests ───────────────────────────────
run_erlang_perf() {
    banner "ERLANG PERFORMANCE TESTS"

    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi

    cd "$GATEWAY_DIR"
    echo "  Running performance suite (this may take several minutes)..."
    echo "  Configure with: YUZU_PERF_AGENTS=N YUZU_PERF_HEARTBEATS=N"
    if rebar3 ct --suite=yuzu_gw_perf_SUITE --verbose 2>&1 | tail -30; then
        pass "Gateway performance tests"
    else
        fail "Gateway performance tests"
    fi
    cd "$PROJECT_ROOT"
}

# ── Tier 5: Full-Stack Integration Tests ────────────────────────────
run_integration() {
    banner "FULL-STACK INTEGRATION TESTS"

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
