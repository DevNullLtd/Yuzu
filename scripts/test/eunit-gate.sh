#!/usr/bin/env bash
# eunit-gate.sh — wrap rebar3 eunit so the gate distinguishes "actual test
# failure" from "rebar3 returns 1 because EUnit emitted 'One or more tests
# were cancelled'".
#
# Background (#1005): rebar3 eunit reports cancellations as a process-exit
# error even when every test that ran passed. Cancellations have multiple
# causes:
#   * EUnit's --dir discovery encounters a non-test module like
#     `yuzu_gw_perf_helpers` (no test_/0 exports).
#   * A flake (registry_tests gen_server timeout under VM pollution) aborts
#     a test set partway through.
# Neither case is a regression we want to block a `/test` run on. This
# wrapper exits 0 iff EUnit's summary line says `Failed: 0` AND at least one
# test EXECUTED. Real failures (Failed: N > 0), infrastructure errors (no
# summary line) and zero-executed runs propagate as non-zero. The executed
# check matters because a set-up that crashes in EVERY module prints
# `Failed: 0.  Skipped: 0.  Passed: 0.` plus "One or more tests were
# cancelled" -- an all-cancelled run that would otherwise read as a pass
# (the #4800 false-green class; scripts/test_gateway.py applies the same rule
# via scripts/gateway_test_summary.py).
#
# Usage:
#   bash scripts/test/eunit-gate.sh [extra rebar3 args...]
#
# The wrapper sets REBAR_BASE_DIR for parallel-safety per the SKILL.md
# convention and cd's into gateway/. Pass-through args go to rebar3 eunit
# (e.g. --module=foo,bar) — default is `--dir apps/yuzu_gw/test`.
#
# Exit codes:
#   0 — EUnit ran, Failed: 0, and >= 1 test executed (passed, even if some
#       sets were cancelled)
#   1 — EUnit ran and Failed: >0, OR no summary line found, OR 0 tests
#       executed (real failure)
#   2 — toolchain or invocation error (rebar3 or python3 missing, gateway/
#       missing, capture file unreadable)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || { echo "eunit-gate: cannot cd to repo root" >&2; exit 2; }

if [[ ! -d gateway ]]; then
    echo "eunit-gate: gateway/ not found at $REPO_ROOT/gateway" >&2
    exit 2
fi

cd gateway

# Source the Erlang toolchain helper when present (sources are no-ops if
# `erl` is already on PATH). Failures here are surfaced by the rebar3
# command's missing-binary error message rather than swallowed.
if [[ -f ../scripts/ensure-erlang.sh ]]; then
    # shellcheck disable=SC1091
    source ../scripts/ensure-erlang.sh 2>/dev/null || true
fi

if ! command -v rebar3 >/dev/null 2>&1; then
    echo "eunit-gate: rebar3 not on PATH" >&2
    exit 2
fi
# Checked up front so a missing parser fails before minutes of tests run.
# `python3` only: this gate runs from /test and scripts/run-tests.sh on
# Linux/macOS hosts, never on a Windows runner (Windows CI steps call
# `python`; no workflow invokes this script).
if ! command -v python3 >/dev/null 2>&1; then
    echo "eunit-gate: python3 not on PATH (needed for the summary parser)" >&2
    exit 2
fi

# Default args mirror the /test SKILL.md invocation. Callers can append
# their own — e.g. `--module=foo,bar` — by passing them as positional
# arguments to this wrapper.
if [[ $# -eq 0 ]]; then
    set -- --dir apps/yuzu_gw/test
fi

# Per-run capture file: the verdict below is parsed from it, so a fixed path
# would let two overlapping runs on one host (#1871) interleave and one read
# the other's summary.
capture=$(mktemp "${TMPDIR:-/tmp}/yuzu_test_eunit_gate.XXXXXX") \
    || { echo "eunit-gate: mktemp failed" >&2; exit 2; }
trap 'rm -f "$capture"' EXIT

REBAR_BASE_DIR="${REBAR_BASE_DIR:-$PWD/_build_eunit}" \
    rebar3 eunit "$@" 2>&1 | tee "$capture"
rebar3_rc=${PIPESTATUS[0]}

# The verdict comes from the same summary PARSER the Meson wrapper uses
# (scripts/gateway_test_summary.py, pinned by tests/test_gateway_test_summary.py):
# whole-line summary matching, the LAST summary wins, and >= 1 test must have
# EXECUTED (#4800). Unlike the Meson gate, this gate (like the release
# workflow's) tolerates a non-zero rebar3 exit when eunit's "Failed: 0" line
# shows tests passed (cancelled sets, #1005); the Meson gate stays strict.
python3 "$REPO_ROOT/scripts/gateway_test_summary.py" cancel-tolerant "$rebar3_rc" "$capture"
