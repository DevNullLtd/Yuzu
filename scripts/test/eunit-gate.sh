#!/usr/bin/env bash
# eunit-gate.sh — run EUnit with the same strict verdict as Meson.
#
# A partially cancelled set is incomplete execution, even if every test that
# ran passed. The former #1005 tolerance hid setup/time-out failures; retain
# rebar3's nonzero status and require a nonempty successful summary (#4800).
#
# Usage:
#   bash scripts/test/eunit-gate.sh [extra rebar3 args...]
#
# The wrapper sets REBAR_BASE_DIR for parallel-safety per the SKILL.md
# convention and cd's into gateway/. Pass-through args go to rebar3 eunit
# (e.g. --module=foo,bar) — default is `--dir apps/yuzu_gw/test`.
#
# Exit codes:
#   0 — EUnit completed successfully and >= 1 test executed
#   nonzero — child failure/cancellation, invalid/empty summary, or setup error

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

# One strict parser across Meson, /test, the local runner and release.
python3 "$REPO_ROOT/scripts/gateway_test_summary.py" strict eunit "$rebar3_rc" "$capture"
