#!/usr/bin/env bash
# check-gateway-eunit-order.sh -- run the gateway eunit suite with its modules
# in REVERSE alphabetical order and fail if anything fails (#1197).
#
# Why: the eunit modules share one VM, and `rebar3 eunit --dir ...` runs them in
# directory-listing order, which differs per filesystem (ext4 hash order,
# APFS/NTFS name order). A module that leaves state behind (a process joined to
# the VM-wide pg group {yuzu_gw, all_agents}, a meck mock, a logger filter, an
# application env key) is harmless when the listing happens to put it last and
# breaks a later module when it does not. The ordinary run, `scripts/test_gateway.py
# gateway eunit`, only ever sees the order of the host it runs on; this script
# runs the opposite of the alphabetical order, so a leak that the usual order
# hides is exposed. A cancelled test shows up as exit status 1 ("One or more tests
# were cancelled") even with zero failures.
#
# What it does: lists apps/yuzu_gw/test/*_tests.erl, sorts the module names in
# reverse, and runs `rebar3 eunit --module=<comma list>` once in its own build
# directory (gateway/_build_eunit_order, so it never disturbs the _build or
# _build_eunit trees of the other gateway suites).
#
# Usage:   scripts/ci/check-gateway-eunit-order.sh [--keep]
#            --keep   keep the scratch build directory (default: remove it)
# Exit:    0 all tests passed in reverse order, 1 a test failed or was cancelled,
#          2 the Erlang toolchain or the test directory is missing.
# Portable: bash 3.2 and BSD userland (macOS): no mapfile, no GNU-only flags.
#
# NOT wired into any workflow yet: the owner decides where it runs.

set -u

keep=0
for arg in "$@"; do
    case "$arg" in
        --keep) keep=1 ;;
        *) echo "usage: $0 [--keep]" >&2; exit 2 ;;
    esac
done

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
gw="$repo/gateway"
testdir="$gw/apps/yuzu_gw/test"

if [ ! -d "$testdir" ]; then
    echo "check-gateway-eunit-order: no test directory at $testdir" >&2
    exit 2
fi

# Put erl/rebar3 on PATH when they are not already there (the helper is a no-op
# otherwise and always returns 0, so check afterwards).
if ! command -v erl >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    . "$repo/scripts/ensure-erlang.sh" >/dev/null 2>&1
fi
if ! command -v erl >/dev/null 2>&1 || ! command -v rebar3 >/dev/null 2>&1; then
    echo "check-gateway-eunit-order: erl and rebar3 must be on PATH" >&2
    exit 2
fi

# The comma list, reverse alphabetical. `LC_ALL=C` keeps the order stable across
# locales; `paste -s -d,` is the portable way to join (BSD and GNU).
modules="$(cd "$testdir" && ls ./*_tests.erl | sed -e 's|^\./||' -e 's|\.erl$||' \
    | LC_ALL=C sort -r | paste -s -d, -)"
if [ -z "$modules" ]; then
    echo "check-gateway-eunit-order: no *_tests.erl modules found" >&2
    exit 2
fi
count="$(printf '%s\n' "$modules" | tr ',' '\n' | wc -l | tr -d ' ')"
echo "check-gateway-eunit-order: $count modules, reverse alphabetical order"

export REBAR_BASE_DIR="$gw/_build_eunit_order"
export YUZU_REQUIRE_TLS_TESTS="${YUZU_REQUIRE_TLS_TESTS:-1}"
rm -rf "$REBAR_BASE_DIR"

cd "$gw" || exit 2
rebar3 eunit --module="$modules"
rc=$?

if [ "$keep" -eq 0 ]; then
    rm -rf "$REBAR_BASE_DIR"
fi

if [ "$rc" -ne 0 ]; then
    echo "check-gateway-eunit-order: FAILED (rebar3 exit $rc): some module depends" \
         "on the order the suite runs in" >&2
    exit 1
fi
echo "check-gateway-eunit-order: ok"
exit 0
