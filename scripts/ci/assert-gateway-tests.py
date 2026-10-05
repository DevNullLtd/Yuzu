#!/usr/bin/env python3
"""Fail a CI leg whose Meson configure did not register the gateway tests.

meson.build builds the Erlang gateway and registers `gateway eunit` /
`gateway ct` only when `find_program('rebar3', required: false)` succeeds.
Otherwise it skips them silently and the leg stays green with no gateway
built or tested: the macOS leg ran that way from the start (#4841), and a
runner that loses Erlang would do the same.

This check runs right after `meson setup` and reads the test list Meson just
wrote (`<builddir>/meson-info/intro-tests.json`). It deliberately does NOT
use the `-Drequire_gateway=true` project option. CI build dirs persist and are
shared across branches, and a non-default project option stored in such a dir
breaks every later `meson setup --reconfigure` from a branch whose
meson.options predates it ("Unknown options"). The option stays available for
local fresh setups. Pinned by tests/test_gateway_test_summary.py.

Usage: assert-gateway-tests.py BUILDDIR
Exit: 0 both tests registered; 1 missing (a ::error:: line is printed); 2 usage.
"""
import json
import os
import sys

REQUIRED = ("gateway eunit", "gateway ct")


def missing_tests(intro_tests):
    """Names in REQUIRED that the introspected test list lacks."""
    names = {t.get("name") for t in intro_tests if isinstance(t, dict)}
    return [n for n in REQUIRED if n not in names]


def main(argv):
    if len(argv) != 1:
        print("usage: assert-gateway-tests.py BUILDDIR", file=sys.stderr)
        return 2
    path = os.path.join(argv[0], "meson-info", "intro-tests.json")
    try:
        with open(path, encoding="utf-8") as f:
            tests = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"::error::cannot read {path}: {exc}")
        return 1
    missing = missing_tests(tests)
    if missing:
        print("::error::Meson did not register " + ", ".join(repr(n) for n in missing)
              + " -- rebar3 (Erlang/OTP 28) was not found at configure time, so the "
              "gateway would be silently skipped on this leg (#4841). Provision "
              "Erlang on this runner (CI: erlef/setup-beam).")
        return 1
    print(f"assert-gateway-tests: {', '.join(REQUIRED)} registered.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
