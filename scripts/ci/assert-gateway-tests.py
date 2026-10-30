#!/usr/bin/env python3
"""Fail a CI leg whose Meson configure did not register the gateway tests.

meson.build builds the Erlang gateway and registers the `gateway eunit
shard <X>` tests and `gateway ct` only when rebar3 is found AND an Erlang/OTP passing the pin
(scripts/erlang_toolchain.py, 28.4 or any later 28.x) is resolved. Otherwise
it skips them and the leg stays green with no gateway built or tested: the
macOS leg ran that way from the start (#4841), and a runner that loses Erlang
- or moves to an OTP outside the pin - would do the same.

This check runs right after `meson setup` and reads the test list Meson just
wrote (`<builddir>/meson-info/intro-tests.json`). It deliberately does NOT
use the `-Drequire_gateway=true` project option. CI build dirs persist and are
shared across branches, and a non-default project option stored in such a dir
breaks every later `meson setup --reconfigure` from a branch whose
meson.options predates it ("Unknown options"). The option stays available for
local fresh setups. Pinned by tests/test_gateway_test_summary.py.

Usage: assert-gateway-tests.py BUILDDIR
Exit: 0 every test registered; 1 missing (a ::error:: line is printed); 2 usage.
"""
import json
import os
import sys

# The eunit shard names track root meson.build's `_gw_eunit_shards`; adding a
# shard there means adding its name here (tests/test_gateway_eunit_shards.py
# fails until the two agree).
REQUIRED = ("gateway eunit shard A", "gateway eunit shard B", "gateway ct")


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
              + " -- at configure time either rebar3 was not found or no Erlang/OTP "
              "passed the pin (28.4 or any later 28.x), so the gateway would be skipped "
              "on this leg (#4841). The configure log's 'Erlang gateway: SKIPPED' "
              "warning lists every install inspected. Provision a matching Erlang on "
              "this runner (CI: see this leg's Erlang install step in ci.yml).")
        return 1
    print(f"assert-gateway-tests: {', '.join(REQUIRED)} registered.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
