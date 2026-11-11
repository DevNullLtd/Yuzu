#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp: the yuzu_fleet_plugin_init_failed label
catalogue stays wired.

AgentHealthStore labels a `yuzu.plugins_failed` token only when it is in the set handed to
set_known_plugins(); an unwired store fails CLOSED, so every real plugin would be summed under
plugin="unknown" and YuzuPluginInitFailed would fire only on that one series. The unit tests build
their own store, so nothing but this gate notices the one production line being dropped, moved
after the first sweep, or duplicated.

Required (comments stripped, whitespace/line-wrap tolerant):
  * `health_store_.set_known_plugins(catalogue_plugin_names(capability_registry_))` exists EXACTLY
    once, and the registry it reads is composed (declared) in the same file;
  * that statement precedes the start of health_recompute_thread_ (which itself starts at exactly
    one site) and every health_store_.recompute_metrics( call;
  * both metrics_.describe registrations (yuzu_fleet_plugin_init_failed and
    kPluginInitFailedRejectedGauge) exist.

Lexical only: it cannot see a statement that is present but in a branch that never runs
(review-enforced). The companion tests/test_plugin_init_failed_wiring_lexical_selftest.py deletes
each required statement in memory and requires the gate to name it.

Usage: python3 -I tests/test_plugin_init_failed_wiring_lexical.py
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SERVER_CPP = os.path.join("server", "core", "src", "server.cpp")
TAG = "test_plugin_init_failed_wiring_lexical"
HINT = (" (this gate pins the plugin-init-failed label catalogue wiring; if server.cpp was "
        "legitimately restructured, update tests/test_plugin_init_failed_wiring_lexical.py and its selftest)")

# The one comment-stripping, whitespace-collapsing scanner the other server.cpp wiring gates share.
_spec = importlib.util.spec_from_file_location(
    "forensics_tier_wiring_lexical", os.path.join(HERE, "test_forensics_tier_wiring_lexical.py"))
_forensics = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _forensics
_spec.loader.exec_module(_forensics)
canonical = _forensics.canonical

_WIRE = (r"health_store_\.set_known_plugins\((?:yuzu::server::)?catalogue_plugin_names\(capability_registry_\)\);")
_THREAD = r"health_recompute_thread_=std::thread\("
_RECOMPUTE = r"health_store_\.recompute_metrics\("

# (id, pattern with a named group `k` = the statement the selftest deletes, why)
REQUIRED: list[tuple[str, str, str]] = [
    ("wire-known-plugins", r"(?P<k>" + _WIRE + r")",
     "the catalogue plugin names must reach the health store, or every real plugin is labelled unknown"),
    ("registry-composed", r"(?P<k>CommandCapabilityRegistry capability_registry_\{YUZU_ALL_CAPABILITY_FRAGMENTS\};)",
     "the catalogue the names are derived from must be composed from every capability fragment"),
    ("wire-before-thread", r"(?P<k>" + _WIRE + r").*?" + _THREAD,
     "the set must be wired before the health recompute thread starts (its first sweep must see it)"),
    ("describe-init-failed", r"(?P<k>metrics_\.describe\(\"yuzu_fleet_plugin_init_failed\",)",
     "yuzu_fleet_plugin_init_failed needs its HELP/TYPE registration"),
    ("describe-rejected",
     r"(?P<k>metrics_\.describe\(yuzu::server::kPluginInitFailedRejectedGauge,"
     r"yuzu::server::kPluginInitFailedRejectedHelp,\"gauge\"\);)",
     "the rejected gauge needs its HELP/TYPE registration from the shared constants"),
]

# (id, pattern, exact count, why)
COUNTED: list[tuple[str, str, int, str]] = [
    ("wire-once", r"(?P<k>" + _WIRE + r")", 1,
     "set_known_plugins is called at exactly one site, once, at boot (a second call would race the sweep)"),
    ("anchor-thread", r"(?P<k>" + _THREAD + r")", 1,
     "the health recompute thread starts at exactly one site (wire-before-thread measures against it)"),
]


def problems_canonical(t: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for rid, pat, why in REQUIRED:
        if not re.search(pat, t, re.S):
            out.append((rid, f"{rid}: {why}"))
    for rid, pat, want, why in COUNTED:
        got = len(re.findall(pat, t, re.S))
        if got != want:
            out.append((rid, f"{rid}: expected exactly {want} occurrences, found {got}: {why}"))
    wire = re.search(_WIRE, t)
    first_sweep = re.search(_RECOMPUTE, t)
    if wire and first_sweep and first_sweep.start() < wire.start():
        out.append(("wire-before-sweep", "wire-before-sweep: a recompute_metrics call precedes the set_known_plugins "
                    "statement; a sweep must never run on an unwired store"))
    return out


def problems(src: str) -> list[tuple[str, str]]:
    return problems_canonical(canonical(src))


def main() -> int:
    try:
        with open(os.path.join(REPO_ROOT, SERVER_CPP), encoding="utf-8") as fh:
            src = fh.read()
    except OSError as e:
        print(f"::error::{TAG}: cannot read {SERVER_CPP}: {e}", file=sys.stderr)
        return 1
    found = problems(src)
    for _rid, msg in found:
        print(f"::error::{TAG}: {SERVER_CPP}: {msg}{HINT}", file=sys.stderr)
    if found:
        return 1
    print(f"OK: {len(REQUIRED)} wiring statements, {len(COUNTED)} counted sites, 1 ordering pin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
