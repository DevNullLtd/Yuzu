#!/usr/bin/env python3
"""Self-test for tests/test_forensics_tier_wiring_lexical.py (#4990).

A gate that has never been seen to fail proves nothing. This runs the gate against in-memory
mutations of the real server/core/src/server.cpp (nothing on disk is touched):

  * for EVERY required wiring statement, delete its key text and require the gate to name exactly
    that requirement (so a stale or over-broad pattern fails loudly instead of passing vacuously);
  * for each counted site, delete the first occurrence and require the count check to fire;
  * for each forbidden hatch, append a spelling of it and require the gate to flag it;
  * move a registration-order setter after its register_routes call and require the gate to flag
    the order for REST v1, the dashboard and the workflow routes;
  * a comment that merely mentions a required token must not satisfy a requirement, and a string
    literal containing a comment opener must not hide a real statement.

Stdlib only.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "forensics_tier_wiring_lexical", os.path.join(HERE, "test_forensics_tier_wiring_lexical.py"))
g = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = g
spec.loader.exec_module(g)

FAILURES: list[str] = []


def expect(cond: bool, what: str) -> None:
    if not cond:
        FAILURES.append(what)
        print(f"FAIL: {what}", file=sys.stderr)


def ids(found: list[tuple[str, str]]) -> set[str]:
    return {rid for rid, _ in found}


def main() -> int:
    with open(os.path.join(g.REPO_ROOT, g.SERVER_CPP), encoding="utf-8") as fh:
        raw = fh.read()
    t = g.canonical(raw)

    expect(g.problems_canonical(t) == [], "the real server.cpp must pass the gate")
    expect(len(g.REQUIRED) >= 28, "the required-statement list must not shrink silently")

    # Delete each required statement's key text.
    for rid, pat, _why in g.REQUIRED:
        m = re.search(pat, t, re.S)
        if not m:
            expect(False, f"{rid}: pattern no longer matches the real source (stale pattern)")
            continue
        a, b = m.span("k")
        mutated = t[:a] + t[b:]
        found = ids(g.problems_canonical(mutated))
        expect(rid in found, f"{rid}: deleting its statement was NOT detected")

    # Counted sites: delete the first occurrence.
    for rid, pat, want, _why in g.COUNTED:
        ms = list(re.finditer(pat, t, re.S))
        expect(len(ms) >= want, f"{rid}: real source has fewer than {want} sites")
        if ms:
            a, b = ms[0].span("k")
            mutated = t[:a] + "(void)0" + t[b:]
            expect(rid in ids(g.problems_canonical(mutated)),
                   f"{rid}: deleting one counted site was NOT detected")

    # Forbidden hatches.
    hatches = {
        "null-set-setter": "rest_api_v1_->set_forensics_plugin_set(nullptr);",
        "null-set-field": "wf_deps.forensics_plugins = nullptr;; .forensics_plugins = nullptr,",
        "null-fixed-poll": "auto tier = ResponseTierFilter::for_fixed_plugin_poll(nullptr);",
    }
    for rid, spelling in hatches.items():
        mutated = g.canonical(raw + "\n" + spelling + "\n")
        expect(rid in ids(g.problems_canonical(mutated)), f"{rid}: hatch spelling was NOT detected")
    expect({r for r, _, _ in g.FORBIDDEN} == set(hatches), "every forbidden hatch has a selftest spelling")

    # Registration-order: move the setter text after its register_routes call.
    for rid, reg in (("rest-set", "rest_api_v1_->register_routes("),
                     ("rest-fn", "rest_api_v1_->register_routes("),
                     ("dashboard-set", "dashboard_routes_->register_routes("),
                     ("dashboard-fn", "dashboard_routes_->register_routes("),
                     ("workflow-set", "workflow_routes_->register_routes("),
                     ("workflow-fn", "workflow_routes_->register_routes(")):
        pat = next(p for r, p, _ in g.REQUIRED if r == rid)
        m = re.search(pat, t, re.S)
        a, b = m.span("k")
        stmt = t[a:b]
        without = t[:a] + t[b:]
        # Put the statement after the LAST occurrence of the register call so none follows it.
        last = without.rfind(reg)
        expect(last >= 0, f"{rid}: register call not found in the real source")
        # Everything after the last register call must not contain another one, so the moved
        # statement has no register call after it.
        moved = without[:last] + without[last:] + stmt
        expect(rid in ids(g.problems_canonical(moved)),
               f"{rid}: a setter placed after the matching register_routes was NOT detected")

    # A comment that mentions a required token must not satisfy a requirement.
    needle = "agent_service_.set_forensics_plugin_set(forensics_plugins());"
    expect(needle in raw, "selftest anchor moved: update the selftest")
    commented = raw.replace(needle, "// " + needle, 1)
    expect("agent-service-set" in ids(g.problems(commented)),
           "a commented-out statement must not satisfy its requirement")

    # A string literal holding a comment opener must not hide a real statement after it.
    hidden = raw.replace(needle, 'static const char* kUrl = "http://x/*"; ' + needle, 1)
    expect("agent-service-set" not in ids(g.problems(hidden)),
           "a string literal containing a comment opener must not hide a real statement")

    if FAILURES:
        print(f"{len(FAILURES)} selftest failure(s)", file=sys.stderr)
        return 1
    print(f"OK: {len(g.REQUIRED)} deletions, {len(g.COUNTED)} counted, {len(g.FORBIDDEN)} hatches, "
          f"6 order and 2 comment/literal mutations all caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
