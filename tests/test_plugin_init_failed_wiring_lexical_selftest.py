#!/usr/bin/env python3
"""Self-test for tests/test_plugin_init_failed_wiring_lexical.py.

Runs the gate against in-memory mutations of the real server/core/src/server.cpp (nothing on disk
is touched): deleting each required statement must be named; a second wiring call, a second thread
start, a wiring moved after the thread, and a recompute call ahead of the wiring must be flagged; a
comment that merely mentions the wiring must not satisfy the gate. Stdlib only.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "plugin_init_failed_wiring_lexical", os.path.join(HERE, "test_plugin_init_failed_wiring_lexical.py"))
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

    for rid, pat, _why in g.REQUIRED:
        m = re.search(pat, t, re.S)
        if not m:
            expect(False, f"{rid}: pattern no longer matches the real source (stale pattern)")
            continue
        a, b = m.span("k")
        expect(rid in ids(g.problems_canonical(t[:a] + t[b:])), f"{rid}: deleting its statement was NOT detected")

    wire = re.search(g._WIRE, t)
    thread = re.search(g._THREAD, t)
    expect(bool(wire and thread), "wiring and thread anchors must exist in the real source")
    if wire and thread:
        stmt = wire.group(0)
        expect("wire-once" in ids(g.problems_canonical(t + stmt)), "a duplicated wiring call was NOT detected")
        expect("anchor-thread" in ids(g.problems_canonical(t + "health_recompute_thread_=std::thread(")),
               "a second thread start was NOT detected")
        moved = t[:wire.start()] + t[wire.end():thread.end()] + stmt + t[thread.end():]
        expect("wire-before-thread" in ids(g.problems_canonical(moved)),
               "a wiring moved after the thread start was NOT detected")
        early = t[:wire.start()] + "health_store_.recompute_metrics(metrics_,w);" + t[wire.start():]
        expect("wire-before-sweep" in ids(g.problems_canonical(early)),
               "a recompute call ahead of the wiring was NOT detected")

    # A comment mentioning the wiring must not satisfy the gate; a string literal must not hide it.
    commented = re.sub(r"(?s)health_store_\s*\.\s*set_known_plugins\s*\(.*?\)\s*\)\s*;", lambda m: "// " + m.group(0).replace("\n", "\n// "), raw, count=1)
    expect("wire-known-plugins" in ids(g.problems(commented)), "a commented-out wiring satisfied the gate")
    hidden = raw.replace("health_store_.set_known_plugins(", 'const char* s = "/*"; health_store_.set_known_plugins(', 1)
    expect("wire-known-plugins" not in ids(g.problems(hidden)), "a string literal hid the real wiring statement")

    if FAILURES:
        print(f"{len(FAILURES)} selftest failure(s)", file=sys.stderr)
        return 1
    print(f"OK: selftest ({len(g.REQUIRED)} deletions, {len(g.COUNTED)} counts, 3 orderings, 2 comment/literal cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
