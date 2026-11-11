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
    code = g.code_canonical(raw)
    lit = g.canonical(raw)
    expect(g.problems_canonical(code, lit) == [], "the real server.cpp must pass the gate")

    # Delete each required statement from the text its row matches against.
    for rid, pat, _why in g.REQUIRED:
        base = g.text_for(rid, code, lit)
        m = re.search(pat, base, re.S)
        if not m:
            expect(False, f"{rid}: pattern no longer matches the real source (stale pattern)")
            continue
        a, b = m.span("k")
        mutated = base[:a] + base[b:]
        found = ids(g.problems_canonical(mutated if base is code else code,
                                         lit if base is code else mutated))
        expect(rid in found, f"{rid}: deleting its statement was NOT detected")

    wire = re.search(g._WIRE, code)
    thread = re.search(g._THREAD, code)
    expect(bool(wire and thread), "wiring and thread anchors must exist in the real source")
    if wire and thread:
        stmt = wire.group(0)
        expect("wire-once" in ids(g.problems_canonical(code + stmt, lit)), "a duplicated wiring call was NOT detected")
        expect("anchor-thread" in ids(g.problems_canonical(code + "health_recompute_thread_=std::thread(", lit)),
               "a second thread start was NOT detected")
        moved = code[:wire.start()] + code[wire.end():thread.end()] + stmt + code[thread.end():]
        expect("wire-before-thread" in ids(g.problems_canonical(moved, lit)),
               "a wiring moved after the thread start was NOT detected")
        early = code[:wire.start()] + "health_store_.recompute_metrics(metrics_,w);" + code[wire.start():]
        expect("wire-before-sweep" in ids(g.problems_canonical(early, lit)),
               "a recompute call ahead of the wiring was NOT detected")

    # Inert text must not stand in for the call: a comment, an ordinary string literal and a raw
    # string literal each replace the real statement and must turn the gate red. Likewise a
    # thread start or recompute call spelt in a literal is not code.
    stmt_re = r"health_store_\s*\.\s*set_known_plugins\s*\(.*?\)\s*\)\s*;"
    m = re.search(stmt_re, raw, re.S)
    expect(bool(m), "the real wiring statement must be found in the raw source")
    if m:
        orig = m.group(0)
        for name, repl in (
            ("comment", "// " + orig.replace("\n", "\n// ")),
            ("ordinary string", 'const char* x = "' + re.sub(r"\s+", " ", orig) + '";'),
            ("raw string", 'const char* x = R"pin(' + orig + ')pin";'),
            ("char-literal-prefixed string", "const char c = 'x'; const char* y = \"" + re.sub(r"\s+", " ", orig) + '";'),
        ):
            mutated = raw[:m.start()] + repl + raw[m.end():]
            expect("wire-known-plugins" in ids(g.problems(mutated)),
                   f"the wiring replaced by a {name} satisfied the gate")
    hidden = raw.replace("health_store_.set_known_plugins(", 'const char* s = "/*"; health_store_.set_known_plugins(', 1)
    expect("wire-known-plugins" not in ids(g.problems(hidden)), "a string literal hid the real wiring statement")
    fake_thread = raw.replace("health_recompute_thread_ = std::thread(", 'const char* q = "health_recompute_thread_ = std::thread("; auto z = std::thread(', 1)
    expect("wire-before-thread" in ids(g.problems(fake_thread)) or "anchor-thread" in ids(g.problems(fake_thread)),
           "a thread start spelt in a literal satisfied the gate")
    # The literal blanker leaves a C++14 digit separator alone.
    expect(g.blank_literals("int n = 1'000; f(\"a\");") == 'int n = 1\'000; f("");', "digit separator mishandled")

    if FAILURES:
        print(f"{len(FAILURES)} selftest failure(s)", file=sys.stderr)
        return 1
    print(f"OK: selftest ({len(g.REQUIRED)} deletions, {len(g.COUNTED)} counts, 3 orderings, 4 inert-text replacements, literal cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
