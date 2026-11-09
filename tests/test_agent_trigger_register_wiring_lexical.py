#!/usr/bin/env python3
"""Static lexical gate over the plugin trigger-registration bridge in agents/core/src/agent.cpp.

`yuzu_register_trigger` (the C ABI entry plugins call through PluginContext::register_trigger)
turns the trigger engine's "table full, nothing registered" answer (`register_trigger` returns
false) into the non-zero return plugin.h promises, so a plugin hears that its trigger did not
take effect instead of reading a silent success. The engine half is unit-tested
(test_trigger_engine.cpp pins the cap and the false return), but the bridge reaches into
`PluginContextImpl`, a translation-unit-local type with no header and no test seam, so no unit
test can call it. This gate pins the two lines the bridge depends on:

  1. Inside the `yuzu_register_trigger` body, `if (!impl->trigger_engine->register_trigger(...))`
     is immediately followed by `return -5;`.
  2. `TriggerEngine::register_trigger` is declared with a `bool` return in trigger_engine.hpp
     (the bridge's `!` test is only meaningful on a bool; a `void` return would not compile
     there, and a quietly-ignored result would reopen the silent success).

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a check.
Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations (the -5 return reverted to 0, the
guard dropped so the result is ignored, the declaration changed to void) and requires
problems() to be non-empty on each; a mutation whose pattern no longer matches fails loudly
(stale pattern) rather than passing vacuously.

Usage: python3 tests/test_agent_trigger_register_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TRIGGER_HPP = ROOT / "agents" / "core" / "include" / "yuzu" / "agent" / "trigger_engine.hpp"
TAG = "test_agent_trigger_register_wiring_lexical"
HINT = (
    " (this gate pins the plugin trigger-registration bridge; if agent.cpp or trigger_engine.hpp was"
    " legitimately restructured, update tests/test_agent_trigger_register_wiring_lexical.py)"
)


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(agent_src, hpp_src):
    """One message per violated invariant, in invariant order; [] when clean."""
    out = []

    body = re.search(r"int yuzu_register_trigger\(.*?(?=YUZU_EXPORT int yuzu_unregister_trigger\()",
                     normalise(agent_src))
    if not body:
        out.append("agent.cpp no longer defines yuzu_register_trigger ahead of yuzu_unregister_trigger")
    elif not re.search(r"if \( ?! ?impl->trigger_engine->register_trigger\([^;{}]*\) ?\) ?return -5;",
                       body.group(0)):
        out.append("yuzu_register_trigger no longer returns -5 when impl->trigger_engine->register_trigger "
                   "reports a full table (the plugin would read a silent success)")

    if not re.search(r"\bbool register_trigger\( ?TriggerConfig config ?\);", normalise(hpp_src)):
        out.append("trigger_engine.hpp no longer declares `bool register_trigger(TriggerConfig config);` "
                   "(the bridge's -5 depends on the bool return)")
    return out


# Each row removes one invariant: (file, pattern, repl, expected substring of the FIRST problem).
# Applied once (count=1) to the named file's text.
MUTATIONS = [
    ("cpp", r"return -5;", "return 0;", "no longer returns -5"),
    ("cpp", r"if \(!impl->trigger_engine->register_trigger\(std::move\(\*cfg\)\)\)\s*return -5;",
     "(void)impl->trigger_engine->register_trigger(std::move(*cfg));", "no longer returns -5"),
    ("cpp", r"int yuzu_register_trigger\(", "int yuzu_register_trigger_renamed(",
     "no longer defines yuzu_register_trigger"),
    ("hpp", r"bool register_trigger\(TriggerConfig config\);", "void register_trigger(TriggerConfig config);",
     "trigger_engine.hpp no longer declares"),
]


class AgentTriggerRegisterWiringLexical(unittest.TestCase):
    def setUp(self):
        self.cpp = AGENT_CPP.read_text(encoding="utf-8")
        self.hpp = TRIGGER_HPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.cpp, self.hpp)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (which, pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                raw = self.cpp if which == "cpp" else self.hpp
                mutated, n = re.subn(pat, repl, raw, count=1)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated, self.hpp) if which == "cpp" else problems(self.cpp, mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
