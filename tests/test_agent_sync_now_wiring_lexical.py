#!/usr/bin/env python3
"""Static lexical gate over agents/core/src/agent.cpp: the `__sync__.now` command branch.

`decide_sync_now` (sync_now_decision.hpp) is a pure function with its own unit tests, but nothing
exercises the Subscribe reader loop that FEEDS it (no gRPC seam in agent.cpp, #1492). The
parameter keys are string literals read in that loop, so a typo compiles and every behavioural
test stays green: a misspelt `delay_max_s` silently degrades every delayed request to the
immediate path, a misspelt `source` silently widens a one-source request to `all`. This gate pins
the `source` and `delay_max_s` reads from `cmd.parameters()` and their pass-through into
`decide_sync_now(cmd.action(), source, delay_max_s, ...)`. Lexical only: it cannot see a
relocation that keeps the tokens but changes control flow (review-enforced). agent.cpp has
non-ASCII lines, so it is read as UTF-8. Usage: python3 tests/test_agent_sync_now_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAG = "test_agent_sync_now_wiring_lexical"
HEAD = 'if (cmd.plugin() == "__sync__") {'
HINT = (
    " (this gate pins the __sync__.now parameter wiring; if agent.cpp was legitimately restructured"
    " or renamed, update the patterns AND the MUTATIONS patterns in"
    " tests/test_agent_sync_now_wiring_lexical.py)"
)


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    """One message per violated invariant, in invariant order; [] when clean."""
    t = normalise(src)
    # Only the text from the __sync__ branch head on is searched, so a same-shaped read
    # elsewhere in agent.cpp cannot satisfy a pattern; a missing head is itself a problem.
    head = t.find(HEAD)
    if head < 0:
        return [f"agent.cpp no longer has the `{HEAD}` branch"]
    t = t[head:]
    out = []
    if not re.search(r'auto it = cmd\.parameters\( ?\)\.find\( ?"source" ?\); ?[^;]*\) ?source = it->second;', t):
        out.append('the __sync__ branch no longer reads `cmd.parameters().find("source")` into `source`')
    if not re.search(r'auto it = cmd\.parameters\( ?\)\.find\( ?"delay_max_s" ?\); ?[^;]*\) ?delay_max_s = it->second;', t):
        out.append('the __sync__ branch no longer reads `cmd.parameters().find("delay_max_s")` '
                   "into `delay_max_s`")
    if not re.search(r"decide_sync_now\( ?cmd\.action\( ?\), ?source, ?delay_max_s, ?[^;]*\) ?;", t):
        out.append("the __sync__ branch no longer passes `source` and `delay_max_s` to "
                   "decide_sync_now(cmd.action(), source, delay_max_s, ...)")
    return out


# Each row damages one invariant inside the __sync__ block: (pattern, repl, flags, count, expected
# substring of the FIRST problem). Patterns are anchored to the block's head so a same-named token
# elsewhere in agent.cpp cannot satisfy the "changed something" check.
_FROM_HEAD = r'(if \(cmd\.plugin\(\) == "__sync__"\) \{.*?)'
MUTATIONS = [
    # 1. the `source` key misspelt
    (_FROM_HEAD + r'find\("source"\)', r'\g<1>find("sources")', re.S, 1,
     "`cmd.parameters().find(\"source\")`"),
    # 2. the `delay_max_s` key misspelt
    (_FROM_HEAD + r'find\("delay_max_s"\)', r'\g<1>find("delay_max")', re.S, 1,
     "`cmd.parameters().find(\"delay_max_s\")`"),
    # 3. the decision called without the delay
    (_FROM_HEAD + r'decide_sync_now\(cmd\.action\(\), source, delay_max_s,',
     r'\g<1>decide_sync_now(cmd.action(), source, std::string{},', re.S, 1,
     "decide_sync_now(cmd.action(), source, delay_max_s"),
    # 4. the branch head renamed: nothing after it can be trusted to be the __sync__ block
    (r'if \(cmd\.plugin\(\) == "__sync__"\) \{', 'if (cmd.plugin() == "__synced__") {', 0, 1,
     "no longer has the"),
]


class AgentSyncNowWiringLexical(unittest.TestCase):
    def setUp(self):
        self.raw = AGENT_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (pat, repl, flags, cnt, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = re.subn(pat, repl, self.raw, count=cnt, flags=flags)
                self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
