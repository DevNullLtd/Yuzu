#!/usr/bin/env python3
"""Static lexical gate over agents/core/src/agent.cpp: the `__sync__.now` command branch.

`decide_sync_now` (agents/core/src/sync_now_decision.hpp) is a pure function with its own unit
tests (tests/unit/test_agent_sync_command.cpp), but nothing exercises the Subscribe reader loop
that FEEDS it (no gRPC seam in agent.cpp, #1492). The command's parameter keys are string
literals read in that loop, so a typo in either one compiles and every behavioural test stays
green: a misspelt `delay_max_s` silently degrades every delayed request to the immediate path,
a misspelt `source` silently widens a one-source request to `all`. This gate pins, inside the
`cmd.plugin() == "__sync__"` block:

  1. `source` is read from `cmd.parameters().find("source")` into `source`.
  2. `delay_max_s` is read from `cmd.parameters().find("delay_max_s")` into `delay_max_s`.
  3. Both reach the decision: `decide_sync_now(cmd.action(), source, delay_max_s, ...)`.

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text cannot satisfy or break a check. Patterns anchor on
distinctive tokens, never line numbers. The block is brace-matched and string-aware, so a read
placed elsewhere in agent.cpp (another command's `source` parameter) cannot satisfy a check.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations to agent.cpp and requires problems()
to be non-empty on each; a mutation whose pattern no longer matches agent.cpp fails loudly
(stale pattern) rather than passing vacuously.

agent.cpp has non-ASCII lines, so it is read as UTF-8.

Usage: python3 tests/test_agent_sync_now_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAG = "test_agent_sync_now_wiring_lexical"
HINT = (
    " (this gate pins the __sync__.now parameter wiring; if agent.cpp was legitimately restructured"
    " or renamed, update the patterns AND the MUTATIONS patterns in"
    " tests/test_agent_sync_now_wiring_lexical.py)"
)
HEAD = r'if \( ?cmd\.plugin\(\) ?== ?"__sync__" ?\) \{'


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def block_after(t, head):
    """Text between the '{' that ends `head` (a regex) and its balanced '}', or None.

    Walks forward from the head and skips string literals as it goes, so the '{}' placeholders in
    spdlog format strings cannot unbalance the count."""
    m = re.search(head, t)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(t) and depth:
        c = t[i]
        if c == '"':
            i += 1
            while i < len(t) and t[i] != '"':
                i += 2 if t[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return t[m.end():i - 1] if depth == 0 else None


def problems(src):
    """One message per violated invariant, in invariant order; [] when clean."""
    blk = block_after(normalise(src), HEAD)
    if blk is None:
        return ['agent.cpp no longer has a balanced `if (cmd.plugin() == "__sync__") {` block '
                "(restructured; update this gate)"]
    out = []
    if not re.search(r'auto it = cmd\.parameters\( ?\)\.find\( ?"source" ?\); ?[^;]*\) ?source = it->second;', blk):
        out.append('the __sync__ branch no longer reads `cmd.parameters().find("source")` into `source`')
    if not re.search(r'auto it = cmd\.parameters\( ?\)\.find\( ?"delay_max_s" ?\); ?[^;]*\) ?delay_max_s = it->second;', blk):
        out.append('the __sync__ branch no longer reads `cmd.parameters().find("delay_max_s")` '
                   "into `delay_max_s`")
    if not re.search(r"decide_sync_now\( ?cmd\.action\( ?\), ?source, ?delay_max_s, ?[^;]*\) ?;", blk):
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
    # 2b. the value read but never assigned
    (_FROM_HEAD + r'delay_max_s = it->second;', r'\g<1>(void)it->second;', re.S, 1,
     "`cmd.parameters().find(\"delay_max_s\")`"),
    # 3. the decision called without the delay
    (_FROM_HEAD + r'decide_sync_now\(cmd\.action\(\), source, delay_max_s,',
     r'\g<1>decide_sync_now(cmd.action(), source, std::string{},', re.S, 1,
     "decide_sync_now(cmd.action(), source, delay_max_s"),
    # 3b. the decision called without the source
    (_FROM_HEAD + r'decide_sync_now\(cmd\.action\(\), source, delay_max_s,',
     r'\g<1>decide_sync_now(cmd.action(), std::string{}, delay_max_s,', re.S, 1,
     "decide_sync_now(cmd.action(), source, delay_max_s"),
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
