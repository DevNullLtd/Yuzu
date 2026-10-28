#!/usr/bin/env python3
"""Static lexical gate over agents/core/src/agent.cpp: the Echo upgrade-window boot steps.

Nothing exercises Agent::run() (no seam, #1492), so a refactor could silently stop CALLING the
tested tar.db adoption helper and KV re-key, or move them after plugin init. Invariants,
anchored on tokens (never line numbers):

  1. `adopt_legacy_echo_db(cfg_.data_dir / "echo.db")` occurs after `KvStore::open(` and before
     the first `descriptor()->init(`. The adoption is the ONLY adopter: a plugin that opens
     echo.db first would create a fresh file beside tar.db (EchoDatabase::open then refuses).
  2. `rename_plugin("tar", "echo")` occurs in the same window, after the adoption call.

`//` comments are stripped and whitespace collapsed before matching. Lexical only: it cannot
see a relocation that keeps the tokens in order but changes control flow (review-enforced).
The self-test applies in-memory deletion/reorder/swap mutations and requires problems() to be
non-empty on each; a mutation whose pattern no longer matches fails loudly (stale pattern).

Usage: python3 tests/test_echo_adoption_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

AGENT_CPP = Path(__file__).resolve().parent.parent / "agents" / "core" / "src" / "agent.cpp"
HINT = " (update tests/test_echo_adoption_wiring_lexical.py only if agent.cpp was legitimately restructured)"
ADOPT = r'adopt_legacy_echo_db\( ?cfg_\.data_dir / "echo\.db" ?\)'
REKEY = r'rename_plugin\( ?"tar", ?"echo" ?\)'


def problems(src):
    t = re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))
    pos = {k: [m.start() for m in re.finditer(p, t)]
           for k, p in (("open", r"KvStore::open\("), ("adopt", ADOPT), ("rekey", REKEY),
                        ("init", r"descriptor\(\)->init\("))}
    out = []
    for k, what in (("open", "KvStore::open("), ("adopt", 'adopt_legacy_echo_db(cfg_.data_dir / "echo.db")'),
                    ("rekey", 'rename_plugin("tar", "echo")'), ("init", "descriptor()->init(")):
        if not pos[k]:
            out.append(f"agent.cpp no longer contains {what}")
    if out:
        return out
    if not pos["open"][0] < pos["adopt"][0] < pos["init"][0]:
        out.append("adopt_legacy_echo_db must run after KvStore::open( and before the first descriptor()->init(")
    if not pos["adopt"][0] < pos["rekey"][0] < pos["init"][0]:
        out.append('rename_plugin("tar", "echo") must run after the adoption and before the first descriptor()->init(')
    return out


# (pattern, replacement, expected substring of the first problem)
MUTATIONS = [
    (r"adopt_legacy_echo_db\(cfg_", "adopt_legacy_echo_db_x(cfg_", "no longer contains"),
    (r"(?=auto adopted = adopt_legacy_echo_db)", "handle.descriptor()->init(raw_pctx); ", "adopt_legacy_echo_db must run"),
    (r'rename_plugin\("tar", "echo"\)', 'rename_plugin("echo", "tar")', "no longer contains"),
    (r"(?=if \(kv_store_ && !kv_store_->rename_plugin)", "handle.descriptor()->init(raw_pctx); ", "rename_plugin"),
]


class EchoAdoptionWiringLexical(unittest.TestCase):
    def setUp(self):
        self.raw = AGENT_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::test_echo_adoption_wiring_lexical: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = re.subn(pat, repl, self.raw, count=1)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
