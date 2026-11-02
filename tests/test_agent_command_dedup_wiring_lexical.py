#!/usr/bin/env python3
"""#3668 static lexical gate over agents/core/src/agent.cpp: the command-dedup claim block.

The claim/replay/RUNNING DECISION is a pure function (`agents/core/src/command_dedup_decision.hpp`,
unit-tested by tests/unit/test_command_dedup_decision.cpp). Nothing exercises the Subscribe
reader loop that CALLS it (no gRPC seam in agent.cpp, #1492), so a refactor could silently stop
calling it, ignore a field of its answer, or drop the `continue` that keeps a duplicate from
dispatching, and every behavioural test would stay green. This gate pins the call sites
lexically. Invariants (numbers are docs/command-dedup.md's):

  1. The claim is gated by `should_claim(command_dedup_ != nullptr, cmd.command_id(),
     cmd.plugin())` (3: the `__guard__`-only bypass lives in ONE place).
  2. The post-claim answer comes from `decide_after_claim(claim.status, claim.state,
     stored_parses)`, and `stored_parses` is computed only for a Terminal duplicate and from a
     real `ParseFromString` (4: an unparsable stored outcome answers RUNNING, never proceeds).
  3. `claimed_here = decision.owns_claim` (1: only the owner may release on queue-full), and the
     queue-full release stays gated by `command_dedup_ && claimed_here`.
  4. `decision.count_claim_error` guards the `yuzu_agent_dedup_claim_errors_total` increment
     (7: the fail-open stays observable).
  5. `decision.action == DedupAction::ReplayStored` guards the move of the stored outcome.
  6. A non-Proceed answer writes the frame and then `continue`s (4: a duplicate never reaches
     dispatch).
  7. The reserved-name dispatch compares against `kDedupBypassPlugin`, and no inline
     `cmd.plugin() ==/!= "__guard__"` comparison exists (3: one literal, not two that can drift).

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a check.
Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations to agent.cpp and requires
problems() to be non-empty on each; a mutation whose pattern no longer matches agent.cpp fails
loudly (stale pattern) rather than passing vacuously.

agent.cpp has non-ASCII lines, so it is read as UTF-8.

Usage: python3 tests/test_agent_command_dedup_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAG = "test_agent_command_dedup_wiring_lexical"
HINT = (
    " (this gate pins the #3668 wiring; if agent.cpp was legitimately restructured or renamed,"
    " update tests/test_agent_command_dedup_wiring_lexical.py)"
)


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    """One message per violated invariant, in invariant order; [] when clean."""
    t = normalise(src)
    out = []

    if not re.search(r"should_claim\( ?command_dedup_ != nullptr, ?cmd\.command_id\(\), ?cmd\.plugin\(\) ?\)", t):
        out.append("agent.cpp no longer gates the claim with should_claim(command_dedup_ != nullptr, "
                   "cmd.command_id(), cmd.plugin()) (#3668)")

    if not re.search(r"decide_after_claim\( ?claim\.status, ?claim\.state, ?stored_parses ?\)", t):
        out.append("agent.cpp no longer decides via decide_after_claim(claim.status, claim.state, "
                   "stored_parses) (#3668)")
    if not re.search(r"stored_parses = claim\.status == ClaimStatus::Duplicate && "
                     r"claim\.state == DedupState::Terminal && "
                     r"stored\.ParseFromString\(claim\.response\);", t):
        out.append("stored_parses is no longer computed only for a Terminal duplicate from a real "
                   "stored.ParseFromString(claim.response) (#3668)")

    if not re.search(r"claimed_here = decision\.owns_claim;", t):
        out.append("claimed_here is no longer assigned from decision.owns_claim (#3668)")
    if not re.search(r"command_dedup_ && claimed_here && command_dedup_->release\( ?cmd\.command_id\(\) ?\)", t):
        out.append("the queue-full release() is no longer gated by command_dedup_ && claimed_here (#3668)")

    if not re.search(r"if \( ?decision\.count_claim_error ?\) metrics_\.counter\( ?\"yuzu_agent_dedup_claim_errors_total\" ?\)"
                     r"\.increment\(\);", t):
        out.append("decision.count_claim_error no longer guards the yuzu_agent_dedup_claim_errors_total "
                   "increment (#3668)")

    if not re.search(r"if \( ?decision\.action == DedupAction::ReplayStored ?\) \{ dup_resp = std::move\( ?stored ?\);", t):
        out.append("decision.action == DedupAction::ReplayStored no longer guards the replay of the stored "
                   "outcome (#3668)")

    # A non-Proceed answer must write the frame and then continue, so a duplicate never dispatches.
    if not re.search(r"if \( ?decision\.action != DedupAction::Proceed ?\) \{.*?"
                     r"stream->Write\( ?dup_resp, ?grpc::WriteOptions\(\) ?\); ?continue; ?\}", t):
        out.append("a non-Proceed dedup answer no longer writes dup_resp and then continues (#3668)")

    if not re.search(r"if \( ?cmd\.plugin\(\) == kDedupBypassPlugin ?\) \{", t):
        out.append("the reserved-name dispatch no longer compares against kDedupBypassPlugin (#3668)")
    if re.search(r"cmd\.plugin\(\) ?[!=]= ?\"__guard__\"", t):
        out.append("agent.cpp compares cmd.plugin() against an inline \"__guard__\" literal; use "
                   "kDedupBypassPlugin so the claim bypass and the dispatch cannot drift (#3668)")
    return out


# Each row removes one invariant from agent.cpp: (pattern, repl, flags, count, expected substring of
# the FIRST problem). count 0 = all matches, 1 = first only.
MUTATIONS = [
    # 1. should_claim call replaced by the old inline bypass
    (r"should_claim\(command_dedup_ != nullptr, cmd\.command_id\(\),\s*cmd\.plugin\(\)\)",
     'command_dedup_ && cmd.plugin() != "__guard__"', 0, 0,
     "should_claim("),
    # 2. decision no longer called / stored_parses hard-wired
    (r"decide_after_claim\(claim\.status, claim\.state, stored_parses\)",
     "decide_after_claim(claim.status, claim.state, true)", 0, 0,
     "decide_after_claim("),
    (r"claim\.status == ClaimStatus::Duplicate &&\s*claim\.state == DedupState::Terminal &&\s*"
     r"stored\.ParseFromString\(claim\.response\)",
     "true", 0, 0,
     "stored_parses is no longer computed"),
    # 3. ownership
    (r"claimed_here = decision\.owns_claim;", "claimed_here = true;", 0, 0,
     "owns_claim"),
    (r"command_dedup_ && claimed_here &&", "command_dedup_ &&", 0, 0,
     "claimed_here"),
    # 4. observable fail-open
    (r"if \(decision\.count_claim_error\)", "if (false)", 0, 0,
     "count_claim_error"),
    # 5. replay guard
    (r"if \(decision\.action == DedupAction::ReplayStored\)", "if (true)", 0, 0,
     "ReplayStored"),
    # 6. duplicate must not fall through to dispatch
    (r"(stream->Write\(dup_resp, grpc::WriteOptions\(\)\);)\s*continue;", r"\g<1>", 0, 0,
     "continues"),
    # 7. dispatch literal drift, and an inline bypass reintroduced
    (r"cmd\.plugin\(\) == kDedupBypassPlugin", 'cmd.plugin() == "__guard__"', 0, 0,
     "kDedupBypassPlugin"),
    (r"\} else if \(should_claim\(", '} else if (cmd.plugin() != "__guard__" && should_claim(', 0, 0,
     "inline"),
]


class AgentCommandDedupWiringLexical(unittest.TestCase):
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
