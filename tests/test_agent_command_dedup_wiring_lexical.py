#!/usr/bin/env python3
"""#3668 static lexical gate over agents/core/src/agent.cpp: the command-dedup claim block.

The claim/replay/RUNNING DECISION is a pure function (`agents/core/src/command_dedup_decision.hpp`,
unit-tested by tests/unit/test_command_dedup_decision.cpp). Nothing exercises the Subscribe
reader loop that CALLS it (no gRPC seam in agent.cpp, #1492), so a refactor could silently stop
calling it, ignore a field of its answer, or drop the `continue` that keeps a duplicate from
dispatching, and every behavioural test would stay green. This gate pins the call sites
lexically. Numbers in parentheses are docs/command-dedup.md's invariants; the leading numbers
are this gate's own items:

  1. The claim is gated by `} else if (should_claim(command_dedup_ != nullptr,
     cmd.command_id(), cmd.plugin())) {` - the call's result is the WHOLE condition, so
     `|| true` / `else if (true)` cannot defeat it (3: the `__guard__`-only bypass lives in
     one place). The empty-command_id warning branch stays (it is the operator signal that
     replay protection cannot apply).
  2. The post-claim answer comes from `decide_after_claim(claim.status, claim.state,
     stored_parses)`, and `stored_parses` is computed only for a Terminal duplicate and from a
     real `ParseFromString` (4: an unparsable stored outcome answers RUNNING, never proceeds).
  3. `bool claimed_here = false;` is the first statement of each loop iteration, is assigned
     exactly once afterwards (`claimed_here = decision.owns_claim;`), and the queue-full
     release stays gated by `command_dedup_ && claimed_here` (1: only the owner releases).
  4. `decision.count_claim_error` guards the `yuzu_agent_dedup_claim_errors_total` increment
     (7: the fail-open stays observable).
  5. `decision.action == DedupAction::ReplayStored` guards the move of the stored outcome (4).
  6. The non-Proceed block is brace-matched and must END with exactly one
     `stream->Write(dup_resp, ...); continue;` and contain exactly one `continue;`, and
     `Write(dup_resp` appears once in the file - a `continue` in only one branch, or a second
     copy elsewhere, cannot satisfy it (4: a duplicate never reaches dispatch).
  7. The claim block precedes the plugin-match loop and the thread-pool submit.
  8. The reserved-name dispatch compares against `kDedupBypassPlugin`, and no inline
     `cmd.plugin() ==/!= "__guard__"` comparison exists (3: one literal, not two that drift).

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a check.
Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). Accepted blind spots, all of the same class: code disabled by `#if 0` or wrapped
in `/* */` (block comments are deliberately not stripped), a deleted `stream_write_mu_` lock (a
convention shared with other sites, not one of this gate's invariants), and a `//` inside a string
literal on the same line as pinned code (normalise() strips from the `//`, so the rest of that line
is not scanned; no such line exists in the claim region today). A `/* */` comment or a string
literal that contains the text `claimed_here = ` makes the assignment count go red: a loud false-red,
not a false-green. The self-test applies in-memory mutations to agent.cpp and requires
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
    " update the patterns AND the MUTATIONS / FN_MUTATIONS patterns in tests/test_agent_command_dedup_wiring_lexical.py)"
)


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def block_after(t, head):
    """Text between the '{' that ends `head` (a regex) and its balanced '}', or None.

    Walks forward from the head and skips string literals as it goes, so the '{}' placeholders in
    spdlog format strings cannot unbalance the count. Scanning forward from the head (instead of
    blanking every string in the file first) means a stray quote character earlier in agent.cpp
    cannot desynchronise the pairing."""
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
    t = normalise(src)
    out = []

    # 1. the claim gate: the call IS the whole condition
    if not re.search(r"\} else if \( ?should_claim\( ?command_dedup_ != nullptr, ?cmd\.command_id\(\), ?"
                     r"cmd\.plugin\(\) ?\) ?\) \{", t):
        out.append("agent.cpp no longer gates the claim with `} else if (should_claim(command_dedup_ != nullptr, "
                   "cmd.command_id(), cmd.plugin())) {` (the call must be the whole condition) (#3668)")
    if not re.search(r"if \( ?cmd\.command_id\(\)\.empty\(\) ?\) \{ spdlog::warn\( ?\"Received command with empty command_id", t):
        out.append("the empty command_id warning branch ('Received command with empty command_id') is gone; "
                   "operators lose the signal that replay protection cannot apply (#3668)")

    # 2. the answer
    if not re.search(r"decide_after_claim\( ?claim\.status, ?claim\.state, ?stored_parses ?\)", t):
        out.append("agent.cpp no longer decides via decide_after_claim(claim.status, claim.state, "
                   "stored_parses) (#3668)")
    if not re.search(r"stored_parses = claim\.status == ClaimStatus::Duplicate && "
                     r"claim\.state == DedupState::Terminal && "
                     r"stored\.ParseFromString\(claim\.response\);", t):
        out.append("stored_parses is no longer computed only for a Terminal duplicate from a real "
                   "stored.ParseFromString(claim.response) (#3668)")

    # 3. ownership
    if not re.search(r"while \( ?stream->Read\( ?&cmd ?\) ?\) \{ if \( ?stop_requested_\.load\(std::memory_order_acquire\) ?\) "
                     r"break; bool claimed_here = false;", t):
        out.append("`bool claimed_here = false;` is no longer the first statement of each loop iteration "
                   "(it must reset per iteration, not persist across commands) (#3668)")
    if len(re.findall(r"claimed_here = ", t)) != 2:
        out.append("claimed_here is assigned more than its declaration and `claimed_here = decision.owns_claim;` "
                   "(#3668)")
    if not re.search(r"claimed_here = decision\.owns_claim;", t):
        out.append("claimed_here is no longer assigned from decision.owns_claim (#3668)")
    if not re.search(r"command_dedup_ && claimed_here && command_dedup_->release\( ?cmd\.command_id\(\) ?\)", t):
        out.append("the queue-full release() is no longer gated by command_dedup_ && claimed_here (#3668)")

    # 4/5. observability and the replay guard
    if not re.search(r"if \( ?decision\.count_claim_error ?\) metrics_\.counter\( ?\"yuzu_agent_dedup_claim_errors_total\" ?\)"
                     r"\.increment\(\);", t):
        out.append("decision.count_claim_error no longer guards the yuzu_agent_dedup_claim_errors_total "
                   "increment (#3668)")
    if not re.search(r"if \( ?decision\.action == DedupAction::ReplayStored ?\) \{ dup_resp = std::move\( ?stored ?\);", t):
        out.append("decision.action == DedupAction::ReplayStored no longer guards the replay of the stored "
                   "outcome (#3668)")

    # 6. a non-Proceed answer writes the frame ONCE and ends with `continue;`
    if len(re.findall(r"stream->Write\( ?dup_resp", t)) != 1:
        out.append("`stream->Write(dup_resp` must appear exactly once in agent.cpp (a second copy could "
                   "satisfy the continue check while the real one loses it) (#3668)")
    blk = block_after(t, r"if \( ?decision\.action != DedupAction::Proceed ?\) \{")
    if (blk is None
            or not re.search(r"stream->Write\( ?dup_resp, ?grpc::WriteOptions\(\) ?\); ?continue; ?$", blk.rstrip())
            or blk.count("continue;") != 1):
        out.append("the non-Proceed dedup block must end with stream->Write(dup_resp, ...); continue; and "
                   "contain exactly one `continue;` - a duplicate must never fall through to dispatch (#3668)")

    # 7. ordering: the claim precedes plugin matching and the pool submit
    claim_at = re.search(r"should_claim\(", t)
    loop_at = t.find("if (cmd.plugin() == handle.descriptor()->name)")
    submit_at = t.find("bool submitted = thread_pool_->submit(")
    if not claim_at or loop_at < 0 or submit_at < 0:
        out.append("cannot locate should_claim( / the plugin-match loop / the pool submit to check ordering "
                   "(agent.cpp was restructured; update this gate) (#3668)")
    elif not (claim_at.start() < loop_at and claim_at.start() < submit_at):
        out.append("the dedup claim must precede the plugin-match loop and the thread-pool submit (#3668)")

    # 8. one literal
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
     "must end with"),
    # 8. dispatch literal drift, and an inline bypass reintroduced elsewhere
    (r"cmd\.plugin\(\) == kDedupBypassPlugin", 'cmd.plugin() == "__guard__"', 0, 0,
     "kDedupBypassPlugin"),
    (r"bool claimed_here = false;", 'bool claimed_here = false; (void)(cmd.plugin() != "__guard__");', 0, 0,
     "inline"),
    # the empty-id warning demoted (operators lose the signal)
    (r'spdlog::warn\("Received command with empty command_id', 'spdlog::debug("Received command with empty command_id', 0, 0,
     "empty command_id"),
]

# Mutations that need more than one substitution, which the single-regex table above cannot express.
# Each is (name, fn(raw) -> mutated, expected substring of the FIRST problem).
def _only_replay_branch_continues(raw):
    out = re.sub(r"(stream->Write\(dup_resp, grpc::WriteOptions\(\)\);)\s*continue;", r"\g<1>", raw)
    return re.sub(r'(terminal outcome",\s*cmd\.command_id\(\)\);)(\s*\} else \{)', r"\g<1> continue;\g<2>", out)


def _second_write_elsewhere(raw):
    out = re.sub(r"(stream->Write\(dup_resp, grpc::WriteOptions\(\)\);)\s*continue;", r"\g<1>", raw)
    return out.replace("bool submitted = thread_pool_->submit(",
                       "stream->Write(dup_resp, grpc::WriteOptions()); continue;\n"
                       "bool submitted = thread_pool_->submit(", 1)


def _plugin_loop_before_claim(raw):
    return re.sub(r"(\n\s*)(if \(cmd\.command_id\(\)\.empty\(\)\) \{\s*spdlog::warn)",
                  r"\1for (const auto& handle : plugins_) { if (cmd.plugin() == handle.descriptor()->name) { break; } }\1\2",
                  raw, count=1)


def _hoist_claimed_here(raw):
    out = raw.replace("bool claimed_here = false;", "", 1)
    return out.replace("while (stream->Read(&cmd)) {", "bool claimed_here = false;\nwhile (stream->Read(&cmd)) {", 1)


FN_MUTATIONS = [
    ("continue only in the ReplayStored branch", _only_replay_branch_continues, "must end with"),
    ("a second Write(dup_resp)+continue elsewhere", _second_write_elsewhere, "exactly once"),
    ("should_claim(...) || true",
     lambda raw: re.sub(r"(should_claim\(command_dedup_ != nullptr, cmd\.command_id\(\),\s*cmd\.plugin\(\)\))",
                        r"\1 || true", raw, count=1), "should_claim("),
    ("should_claim call replaced by `true`",
     lambda raw: re.sub(r"should_claim\(command_dedup_ != nullptr, cmd\.command_id\(\),\s*cmd\.plugin\(\)\)",
                        "true", raw, count=1), "should_claim("),
    ("claimed_here = true; added after the decision",
     lambda raw: raw.replace("claimed_here = decision.owns_claim;",
                             "claimed_here = decision.owns_claim; claimed_here = true;", 1),
     "claimed_here is assigned"),
    ("claimed_here hoisted out of the loop", _hoist_claimed_here, "per iteration"),
    ("plugin-match loop before the claim", _plugin_loop_before_claim, "precede"),
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

    def test_multi_step_mutations_are_caught(self):
        for name, fn, expected in FN_MUTATIONS:
            with self.subTest(mutation=name):
                mutated = fn(self.raw)
                self.assertNotEqual(mutated, self.raw, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
