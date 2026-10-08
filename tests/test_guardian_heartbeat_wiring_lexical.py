#!/usr/bin/env python3
"""#5513 static lexical gate over the Guardian heartbeat generation wiring.

AgentImpl::run()'s heartbeat loop has no unit-drivable seam (#1492), so nothing else would notice
if the call that puts the Guardian boot re-arm signal on the wire were deleted: the emitter and
GuardianEngine::generation_report() are unit-tested in isolation, yet removing their call site
restores the never-retry bug with every test green. This gate pins the call site lexically.
Invariants on agents/core/src/agent.cpp (heartbeat "Group B"):

  a. `guardian_->generation_report()` is called (once, into a local).
  b. That local's `.reported` AND `.boot_rearm_unresolved` are both passed to
     `emit_guardian_generation_heartbeat_tags(`; the old inline
     `tags["yuzu.guardian_generation"] =` insert is ABSENT from agent.cpp.
  c. The call sits in a `try` whose `catch (...)` calls `hb_guardian_contain(kHbGuardianGeneration, ...`.
  d. Order: the emit comes AFTER `guardian_->journal_maintenance_tick()` (Group A1 before Group B), so
     an ack the tick produces is visible on the same heartbeat.
  e. guardian_health_heartbeat.hpp's emitter inserts the companion tag key BEFORE
     `yuzu.guardian_generation` (a failure between the two must never ship (0, companion absent)).

Robustness: /* */ and // comments are stripped and whitespace collapsed before matching, so a
commented-out call, line wrapping or comment text mentioning a token cannot satisfy or break a check.
Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies in-memory mutations and requires problems() to name the
expected violation on each; a mutation that changes nothing fails loudly (stale pattern).

Modelled on tests/test_agent_ota_wiring_lexical.py. Sources are read as UTF-8.
Usage: python3 tests/test_guardian_heartbeat_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
HEADER = ROOT / "agents" / "core" / "src" / "guardian_health_heartbeat.hpp"
TAG = "test_guardian_heartbeat_wiring_lexical"
HINT = (" (this gate pins the #5513 heartbeat wiring; if agent.cpp or guardian_health_heartbeat.hpp was"
        " legitimately restructured, update tests/test_guardian_heartbeat_wiring_lexical.py)")
GEN = "guardian_->generation_report()"
EMIT = "emit_guardian_generation_heartbeat_tags("
TICK = "guardian_->journal_maintenance_tick();"
INLINE = r'tags\["yuzu\.guardian_generation"\] ?='


def normalise(src):
    """Strip /* */ then // comments, collapse whitespace."""
    s = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", s))


def problems(agent_src, header_src):
    """One message per violated invariant, in a..e order; [] when clean."""
    t, h, out = normalise(agent_src), normalise(header_src), []
    m = re.search(r"(\w+) = " + re.escape(GEN) + ";", t)
    if not m:
        out.append(f"agent.cpp no longer calls {GEN} into a local (a)")
    v = re.escape(m.group(1)) if m else r"\w+"
    call = re.search(re.escape(EMIT) + " ?tags, ?" + v + r"\.reported, ?" + v + r"\.boot_rearm_unresolved ?\)", t)
    if not call:
        out.append(f"agent.cpp no longer passes the report's .reported and .boot_rearm_unresolved to {EMIT} (b)")
    if re.search(INLINE, t):
        out.append('agent.cpp inserts tags["yuzu.guardian_generation"] inline instead of via the emitter (b)')
    if not re.search(r"try \{ (const auto )?\w+ = " + re.escape(GEN) + "; ?" + re.escape(EMIT)
                     + r"[^;]*; ?\} catch \(\.\.\.\) ?\{ ?hb_guardian_contain\( ?kHbGuardianGeneration,", t):
        out.append("the generation_report()/emitter call is no longer in a try whose catch(...) calls "
                   "hb_guardian_contain(kHbGuardianGeneration, ...) (c)")
    if call:
        ticks = [x.start() for x in re.finditer(re.escape(TICK), t) if x.start() < call.start()]
        if not ticks or call.start() - ticks[-1] > 2500:
            out.append(f"the generation emit no longer follows {TICK} in the same heartbeat build (d)")
    if len(re.findall(re.escape(EMIT), t)) != 1:
        out.append(f"expected exactly one {EMIT} call in agent.cpp (b)")
    body = re.search(r"void emit_guardian_generation_heartbeat_tags\(.*?\n\}", header_src, re.S)
    hb = normalise(body.group(0)) if body else h
    c, g = hb.find("tags[kGuardianBootRearmUnresolvedTag]"), hb.find('tags["yuzu.guardian_generation"]')
    if c < 0 or g < 0 or c > g:
        out.append("guardian_health_heartbeat.hpp no longer inserts the companion tag BEFORE "
                   "yuzu.guardian_generation (e)")
    return out


def _sub(pat, repl, flags=0):
    return lambda s: re.sub(pat, repl, s, flags=flags)


# (name, target 'agent'|'hdr', mutator, expected substring of the joined problems)
MUTATIONS = [
    ("delete generation_report call", "agent",
     _sub(r"const auto gen_report = guardian_->generation_report\(\);", "const GenReport gen_report{};"), "(a)"),
    ("emitter call -> old inline insert", "agent",
     _sub(r"emit_guardian_generation_heartbeat_tags\(\s*tags, gen_report\.reported, gen_report\.boot_rearm_unresolved\);",
          'tags["yuzu.guardian_generation"] = std::to_string(gen_report.reported);'), "inline"),
    ("comment the call out", "agent",
     _sub(r"^( *)(const auto gen_report = guardian_->generation_report\(\);|emit_guardian_generation_heartbeat_tags\("
          r"|tags, gen_report\.reported, gen_report\.boot_rearm_unresolved\);)$", r"\1// \2", re.M), "(b)"),
    ("block-comment the call out", "agent",
     _sub(r"(const auto gen_report = guardian_->generation_report\(\);\s*emit_guardian_generation_heartbeat_tags\("
          r"[^;]*;)", r"/* \1 */"), "(a)"),
    ("drop boot_rearm_unresolved argument", "agent",
     _sub(r"gen_report\.boot_rearm_unresolved\);", "false);"), "(b)"),
    ("drop reported argument", "agent",
     _sub(r"tags, gen_report\.reported, gen_report\.boot_rearm_unresolved", "tags, 0, gen_report.boot_rearm_unresolved"), "(b)"),
    ("catch no longer contains the generation group", "agent",
     _sub(r"hb_guardian_contain\(kHbGuardianGeneration,", "hb_guardian_contain(kHbGuardianTags,"), "(c)"),
    ("emit moved before the tick", "agent",
     lambda s: s.replace(TICK, "(void)0;", 1).replace(
         "gen_report.boot_rearm_unresolved);", "gen_report.boot_rearm_unresolved);\n" + TICK, 1), "(d)"),
    ("header: companion/generation order swapped", "hdr",
     _sub(r'( *if \(boot_rearm_unresolved\)\n\s*tags\[kGuardianBootRearmUnresolvedTag\] = "1";\n)'
          r'( *tags\["yuzu\.guardian_generation"\] = std::to_string\(reported\);\n)', r"\2\1"), "(e)"),
]


class GuardianHeartbeatWiringLexical(unittest.TestCase):
    def setUp(self):
        self.agent = AGENT_CPP.read_text(encoding="utf-8")
        self.hdr = HEADER.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.agent, self.hdr)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for name, target, mutate, expected in MUTATIONS:
            with self.subTest(mutation=name):
                src = self.agent if target == "agent" else self.hdr
                mutated = mutate(src)
                self.assertNotEqual(mutated, src, "mutation changed nothing (stale pattern)")
                a, h = (mutated, self.hdr) if target == "agent" else (self.agent, mutated)
                p = problems(a, h)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, "\n".join(p))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
