#!/usr/bin/env python3
"""Static lexical gate over agents/core/src/agent.cpp: the Guardian empty-rule_id sender refusal.

The server drops a Guardian event with an empty rule_id at ingest and answers nothing, so the
agent refuses to send one (refuse_unsendable_guardian_event). The helper sits on two private
AgentImpl send paths with no gRPC seam to unit-test (#1492); a refactor could stop calling it, or
call it after the Write, and every behavioural test would stay green. Pinned here:

  1. emit_guardian_event (legacy) calls refuse_unsendable_guardian_event(ev, "legacy") and
     returns LegacySendOutcome::Sent BEFORE it builds the response or takes stream_write_mu_.
  2. send_guardian_outbox_entry (Spark) builds `wire_ev`, calls
     refuse_unsendable_guardian_event(wire_ev, "spark") and returns SendResult::Sent BEFORE
     the Write, and serialises `wire_ev` (not a second conversion).
  3. The helper decides through guardian_event_refused_by_server, logs the event id only through
     log_id_token (CWE-117), and wraps the log in try/catch(...).
  4. The legacy drift-sink lambda's T_wire record is not marked sent for a refused event.

Robustness: `//` comments are stripped and whitespace collapsed before matching. Carries an
in-memory mutation self-test; a mutation whose pattern no longer matches fails loudly (stale
pattern) rather than passing vacuously. Lexical only: it cannot see a relocation that keeps the
tokens but changes control flow (review-enforced).

Usage: python3 tests/test_agent_guardian_refusal_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
HINT = (" (this gate pins the sender refusal wiring; if agent.cpp was legitimately restructured,"
        " update the patterns AND the MUTATIONS in tests/test_agent_guardian_refusal_wiring_lexical.py)")


def normalise(src):
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    t = normalise(src)
    out = []
    if not re.search(r"LegacySendOutcome emit_guardian_event\( ?const gpb::GuaranteedStateEvent& ev ?\) \{ "
                     r"if \( ?refuse_unsendable_guardian_event\( ?ev, ?\"legacy\" ?\) ?\) "
                     r"return LegacySendOutcome::Sent; pb::CommandResponse resp;", t):
        out.append("emit_guardian_event no longer opens with the legacy refusal returning "
                   "LegacySendOutcome::Sent before the response is built" + HINT)
    if not re.search(r"const auto wire_ev = guardian_outbox_entry_to_event\( ?e, ?kHostPlatform ?\); "
                     r"if \( ?refuse_unsendable_guardian_event\( ?wire_ev, ?\"spark\" ?\) ?\) "
                     r"return SendResult::Sent; pb::CommandResponse resp;", t):
        out.append("send_guardian_outbox_entry no longer refuses wire_ev (\"spark\") with "
                   "SendResult::Sent before the response is built" + HINT)
    if not re.search(r"resp\.set_payload\( ?wire_ev\.SerializeAsString\(\) ?\);", t):
        out.append("send_guardian_outbox_entry no longer serialises the refused-checked wire_ev" + HINT)
    m = re.search(r"bool refuse_unsendable_guardian_event\([^)]*\) \{(.*?)\n? ?return true; \}", t)
    body = m.group(1) if m else ""
    if not re.search(r"if \( ?!guardian_event_refused_by_server\( ?ev ?\) ?\) return false;", body):
        out.append("refuse_unsendable_guardian_event no longer decides via guardian_event_refused_by_server" + HINT)
    if not re.search(r"try \{ spdlog::warn\([^;]*::yuzu::log_id_token\( ?ev\.event_id\(\) ?\)[^;]*\); "
                     r"\} catch \( ?\.\.\. ?\)", body):
        out.append("the refusal log no longer goes through log_id_token inside try/catch(...)" + HINT)
    if not re.search(r"const bool sent = \( ?outcome == LegacySendOutcome::Sent ?\) && "
                     r"!guardian_event_refused_by_server\( ?ev ?\);", t):
        out.append("the legacy T_wire record can mark a refused event sent" + HINT)
    return out


MUTATIONS = [
    ("legacy refusal removed",
     'if (refuse_unsendable_guardian_event(ev, "legacy"))', 'if (false)'),
    ("legacy refusal returns Retain-like outcome",
     'return LegacySendOutcome::Sent; // dropped by design', 'return LegacySendOutcome::WriteFailed; // dropped by design'),
    ("spark refusal removed",
     'if (refuse_unsendable_guardian_event(wire_ev, "spark"))', 'if (false)'),
    ("spark refusal returns Retain",
     'return SendResult::Sent; // Retain would wedge', 'return SendResult::Retain; // Retain would wedge'),
    ("payload re-converted instead of wire_ev",
     'resp.set_payload(wire_ev.SerializeAsString());', 'resp.set_payload(e.event.SerializeAsString());'),
    ("raw event id in the log",
     '::yuzu::log_id_token(ev.event_id())', 'ev.event_id()'),
    ("T_wire marks refused sent",
     '(outcome == LegacySendOutcome::Sent) &&\n                                          !guardian_event_refused_by_server(ev);',
     '(outcome == LegacySendOutcome::Sent);'),
]


class RefusalWiring(unittest.TestCase):
    src = AGENT_CPP.read_text(encoding="utf-8")

    def test_clean(self):
        self.assertEqual(problems(self.src), [])

    def test_mutations_are_caught(self):
        for name, old, new in MUTATIONS:
            with self.subTest(name):
                self.assertEqual(self.src.count(old), 1, f"stale mutation pattern: {name}")
                self.assertTrue(problems(self.src.replace(old, new)), f"mutation not caught: {name}")


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=1))
