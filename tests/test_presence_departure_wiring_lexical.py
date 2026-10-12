#!/usr/bin/env python3
"""#5678 static lexical gate over the two disconnect paths' presence mirror.

Both disconnect paths (the direct Subscribe stream in agent_service_impl.cpp, the gateway
DISCONNECTED handler in gateway_service_impl.cpp) must mirror a departure into durable presence
ONLY through presence_departure.hpp's mirror_departure_to_presence(), with the real gate. The
direct path has no unit harness (bidi gRPC stream), so this pin is its coverage. Invariants,
per file:

  1. Exactly one `mirror_departure_to_presence(<gate>, heartbeat_ingestion_ ?
     heartbeat_ingestion_->offline_endpoint_store() : nullptr, agent_id, session_id);` call, with
     <gate> = `removed_current_session` (direct) or `removed_current_session || store_removed`
     (gateway: a non-owning replica removes no local session, so the directory result is its
     only proof).
  2. No raw `remove_if_session(` call (`->` or `.`): a hand-copied, possibly ungated call would
     bypass the helper.

`//` comments are stripped and whitespace runs collapsed before matching, so line wrapping and
comment text cannot satisfy or break a check. The self-test applies in-memory mutations (dropped
gate, `(false, nullptr, ...)` substitution, raw call) and requires problems() to be non-empty on
each; a mutation whose pattern no longer matches fails loudly rather than passing vacuously.

Usage: python3 tests/test_presence_departure_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "server" / "core" / "src"
TAG = "test_presence_departure_wiring_lexical"
HINT = (
    " (this gate pins the #5678 presence-mirror wiring; if the disconnect handlers were"
    " legitimately restructured, update tests/test_presence_departure_wiring_lexical.py)"
)
STORE_ARG = "heartbeat_ingestion_ ? heartbeat_ingestion_->offline_endpoint_store() : nullptr"
SITES = (
    ("agent_service_impl.cpp", "removed_current_session"),
    ("gateway_service_impl.cpp", "removed_current_session || store_removed"),
)


def normalise(src):
    """Strip // comments, collapse whitespace, drop spaces inside parens so a clang-format wrap
    after `(` matches the one-line form (/* */ deliberately not stripped)."""
    t = re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))
    return re.sub(r" ?([()]) ?", r"\1", t)


def problems(name, gate, src):
    """One message per violated invariant; [] when clean."""
    t = normalise(src)
    call = normalise(f"mirror_departure_to_presence({gate}, {STORE_ARG}, agent_id, session_id);")
    out = []
    n = t.count(call)
    if n != 1:
        out.append(f"{name}: expected exactly one `{call}` (found {n}) (#5678)")
    if re.search(r"(->|\.) ?remove_if_session ?\(", t):
        out.append(f"{name}: raw remove_if_session( call bypasses mirror_departure_to_presence (#5678)")
    return out


# (file index into SITES, pattern, replacement, expected substring of the FIRST problem)
MUTATIONS = [
    (0, r"mirror_departure_to_presence\(\s*removed_current_session,", "mirror_departure_to_presence(false,",
     "expected exactly one"),
    (0, r"heartbeat_ingestion_ \? heartbeat_ingestion_->offline_endpoint_store\(\) : nullptr", "nullptr",
     "expected exactly one"),
    (0, r"mirror_departure_to_presence\(", "heartbeat_ingestion_->offline_endpoint_store()->remove_if_session(",
     "expected exactly one"),
    (1, r"removed_current_session \|\| store_removed", "removed_current_session",
     "expected exactly one"),
    (1, r"mirror_departure_to_presence\(\s*removed_current_session \|\| store_removed,", "mirror_departure_to_presence(false,",
     "expected exactly one"),
    (1, r"\n(\s*)agent_id, session_id\);", r"\n\g<1>agent_id, session_id);\n"
     r"offline_store.remove_if_session(agent_id, session_id);",
     "raw remove_if_session"),
]


class PresenceDepartureWiringLexical(unittest.TestCase):
    def setUp(self):
        self.raw = [(n, g, (SRC / n).read_text(encoding="utf-8")) for n, g in SITES]

    def test_source_is_clean(self):
        p = [m for n, g, s in self.raw for m in problems(n, g, s)]
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (idx, pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                name, gate, src = self.raw[idx]
                mutated, n = re.subn(pat, repl, src, count=1)
                self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(name, gate, mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
