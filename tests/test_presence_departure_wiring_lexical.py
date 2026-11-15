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

Plus the endpoint_state retention prune's host (#5678): in server.cpp the one
`offline_endpoint_store_->run_retention_prune(kHardwareRosterWindow)` call must sit inside the
preflight_runner_thread_ lambda, inside the block of an `if (... && tick %
kOfflineEndpointPruneEveryNTicks == 1)`. No unit test drives that thread, so deleting the call,
dropping or loosening the cadence gate, changing the cadence constant, or moving the call onto
another thread (health_recompute_thread_ shares the revocation sweep's budget) would leave every
other test green. The software change ledger prune (SAM-14) is pinned the same way: one
`software_inventory_store_->run_retention_prune_changes()` call, inside that lambda, in the block
of an `if (... && tick % kSoftwareLedgerPruneEveryNTicks == 1)`. Each cadence constant is pinned to
`constexpr int <name> = 60;`, and the condition must end the `if` exactly (`== 10` and
`== 1 || true` fail) in a head with no `||`, so a dead `(void)(cond);` ahead of an ungated call, or a
call moved out of the block, fails too.

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


# Cadence of both prunes: ticks of the preflight runner thread (~1 h at 60 s/tick).
PRUNE_EVERY_N_TICKS = 60
# (call, tick condition, label, cadence constant): each prune hosted on the preflight runner thread.
PRUNES = (
    ("offline_endpoint_store_->run_retention_prune(kHardwareRosterWindow)",
     "tick % kOfflineEndpointPruneEveryNTicks == 1", "endpoint prune (#5678)",
     "kOfflineEndpointPruneEveryNTicks"),
    ("software_inventory_store_->run_retention_prune_changes()",
     "tick % kSoftwareLedgerPruneEveryNTicks == 1", "software change ledger prune (SAM-14)",
     "kSoftwareLedgerPruneEveryNTicks"),
)
PRUNE_START = "preflight_runner_thread_ = std::thread("
PRUNE_END = '"Pre-flight runner thread stopped"'


def block_end(text, open_idx):
    """Index of the `}` matching the `{` at open_idx, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        depth += (text[i] == "{") - (text[i] == "}")
        if depth == 0:
            return i
    return -1


def gate_problems(body, call, cond, label):
    """The call sits in the block of an `if (<no ||> && cond)` whose condition ends at `cond`."""
    gate = cond + "){"
    if body.count(gate) != 1:
        return [f"server.cpp: the {label} is not gated by an `if (... && {cond})` block"]
    end = body.index(gate)
    head = body[max(body.rfind(c, 0, end) for c in ";{}") + 1:end].lstrip()
    if not head.startswith("if(") or "||" in head:
        return [f"server.cpp: the {label} condition `{cond}` is not the tail of a plain `if (... && ...)`"]
    opening = end + len(gate) - 1
    if not opening < body.index(call) < block_end(body, opening):
        return [f"server.cpp: the {label} is not inside the block gated by `{cond}`"]
    return []


def prune_problems(src):
    """Each prune call appears once file-wide, inside the preflight thread lambda, in its gated block."""
    t = normalise(src)
    out = []
    lo, hi = t.find(normalise(PRUNE_START)), t.find(PRUNE_END)
    if lo < 0 or hi < lo:
        return ["server.cpp: preflight_runner_thread_ lambda not found (#5678)"]
    body = t[lo:hi]
    for raw_call, raw_cond, label, const in PRUNES:
        call, cond = normalise(raw_call), normalise(raw_cond)
        decl = normalise(f"constexpr int {const} = {PRUNE_EVERY_N_TICKS};")
        if t.count(decl) != 1:
            out.append(f"server.cpp: expected exactly one `{decl}` (found {t.count(decl)}): {label}")
        if t.count(call) != 1:
            out.append(f"server.cpp: expected exactly one `{call}` (found {t.count(call)}): {label}")
        elif call not in body:
            out.append(f"server.cpp: the {label} is not inside the preflight_runner_thread_ lambda")
        else:
            out.extend(gate_problems(body, call, cond, label))
    return out


def gated_if(cond):
    """Regex for the `if (... && cond) {` head holding `cond` (captures what precedes `&& cond`)."""
    return r"if \(([^{;]*?)\s*&&\s*" + re.escape(cond) + r"\)\s*\{"


# (pattern, replacement) mutations of server.cpp; each must make prune_problems() non-empty.
PRUNE_MUTATIONS = []
for _call, _cond, _, _const in PRUNES:
    PRUNE_MUTATIONS += [
        (re.escape(_call), "(void)0"),
        (re.escape(_cond), "true"),
        (re.escape(_cond), _cond[:-1] + "10"),              # == 10
        (re.escape(_cond), _cond + " || true"),             # == 1 || true
        (re.escape(f"constexpr int {_const} = {PRUNE_EVERY_N_TICKS};"),
         f"constexpr int {_const} = 6;"),
        # a dead `(void)(cond);` ahead of an ungated block
        (gated_if(_cond), "(void)(" + _cond + ");\nif (\\1 && true) {"),
        # the call leaves the gated block (the gated block is empty)
        (re.escape(_cond) + r"\) \{", _cond + ") {}\n{"),
    ]
PRUNE_MUTATIONS.append((re.escape(PRUNE_START), "health_recompute_thread_ = std::thread("))

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
        p += prune_problems((SRC / "server.cpp").read_text(encoding="utf-8"))
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

    def test_prune_mutations_are_caught(self):
        src = (SRC / "server.cpp").read_text(encoding="utf-8")
        for i, (pat, repl) in enumerate(PRUNE_MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = re.subn(pat, repl, src, count=1)
                self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                self.assertTrue(prune_problems(mutated), "mutation was NOT detected by the gate")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
