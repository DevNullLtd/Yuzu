#!/usr/bin/env python3
"""Static lexical gate over the registry.write audit wiring: the agent's action stamp and the
server's four ingest hooks.

Neither half has a unit seam that reaches the production call sites. agent.cpp's command loop
(the CommandContextImpl built for a gRPC command, its output flush, its terminal frame) is not
constructible from a test; the helpers in command_frames.hpp are pinned by
test_agent_command_frames.cpp, but deleting the call to them, or the `.action = cmd.action()`
that feeds them, leaves every unit test green while no frame is ever stamped, so no
`registry.write` row is ever minted. On the server the four hooks sit beside the four places a
frame is stored; the Subscribe pair has no ordering harness, and the gateway terminal pair is
only partly covered. This gate is that coverage. Invariants:

  agent.cpp
    1. `command_frames.hpp` is included once.
    2. Exactly one `stamp_output_frame(resp, command_id, action, std::move(combined));` (the
       output flush) and exactly one `stamp_final_frame(final_resp, cmd.command_id(),
       cmd.action(), rc);` (the terminal frame).
    3. Exactly one `.action = cmd.action(),` (the CommandContextImpl initialiser that carries the
       dispatched action to the flush).

  agent_service_impl.cpp
    4. Exactly four `response_store_->store(` calls (a fifth output-storing site needs a hook, or
       a ruling that it owes none) and exactly four `audit_registry_frame(agent_id, resp)` calls.
    5. Each hook is IMMEDIATELY followed by its failure signal and then by
       `notify_exec_tracker(resp.command_id(), agent_id, resp);`: the audit row is written
       before the execution advances. Two Subscribe forms, which add the audit-failed trailer
       once per stream through `audit_failed_signalled`, and two gateway forms (an error line).
    6. `audit_failed_signalled` is declared exactly once, BEFORE the Subscribe read loop: declared
       inside it, it would be re-armed per frame and the trailer would be added per failed frame.

`//` comments are stripped and whitespace runs collapsed before matching, so line wrapping and
comment text cannot satisfy or break a check. The gateway error statement is matched as a whole
(its wording is pinned by the unit test, not here). The self-test applies in-memory mutations (a
deleted stamp call, a deleted initialiser, a hook moved after the notification, a dropped failure
signal, a flag that is never set or is re-armed per frame) and requires problems() to be non-empty
on each; a mutation whose pattern no longer matches fails loudly rather than passing vacuously.

Usage: python3 tests/test_audit_action_stamp_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agents" / "core" / "src" / "agent.cpp"
SERVER = ROOT / "server" / "core" / "src" / "agent_service_impl.cpp"
TAG = "test_audit_action_stamp_wiring_lexical"
HINT = (
    " (this gate pins the registry.write audit wiring; if the command loop or the frame-storing"
    " sites were legitimately restructured, update tests/test_audit_action_stamp_wiring_lexical.py)"
)


def normalise(src):
    """Strip // comments, collapse whitespace, drop spaces inside parens so a clang-format wrap
    after `(` matches the one-line form (/* */ deliberately not stripped)."""
    t = re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))
    return re.sub(r" ?([()]) ?", r"\1", t)


AGENT_ONCE = (
    '#include "command_frames.hpp"',
    "yuzu::agent::stamp_output_frame(resp, command_id, action, std::move(combined));",
    "yuzu::agent::stamp_final_frame(final_resp, cmd.command_id(), cmd.action(), rc);",
    ".action = cmd.action(),",
)

HOOK = "audit_registry_frame(agent_id, resp)"
NOTIFY = "notify_exec_tracker(resp.command_id(), agent_id, resp);"
FLAG_DECL = "bool audit_failed_signalled = false;"
READ_LOOP = "while (stream->Read(&resp))"
SUBSCRIBE_FORM = normalise(
    f"if (!{HOOK} && !audit_failed_signalled) {{ signal_grpc_audit_failed(context);"
    f" audit_failed_signalled = true; }} {NOTIFY}"
)
GATEWAY_RE = re.compile(
    re.escape(normalise(f"if (!{HOOK}) spdlog::error(")) + r"[^;]*" + re.escape(normalise(f"); {NOTIFY}"))
)


def agent_problems(src):
    t = normalise(src)
    out = []
    for snippet in AGENT_ONCE:
        n = t.count(normalise(snippet))
        if n != 1:
            out.append(f"agent.cpp: expected exactly one `{snippet}` (found {n})")
    return out


def server_problems(src):
    t = normalise(src)
    out = []
    stores = t.count("response_store_->store(")
    if stores != 4:
        out.append(
            f"agent_service_impl.cpp: expected exactly 4 `response_store_->store(` sites, found {stores}"
            " (a new output-storing site needs an audit_registry_frame hook before its notify)"
        )
    hooks = t.count(normalise(HOOK))
    if hooks != 4:
        out.append(f"agent_service_impl.cpp: expected exactly 4 `{HOOK}` hook calls, found {hooks}")
    subscribe = t.count(SUBSCRIBE_FORM)
    if subscribe != 2:
        out.append(
            f"agent_service_impl.cpp: expected exactly two Subscribe hooks of the form"
            f" `{SUBSCRIBE_FORM}` (found {subscribe}): the row is written before the execution"
            " advances, and the trailer is added once per stream"
        )
    gateway = len(GATEWAY_RE.findall(t))
    if gateway != 2:
        out.append(
            f"agent_service_impl.cpp: expected exactly two gateway hooks of the form"
            f" `if (!{HOOK}) spdlog::error(...); {NOTIFY}` (found {gateway}): the row is written"
            " before the execution advances"
        )
    decls = t.count(FLAG_DECL)
    loops = t.count(normalise(READ_LOOP))
    if decls != 1 or loops != 1 or t.find(FLAG_DECL) > t.find(normalise(READ_LOOP)):
        out.append(
            f"agent_service_impl.cpp: `{FLAG_DECL}` must appear exactly once and BEFORE the single"
            f" `{READ_LOOP}` (found {decls} declaration(s) and {loops} loop(s)): declared inside the"
            " loop it would be re-armed per frame"
        )
    return out


# (file, pattern, replacement); each must make that file's problems() non-empty.
AGENT_MUTATIONS = [
    (r"yuzu::agent::stamp_output_frame\(resp, command_id, action, std::move\(combined\)\);", "(void)0;"),
    (r"yuzu::agent::stamp_final_frame\(final_resp, cmd\.command_id\(\), cmd\.action\(\), rc\);", "(void)0;"),
    (r"\.action = cmd\.action\(\),", ""),
    (r'#include "command_frames\.hpp"', ""),
]
SERVER_MUTATIONS = [
    # a Subscribe hook deleted
    (
        r"if \(!audit_registry_frame\(agent_id, resp\) && !audit_failed_signalled\) \{\s*"
        r"signal_grpc_audit_failed\(context\);\s*audit_failed_signalled = true;\s*\}",
        "",
    ),
    # the Subscribe failure signal dropped
    (
        r"(if \(!audit_registry_frame\(agent_id, resp\) && !audit_failed_signalled\) \{)\s*"
        r"signal_grpc_audit_failed\(context\);",
        r"\1 (void)0;",
    ),
    # the once-per-stream flag never set
    (r"\n\s*audit_failed_signalled = true;", ""),
    # the flag declared inside the loop: re-armed for every frame
    (
        r"bool audit_failed_signalled = false;\s*while \(stream->Read\(&resp\)\) \{",
        "while (stream->Read(&resp)) {\n        bool audit_failed_signalled = false;",
    ),
    # a Subscribe hook moved after the notification
    (
        r"(if \(!audit_registry_frame\(agent_id, resp\) && !audit_failed_signalled\) \{[^}]*\})"
        r"(\s*(?://[^\n]*\n\s*)*)(notify_exec_tracker\(resp\.command_id\(\), agent_id, resp\);)",
        r"\3\2\1",
    ),
    # a gateway hook moved after the notification
    (
        r"(if \(!audit_registry_frame\(agent_id, resp\)\)\s*spdlog::error\([^;]*;)"
        r"(\s*(?://[^\n]*\n\s*)*)(notify_exec_tracker\(resp\.command_id\(\), agent_id, resp\);)",
        r"\3\2\1",
    ),
    # a gateway hook deleted
    (r"if \(!audit_registry_frame\(agent_id, resp\)\)\s*spdlog::error\([^;]*;", ""),
    # a fifth output-storing site appears
    (r"response_store_->store\(sr\);", "response_store_->store(sr);\nresponse_store_->store(sr);"),
]


class AuditActionStampWiringLexical(unittest.TestCase):
    def setUp(self):
        self.agent = AGENT.read_text(encoding="utf-8")
        self.server = SERVER.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = agent_problems(self.agent) + server_problems(self.server)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for label, src, muts, check in (
            ("agent.cpp", self.agent, AGENT_MUTATIONS, agent_problems),
            ("agent_service_impl.cpp", self.server, SERVER_MUTATIONS, server_problems),
        ):
            for i, (pat, repl) in enumerate(muts, 1):
                with self.subTest(file=label, mutation=i, pattern=pat):
                    mutated, n = re.subn(pat, repl, src, count=1)
                    self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                    self.assertTrue(check(mutated), "mutation was NOT detected by the gate")


if __name__ == "__main__":
    unittest.main()
