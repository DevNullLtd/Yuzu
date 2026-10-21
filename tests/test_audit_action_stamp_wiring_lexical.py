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
       a ruling that it owes none) and exactly four `audit_registry_frame(audit_store_, agent_id,
       resp)` calls.
    5. Each hook is IMMEDIATELY followed by its failure signal and then by
       `notify_exec_tracker(resp.command_id(), agent_id, resp);`: the audit row is written
       before the execution advances. Two Subscribe forms (the audit-failed trailer) and two
       gateway forms (the error line).

`//` comments are stripped and whitespace runs collapsed before matching, so line wrapping and
comment text cannot satisfy or break a check. The self-test applies in-memory mutations (a deleted
stamp call, a deleted initialiser, a hook moved after the notification, a dropped failure signal)
and requires problems() to be non-empty on each; a mutation whose pattern no longer matches fails
loudly rather than passing vacuously.

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

HOOK = "if (!audit_registry_frame(audit_store_, agent_id, resp))"
NOTIFY = "notify_exec_tracker(resp.command_id(), agent_id, resp);"
SUBSCRIBE_FORM = f"{HOOK} signal_grpc_audit_failed(context); {NOTIFY}"
GATEWAY_FORM = (
    f'{HOOK} spdlog::error("[gateway] registry.write audit row failed to persist (agent={{}}, "'
    f' "command={{}})", yuzu::log_id_token(agent_id), yuzu::log_id_token(resp.command_id())); {NOTIFY}'
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
    hooks = t.count(normalise("audit_registry_frame(audit_store_, agent_id, resp)"))
    if hooks != 4:
        out.append(f"agent_service_impl.cpp: expected exactly 4 audit_registry_frame hook calls, found {hooks}")
    for name, form in (("Subscribe", SUBSCRIBE_FORM), ("gateway", GATEWAY_FORM)):
        want = normalise(form)
        n = t.count(want)
        if n != 2:
            out.append(
                f"agent_service_impl.cpp: expected exactly two {name} hooks of the form"
                f" `{want}` (found {n}): the row is written before the execution advances"
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
    # a hook deleted
    (r"if \(!audit_registry_frame\(audit_store_, agent_id, resp\)\)\s*signal_grpc_audit_failed\(context\);", ""),
    # the Subscribe failure signal dropped
    (r"(if \(!audit_registry_frame\(audit_store_, agent_id, resp\)\))\s*signal_grpc_audit_failed\(context\);", r"\1 (void)0;"),
    # a gateway hook moved after the notification
    (
        r"(if \(!audit_registry_frame\(audit_store_, agent_id, resp\)\)\s*spdlog::error\([^;]*;)(\s*(?://[^\n]*\n\s*)*)(notify_exec_tracker\(resp\.command_id\(\), agent_id, resp\);)",
        r"\3\2\1",
    ),
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
