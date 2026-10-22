#!/usr/bin/env python3
"""Static lexical gate over the registry.write audit wiring: the agent's action stamp, the
server's four ingest hooks and the weak store they write to.

Neither half has a unit seam that reaches the production call sites. agent.cpp's command loop
(the CommandContextImpl built for a gRPC command, its output flush, its terminal frame) is not
constructible from a test; the helpers in command_frames.hpp are pinned by
test_agent_command_frames.cpp, but deleting the call to them, or the `.action = cmd.action()`
that feeds them, leaves every unit test green while no frame is ever stamped, so no
`registry.write` row is ever minted. On the server the four hooks sit beside the four places a
frame is stored; the Subscribe arms and the gateway terminal arm have no runtime ordering test
(docs/executions-history-ladder.md), and no unit test reads server.cpp. This gate is that
coverage; behaviour that a unit test can drive (the budget, the exact id shape) is pinned there.
Invariants:

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
    7. The hook body reads the store only through the statement
       `const auto store = registry_audit_store_.lock();`, once, and neither it nor
       process_gateway_response (the detached forwarder threads' entry) reads the raw
       `audit_store_` the other sites use and stop() unwires: that would be a use-after-free
       (#3279). String literals and `//` comments naming it do not count.
    8. The hook's `try {` opens before the pure verdict, so what the verdict raises is reported.
    9. The hook names an overflow key (`const std::string overflow = ...;`) and charges every row
       with it; without it agents past the budget's exact table share ONE allowance (a loss cliff
       at fleet scale). A live unit case pins the behaviour; this pin names the statements.
   10. The file calls `make_registry_audit_budget();` exactly once, the one place the production
       numbers meet (unit tests pin them).
   11. The hook runs inside the shutdown rundown gate (rundown_gate.hpp), which closes the pool
       half of the #3279 reach that the weak store does not: exactly one
       `const auto in_flight = registry_audit_gate_.try_enter();` followed by
       `if (!in_flight) return true;`, after the pure verdict and BEFORE the weak lock (the
       entry must die last, so the count falls after the strong reference is released); exactly
       one `registry_audit_gate_.closed()`, after the charge and before the only `store->log(`,
       with a `book_rows();` and a `return false;` between them (a closed gate loses the rest of
       the frame, counted); the hook never closes or waits itself; and the weak lock is the only
       `registry_audit_store_.lock(` in the file (a second reader would also need the gate).

  server.cpp
   12. `agent_service_.set_registry_audit_store(audit_store_);` appears exactly once and the setter
       is called nowhere else: deleting the line turns every row off silently, and clearing a weak
       pointer that a forwarder may be locking is a data race (the #3350 precedent).
   13. In stop(), `agent_service_.close_registry_audit();` then `if (!agent_service_.
       wait_registry_audit_idle(` ... `std::_Exit(1);` appear exactly once each, in that order,
       and both BEFORE the one `audit_store_.reset();`: reset the store or the pool while a
       forwarder is between two rows and the next row leases a pool that is going (the wait is
       what makes that impossible; on its timeout the process exits rather than go on).

`//` comments are stripped and whitespace runs collapsed before matching, so line wrapping and
comment text cannot satisfy or break a check. The gateway error statement is matched as a whole
(its wording is pinned by the unit test, not here). The self-test applies in-memory mutations (a
deleted stamp call, a deleted initialiser, a hook moved after the notification, a dropped failure
signal, a flag that is never set or is re-armed per frame, a raw store read beside the weak lock or
in the forwarder entry, a verdict outside the try, a charge without the overflow key, a missing
factory call, a deleted or cleared weak-store wiring, the rundown gate's entry deleted or moved
after the lock, its per-row check deleted or moved before the charge or made to return true or to
skip the booking, a second weak lock, the close or the wait deleted, swapped or moved after the
reset, the wait's result ignored or its force-exit removed) and requires problems() to be
non-empty on each; a mutation whose pattern no longer matches fails loudly rather than passing
vacuously. A
second set of BENIGN edits (a comment or a string naming the raw store, a re-wrapped call) must
leave problems() empty.

Usage: python3 tests/test_audit_action_stamp_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agents" / "core" / "src" / "agent.cpp"
SERVER = ROOT / "server" / "core" / "src" / "agent_service_impl.cpp"
MAIN = ROOT / "server" / "core" / "src" / "server.cpp"
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
HOOK_SIG = "bool AgentServiceImpl::audit_registry_frame("
FORWARDER_SIG = "void AgentServiceImpl::process_gateway_response("
WEAK_LOCK = "const auto store = registry_audit_store_.lock();"
ENTER = "const auto in_flight = registry_audit_gate_.try_enter();"
ENTER_GUARD = "if (!in_flight) return true;"
CLOSED_CHECK = "registry_audit_gate_.closed()"
STORE_LOG = "store->log("
CLOSE_CALL = "agent_service_.close_registry_audit();"
WAIT_COND = "if (!agent_service_.wait_registry_audit_idle("
EXIT_CALL = "std::_Exit(1);"
STORE_RESET = "audit_store_.reset();"
VERDICT = "registry_audit_events_for_frame("
LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')
OVERFLOW_KEY = "const std::string overflow = registry_audit_overflow_key(agent_id);"
CHARGE = "registry_audit_budget_->try_admit(agent_id, overflow)"
BUDGET_CTOR = "registry_audit_budget_ = make_registry_audit_budget();"
WIRING = "agent_service_.set_registry_audit_store(audit_store_);"
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


def body_of(t, sig):
    """The normalised body of the function whose signature starts with `sig` (the braces in its
    string literals balance)."""
    at = t.find(normalise(sig))
    start = t.find("{", t.find(")", at)) if at >= 0 else -1
    depth = 0
    for i in range(start, len(t)) if start >= 0 else ():
        depth += (t[i] == "{") - (t[i] == "}")
        if depth == 0:
            return t[start : i + 1]
    return None


def raw_store_read(body):
    """A bare `audit_store_` outside string literals (`registry_audit_store_` does not count)."""
    return re.search(r"(?<![A-Za-z0-9_])audit_store_", LITERAL.sub('""', body))


def main_problems(src):
    t = normalise(src)
    out = []
    wired, calls = t.count(normalise(WIRING)), t.count("set_registry_audit_store(")
    if wired != 1 or calls != 1:
        out.append(
            f"server.cpp: expected exactly one `{WIRING}` and no other call of"
            f" set_registry_audit_store (found {wired} wiring line(s) and {calls} setter call(s)):"
            " without the wiring no row is written, and clearing a weak pointer that a forwarder"
            " thread may be locking is a data race"
        )
    close, wait, reset = normalise(CLOSE_CALL), normalise(WAIT_COND), normalise(STORE_RESET)
    n_close, n_wait, n_reset = t.count(close), t.count(wait), t.count(reset)
    c, w, r = t.find(close), t.find(wait), t.find(reset)
    if (n_close, n_wait, n_reset) != (1, 1, 1) or not 0 <= c < w < r or EXIT_CALL not in t[w:r]:
        out.append(
            f"server.cpp: stop() must call `{CLOSE_CALL}`, then wait with `{WAIT_COND}...` and"
            f" `{EXIT_CALL}` on its timeout, each exactly once, all BEFORE the one `{STORE_RESET}`"
            f" (found {n_close} close, {n_wait} wait and {n_reset} reset statement(s)): reset the"
            " store or the pool while a forwarder thread is between two rows and its next row"
            " leases a pool that is going"
        )
    return out


def server_problems(src):
    t = normalise(src)
    out = []
    body = body_of(t, HOOK_SIG)
    forwarder = body_of(t, FORWARDER_SIG)
    if (
        body is None
        or forwarder is None
        or body.count(WEAK_LOCK) != 1
        or raw_store_read(body)
        or raw_store_read(forwarder)
    ):
        out.append(
            f"agent_service_impl.cpp: audit_registry_frame must read the store only through one"
            f" `{WEAK_LOCK}` and process_gateway_response not at all (never the raw `audit_store_`,"
            " which stop() unwires and frees while detached forwarder threads still run)"
        )
    if body is not None:
        enter = normalise(f"{ENTER} {ENTER_GUARD}")
        at_enter, at_verdict, at_lock = body.find(enter), body.find(VERDICT), body.find(WEAK_LOCK)
        at_charge, at_closed = body.find(normalise(CHARGE)), body.find(CLOSED_CHECK)
        at_log = body.find(STORE_LOG)
        closed_branch = body[at_closed:at_log] if 0 <= at_closed < at_log else ""
        if (
            body.count(enter) != 1
            or not 0 <= at_verdict < at_enter < at_lock
            or body.count(CLOSED_CHECK) != 1
            or body.count(STORE_LOG) != 1
            or not 0 <= at_charge < at_closed < at_log
            or "book_rows();" not in closed_branch
            or "return false;" not in closed_branch
            or "registry_audit_gate_.close()" in body
            or "wait_idle" in body
            or t.count("registry_audit_store_.lock(") != 1
        ):
            out.append(
                f"agent_service_impl.cpp: audit_registry_frame must enter the rundown gate with"
                f" `{ENTER} {ENTER_GUARD}` once, after the verdict and BEFORE `{WEAK_LOCK}` (it"
                f" must die last), check `{CLOSED_CHECK}` once, after the charge and before the"
                f" only `{STORE_LOG}`, with `book_rows();` and `return false;` in between, never"
                f" close or wait itself, and hold the only `registry_audit_store_.lock(` in the"
                f" file: otherwise a forwarder between two rows leases a pool that stop() is"
                f" destroying"
            )
    if body is None or not 0 <= body.find("try {") < body.find(VERDICT):
        out.append(
            "agent_service_impl.cpp: the try in audit_registry_frame must open before the verdict"
        )
    if body is None or any(body.count(normalise(s)) != 1 for s in (OVERFLOW_KEY, CHARGE)):
        out.append(
            f"agent_service_impl.cpp: audit_registry_frame must compute `{OVERFLOW_KEY}` once and"
            f" charge every row with `{CHARGE}`"
        )
    if t.count(normalise(BUDGET_CTOR)) != 1:
        out.append(f"agent_service_impl.cpp: expected exactly one `{BUDGET_CTOR}` in the constructor")
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
    # the hook reads the raw store instead of the weak one
    (r"registry_audit_store_\.lock\(\)", "std::shared_ptr<AuditStore>(audit_store_, [](AuditStore*) {})"),
    # the rows are charged without the overflow key: agents past the exact table share ONE allowance
    (r"registry_audit_budget_->try_admit\(agent_id, overflow\)", "registry_audit_budget_->try_admit(agent_id)"),
    # the constructor stops building the production budget
    (r"registry_audit_budget_ = make_registry_audit_budget\(\);", ""),
    # a raw store read beside the weak lock (the lock count stays one)
    (
        r"(const auto store = registry_audit_store_\.lock\(\);)",
        r"\1 (void)audit_store_->is_open();",
    ),
    # a raw store read in the forwarder threads' entry point
    (
        r"(void AgentServiceImpl::process_gateway_response\(const std::string& agent_id,\s*"
        r"const pb::CommandResponse& resp\) \{)",
        r"\1 (void)audit_store_->is_open();",
    ),
    # only the overflow declaration deleted (the charge still names it)
    (r"const std::string overflow = registry_audit_overflow_key\(agent_id\);", ""),
    # the rundown gate's entry deleted
    (
        r"const auto in_flight = registry_audit_gate_\.try_enter\(\);\s*if \(!in_flight\)\s*"
        r"return true;[^\n]*\n",
        "",
    ),
    # the entry moved after the weak lock: the strong reference would then die AFTER the count
    (
        r"(const auto in_flight = registry_audit_gate_\.try_enter\(\);\s*if \(!in_flight\)\s*"
        r"return true;[^\n]*\n\s*)(const auto store = registry_audit_store_\.lock\(\);)",
        "\\2\n        \\1",
    ),
    # the per-row check deleted
    (r"(?s)if \(registry_audit_gate_\.closed\(\)\) \{.*?return false;\s*\}", ""),
    # the per-row check moved before the charge
    (
        r"(?s)(const auto admit = registry_audit_budget_->try_admit\(agent_id, overflow\);.*?)"
        r"(if \(registry_audit_gate_\.closed\(\)\) \{.*?return false;\s*\})",
        "\\2\n            \\1",
    ),
    # a closed gate no longer fails the frame
    (r"(?s)(if \(registry_audit_gate_\.closed\(\)\) \{.*?)return false;", r"\1return true;"),
    # a closed gate no longer books the rows it loses
    (
        r"(?s)(if \(registry_audit_gate_\.closed\(\)\) \{.*?)book_rows\(\);(.*?return false;)",
        r"\1\2",
    ),
    # the hook closes the gate itself
    (
        r"if \(registry_audit_gate_\.closed\(\)\) \{",
        "registry_audit_gate_.close();\n            if (registry_audit_gate_.closed()) {",
    ),
    # a second reader of the weak store
    (
        r"(const auto store = registry_audit_store_\.lock\(\);)",
        r"\1 (void)registry_audit_store_.lock();",
    ),
    # the verdict outside the try
    (r"(?s)    try \{\n(        const auto frame = .*?return true;\n)", r"\1    try {\n"),
]
# Edits that must NOT be flagged: (file, pattern, replacement).
BENIGN_SERVER_EDITS = [
    # a comment naming the raw store
    (
        r"(const auto store = registry_audit_store_\.lock\(\);)",
        r"// audit_store_ is deliberately not read here\n        \1",
    ),
    # a log string naming it
    (
        r'"\[audit\] registry\.write hook threw \(agent=\{\}, command=\{\}\)"',
        '"[audit] registry.write hook threw (audit_store_ untouched; agent={}, command={})"',
    ),
    # the charge re-wrapped across lines
    (
        r"registry_audit_budget_->try_admit\(agent_id, overflow\)",
        "registry_audit_budget_->try_admit(\n                agent_id,\n                overflow)",
    ),
    # the gate entry re-wrapped across lines
    (
        r"const auto in_flight = registry_audit_gate_\.try_enter\(\);",
        "const auto in_flight =\n            registry_audit_gate_.try_enter();",
    ),
    # a comment naming what only stop() may do
    (
        r"(const auto in_flight = registry_audit_gate_\.try_enter\(\);)",
        "// registry_audit_gate_.close() is stop()'s, never the hook's\n        \\1",
    ),
]
BENIGN_MAIN_EDITS = [
    # the wiring line also kept in a comment
    (
        r"(agent_service_\.set_registry_audit_store\(audit_store_\);)",
        r"// agent_service_.set_registry_audit_store(audit_store_);\n            \1",
    ),
    # the reset also named in a comment ahead of the close
    (
        r"(agent_service_\.close_registry_audit\(\);)",
        "// audit_store_.reset(); follows the wait\n        \\1",
    ),
]
MAIN_MUTATIONS = [
    # the wiring line deleted
    (r"agent_service_\.set_registry_audit_store\(audit_store_\);", ""),
    # the gate is never closed
    (r"agent_service_\.close_registry_audit\(\);", ""),
    # the wait (and its force-exit) deleted
    (
        r"(?s)if \(!agent_service_\.wait_registry_audit_idle\(kRegistryAuditRundownBound\)\) \{"
        r".*?std::_Exit\(1\);\s*\}",
        "",
    ),
    # the close moved after the wait
    (
        r"(?s)(agent_service_\.close_registry_audit\(\);)(\s*)(if \(!agent_service_\."
        r"wait_registry_audit_idle\(kRegistryAuditRundownBound\)\) \{.*?std::_Exit\(1\);\s*\})",
        r"\3\2\1",
    ),
    # the wait moved after the reset it must precede
    (
        r"(?s)(if \(!agent_service_\.wait_registry_audit_idle\(kRegistryAuditRundownBound\)\) \{"
        r".*?std::_Exit\(1\);\s*\})(\s*)(audit_store_\.reset\(\);)",
        r"\3\2\1",
    ),
    # the force-exit removed: a timed-out wait would go on to reset
    (
        r"(?s)(wait_registry_audit_idle\(kRegistryAuditRundownBound\)\) \{.*?)std::_Exit\(1\);",
        r"\1(void)0;",
    ),
    # the wait's result ignored
    (
        r"if \(!agent_service_\.wait_registry_audit_idle\(kRegistryAuditRundownBound\)\)",
        "(void)agent_service_.wait_registry_audit_idle(kRegistryAuditRundownBound);"
        "\n        if (false)",
    ),
    # the weak pointer cleared at shutdown (a data race against lock())
    (
        r"(agent_service_\.set_registry_audit_store\(audit_store_\);)",
        r"\1\n    agent_service_.set_registry_audit_store({});",
    ),
]


class AuditActionStampWiringLexical(unittest.TestCase):
    def setUp(self):
        self.agent = AGENT.read_text(encoding="utf-8")
        self.server = SERVER.read_text(encoding="utf-8")
        self.main = MAIN.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = agent_problems(self.agent) + server_problems(self.server) + main_problems(self.main)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for label, src, muts, check in (
            ("agent.cpp", self.agent, AGENT_MUTATIONS, agent_problems),
            ("agent_service_impl.cpp", self.server, SERVER_MUTATIONS, server_problems),
            ("server.cpp", self.main, MAIN_MUTATIONS, main_problems),
        ):
            for i, (pat, repl) in enumerate(muts, 1):
                with self.subTest(file=label, mutation=i, pattern=pat):
                    mutated, n = re.subn(pat, repl, src, count=1)
                    self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                    self.assertTrue(check(mutated), "mutation was NOT detected by the gate")

    def test_benign_edits_are_not_flagged(self):
        for label, src, edits, check in (
            ("agent_service_impl.cpp", self.server, BENIGN_SERVER_EDITS, server_problems),
            ("server.cpp", self.main, BENIGN_MAIN_EDITS, main_problems),
        ):
            for i, (pat, repl) in enumerate(edits, 1):
                with self.subTest(file=label, edit=i, pattern=pat):
                    edited, n = re.subn(pat, repl, src, count=1)
                    self.assertGreaterEqual(n, 1, "benign edit changed nothing (stale pattern)")
                    self.assertEqual(check(edited), [], "a benign edit was flagged")


if __name__ == "__main__":
    unittest.main()
