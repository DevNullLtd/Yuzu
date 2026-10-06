#!/usr/bin/env python3
"""#2182 static lexical gate over agents/core/src/agent.cpp.

The #2182 primitives (OtaUpdateThread stop-then-join, CtxSlot's post-publish stop_seen()) are
unit-tested in isolation, but nothing exercises AgentImpl::run() (no seam, #1492), so a
refactor could silently stop CALLING them. This gate pins the call sites lexically. Invariants:

  1. The reconnect teardown joins the OTA thread through
     `update_thread_.stop_and_join(updater())` (stop THEN join, one tested place).
  2. The update thread is spawned through `update_thread_.start(`.
  3. Each of the four post-publish sites (heartbeat, Register, Subscribe, sync sender) builds
     its CtxSlot with the predicate ctor (`CtxSlot NAME{ctx_mu_, SLOT, &ctx, ...}`) and then
     gates a break/return on `NAME.stop_seen()` afterwards.
  4. Every teardown sets the stop flag BEFORE cancel_ctx() of the matching context:
     heartbeat_stop_ -> cancel_ctx(heartbeat_ctx_) (reconnect teardown + quiesce_run_workers),
     sync_stop_ -> cancel_ctx(sync_ctx_) (same two), and stop() cancels heartbeat, sync and
     register contexts in sequence. quiesce_run_workers() additionally must call `u->stop()`
     between the heartbeat flag and its cancel, and must end by joining
     `update_thread_.join()` after the sync thread. The post-publish predicate is only sound
     because of this flag-then-cancel order.

Robustness: `//` comments are stripped and whitespace is collapsed before matching, so line
wrapping, re-indentation and comment text mentioning a token cannot satisfy or break a check.
Patterns anchor on distinctive tokens, never line numbers.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). The self-test applies 14 in-memory mutations (10 deletions/reorders across
the invariants, plus 4 predicate-ctor arity reversions at the register, heartbeat, subscribe
and sync sites) and requires problems() to be non-empty on each; a mutation whose pattern no
longer matches agent.cpp fails loudly (stale pattern) rather than passing vacuously.

Why Python: this replaces a bash gate that forked ~500-750 grep/tr/perl/cmp processes per run
and timed out at 90 s on the Windows CI leg (#5428). This is one process, well under a second on every OS.
Two controls of the bash original have no analogue here by construction and were dropped:
the regex-error control (`re` raises at compile time, so a bad pattern is a hard error) and
the >255 repetition-bound lint (BSD RE_DUP_MAX does not apply to `re`). Their absence is not
lost coverage.
Also dropped: the AGENT_CPP path override, --self-test-only, the distinct exit code 3 and the
missing-file `::error::` line (a missing source now raises in setUp).

agent.cpp has non-ASCII lines, so it is read as UTF-8.

Usage: python3 tests/test_agent_ota_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAG = "test_agent_ota_wiring_lexical"
HINT = (
    " (this gate pins the #2182 wiring; if agent.cpp was legitimately restructured or renamed,"
    " update tests/test_agent_ota_wiring_lexical.py)"
)


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def problems(src):
    """One message per violated invariant, in invariant order; [] when clean."""
    t = normalise(src)
    out = []

    if not re.search(r"update_thread_\.stop_and_join\( ?updater\(\) ?\)", t):
        out.append("agent.cpp no longer calls update_thread_.stop_and_join(updater()) in the reconnect teardown (#2182)")
    if not re.search(r"update_thread_\.start\(", t):
        out.append("agent.cpp no longer starts the update thread via update_thread_.start( (#2182)")

    for name, ctxm in (
        ("hb_slot", "heartbeat_ctx_"),
        ("register_slot", "register_ctx_"),
        ("sub_slot", "subscribe_ctx_"),
        ("sync_slot", "sync_ctx_"),
    ):
        if not re.search("CtxSlot " + name + r" ?\{ ?ctx_mu_, ?" + ctxm + r", ?&[a-z_]*ctx, ?[^}]", t):
            out.append(f"{name} is no longer built with CtxSlot's predicate constructor "
                       f"(CtxSlot {name}{{ctx_mu_, {ctxm}, &ctx, <stop predicate>}}) (#2182)")
        if not re.search("CtxSlot " + name + r" ?\{.*if \(" + name + r"\.stop_seen\(\)\) ?(break|return)", t):
            out.append(f"{name}.stop_seen() no longer gates a break/return after publishing (#2182)")

    if len(re.findall(r"heartbeat_stop_\.store\(true, ?std::memory_order_release\); ?"
                     r"(if \(auto u = updater\(\)\) u->stop\(\); ?)?cancel_ctx\(heartbeat_ctx_\);", t)) < 2:
        out.append("expected heartbeat_stop_.store(true) immediately followed by cancel_ctx(heartbeat_ctx_) "
                   "at both the reconnect teardown and quiesce_run_workers (#2182)")
    if len(re.findall(r"sync_stop_\.store\(true, ?std::memory_order_release\); ?cancel_ctx\(sync_ctx_\);", t)) < 2:
        out.append("expected sync_stop_.store(true) immediately followed by cancel_ctx(sync_ctx_) "
                   "at both the reconnect teardown and quiesce_run_workers (#2182)")
    # The gap between the function head and the heartbeat store is [^}]* (no closing brace), so
    # the match cannot run past the function's first inner block into another copy of the sequence.
    if not re.search(r"quiesce_run_workers\(\) noexcept \{[^}]*heartbeat_stop_\.store\(true, ?std::memory_order_release\); ?"
                     r"if \(auto u = updater\(\)\) ?u->stop\(\); ?cancel_ctx\(heartbeat_ctx_\);", t):
        out.append("quiesce_run_workers() no longer calls u->stop() between heartbeat_stop_.store(true) "
                   "and cancel_ctx(heartbeat_ctx_) (#2182)")
    if not re.search(r"cancel_ctx\(sync_ctx_\); ?if \(sync_thread_\.joinable\(\)\) ?\{? ?sync_thread_\.join\(\); ?\}? ?"
                     r"update_thread_\.join\(\); ?\}", t):
        out.append("quiesce_run_workers() no longer ends with update_thread_.join() after the sync thread join (#2182)")
    if not re.search(r"cancel_ctx\(heartbeat_ctx_\); ?cancel_ctx\(sync_ctx_\); ?cancel_ctx\(register_ctx_\);", t):
        out.append("stop() no longer cancels heartbeat, sync and register contexts in sequence (#2182)")
    return out


# Each row removes one invariant from agent.cpp: (pattern, repl, flags, count, expected substring of
# the FIRST problem). count 0 = all matches, 1 = first only.
MUTATIONS = [
    (r"update_thread_\.stop_and_join\(updater\(\)\);", "update_thread_.join();", 0, 0,
     "stop_and_join"),
    (r"update_thread_\.start\(", "update_thread_.begin(", 0, 0,
     "update_thread_.start("),
    (r"hb_slot\.stop_seen\(\)", "false", 0, 0,
     "hb_slot.stop_seen()"),
    (r"CtxSlot register_slot\{ctx_mu_, register_ctx_, &ctx, \[this\] \{",
     "CtxSlot register_slot{ctx_mu_, register_ctx_, &ctx}; { ", 0, 0,
     "register_slot is no longer built"),
    (r"sub_slot\.stop_seen\(\)", "false", 0, 0,
     "sub_slot.stop_seen()"),
    (r"sync_slot\.stop_seen\(\)", "false", 0, 0,
     "sync_slot.stop_seen()"),
    (r"^( *)cancel_ctx\(register_ctx_\);", r"\g<1>(void)0;", re.M, 0,
     "stop() no longer cancels"),
    (r"^( *)cancel_ctx\(sync_ctx_\); // unblock an in-flight ReportInventory before joining", r"\g<1>(void)0;", re.M, 0,
     "sync_stop_.store(true)"),
    # quiesce_run_workers + reconnect: delete u->stop(); delete update_thread_.join()
    (r"^ *if \(auto u = updater\(\)\)\n *u->stop\(\);\n", "", re.M, 0,
     "u->stop() between"),
    (r"^( *)update_thread_\.join\(\);", r"\g<1>(void)0;", re.M, 0,
     "update_thread_.join() after"),
    # reorder: heartbeat flag store AFTER its cancel_ctx at the reconnect teardown
    (r"^( *)(heartbeat_stop_\.store\(true, std::memory_order_release\);)\n( *cancel_ctx\(heartbeat_ctx_\);)$",
     r"\g<3>\n\g<1>\g<2>", re.M, 0,
     "heartbeat_stop_.store(true)"),
    # predicate ctor reverted to the 3-arg form (hb, sub, sync)
    (r"(CtxSlot hb_slot\{ctx_mu_, heartbeat_ctx_, &ctx),\s*\[&should_stop\] \{ return should_stop\(\); \}\}", r"\g<1>}", 0, 1,
     "hb_slot is no longer built"),
    (r"(CtxSlot sub_slot\{ctx_mu_, subscribe_ctx_, &sub_ctx),\s*\[this\] \{.*?\}\}", r"\g<1>}", re.S, 1,
     "sub_slot is no longer built"),
    (r"(CtxSlot sync_slot\{ctx_mu_, sync_ctx_, &ctx),\s*\[this\] \{.*?\}\}", r"\g<1>}", re.S, 1,
     "sync_slot is no longer built"),
]


class AgentOtaWiringLexical(unittest.TestCase):
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
