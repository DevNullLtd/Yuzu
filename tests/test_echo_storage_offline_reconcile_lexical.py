#!/usr/bin/env python3
"""Static lexical gate over agents/plugins/echo/src/echo_plugin.cpp: the storage-offline shell wiring.

#8099: a database closed at run time by a failed ROLLBACK is published as storage offline with the
reason `rollback_wedged`, by the reconcile block at the top of EchoPlugin::do_collect_slow, and the
actions that would answer wrongly on that store are refused (yuzu::echo::refused_on_closed_store).
The decisions (online_offline_tag_action, format_closed_store_refusal) and the store seam are
unit-tested, but EchoPlugin is TU-local and the wedge cannot be forced inside the loaded plugin
without a test knob in shipped code, so the SHELL that calls them is reachable by no test: deleting
a call, swapping its arguments, or moving it after the collect would stay green. This gate pins the
shell lexically. Invariants, anchored on tokens (never line numbers):

  do_collect_slow:
  1. `store_open` is `db_->is_open()` and `key_present` is `pctx.storage_exists(kStorageOfflineKey)`.
  2. `switch (online_offline_tag_action(store_open, key_present, <the key's value or empty>))`.
  3. The `publish_wedged` case calls `pctx.storage_set(kStorageOfflineKey, kRollbackWedgedToken)`.
  4. The `clear` case calls `pctx.storage_delete(kStorageOfflineKey)`.
  5. The switch comes before `retry_pending_mapdrive_backfill();` and `collect_slow_impl(`: a
     reconcile placed after them would not run while a long collect or a backfill retry holds the tick.
  6. A null `db_` returns (an error line and 1) BEFORE the reconcile reads it: a null store read as
     closed would publish `rollback_wedged`.
  7. `refuse_on_closed_store(ctx, "collect_slow")` returns 1 AFTER the switch (a closed store still
     publishes its tag) and BEFORE the backfill retry and the collect.

  execute_dispatch:
  8. `collect_slow` is routed to do_collect_slow first, then `refuse_on_closed_store(ctx, action)`
     returns 1, then the rest of the chain starts with `collect_fast`.

The cross-side check compares the reason tokens of the agent header with the server's closed label
set, so a rename on one side only fails here instead of surfacing as reason=unknown in production.

`//` and `/* */` comments are stripped and whitespace collapsed before matching. Lexical only: it
cannot see a relocation that keeps the tokens in order but changes control flow (review-enforced).
The self-test applies in-memory mutations inside each function and requires problems() to be
non-empty on each; a mutation whose pattern no longer matches fails loudly (stale pattern).

Usage: python3 tests/test_echo_storage_offline_reconcile_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "agents" / "plugins" / "echo" / "src" / "echo_plugin.cpp"
AGENT_HDR = (Path(__file__).resolve().parent.parent / "agents" / "plugins" / "echo" / "src"
             / "echo_status_format.hpp")
SERVER_HDR = Path(__file__).resolve().parent.parent / "server" / "core" / "src" / "echo_storage_offline_tag.hpp"
HINT = " (update tests/test_echo_storage_offline_reconcile_lexical.py only if echo_plugin.cpp was legitimately restructured)"

FN = r"\bint do_collect_slow\( ?yuzu::CommandContext& ctx ?\) \{"
DISPATCH_FN = (r"\bint execute_dispatch\( ?yuzu::CommandContext& ctx, std::string_view action, "
               r"yuzu::Params params ?\) \{")
KEY = r"yuzu::echo::kStorageOfflineKey"
TOKEN = r"yuzu::echo::kRollbackWedgedToken"
ACTION = r"yuzu::echo::OfflineTagAction::"
STORE_OPEN = r"\bconst bool store_open = db_->is_open\(\);"
KEY_PRESENT = r"\bconst bool key_present = pctx\.storage_exists\( ?" + KEY + r" ?\);"
SWITCH = (r"\bswitch \( ?yuzu::echo::online_offline_tag_action\( ?store_open, ?key_present, ?key_present \? "
          r"pctx\.storage_get\( ?" + KEY + r" ?\) : std::string\{\} ?\) ?\)")
PUBLISH = r"\bpctx\.storage_set\( ?" + KEY + r", ?" + TOKEN + r" ?\)"
CLEAR = r"\bpctx\.storage_delete\( ?" + KEY + r" ?\)"
NULL_GUARD = r"\bif \( ?!db_ ?\) \{ ctx\.write_output\( ?\"error\|Echo database not initialized\" ?\); return 1; \}"
REFUSE_SLOW = r"\bif \( ?refuse_on_closed_store\( ?ctx, ?\"collect_slow\" ?\) ?\) return 1;"
DISPATCH_SEQ = (r"\bif \( ?action == \"collect_slow\" ?\) return do_collect_slow\( ?ctx ?\); "
                r"if \( ?refuse_on_closed_store\( ?ctx, ?action ?\) ?\) return 1; "
                r"if \( ?action == \"collect_fast\" ?\) return do_collect_fast\( ?ctx ?\);")

_TOKEN = re.compile(
    r'"(?:\\.|[^"\\\n])*"'      # string literal: kept verbatim
    r"|'(?:\\.|[^'\\\n])'"      # char literal: kept verbatim
    r"|//[^\n]*"                  # line comment: dropped
    r"|/\*.*?\*/",                # block comment: dropped
    re.S,
)


def normalise(src):
    """Drop comments in source order (string and char literals stay intact), collapse whitespace."""
    t = _TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", src)
    return re.sub(r"[ \t\n\r\f\v]+", " ", t)


def balanced(t, start):
    """The text from `start` (just past an opening brace) up to its matching closing brace, or None.
    Literals are masked (same length) only for the brace walk, so a brace inside a log message
    cannot end the block early."""
    masked = _TOKEN.sub(lambda m: '"' + "x" * (len(m.group(0)) - 2) + '"', t)
    depth = 1
    for i in range(start, len(masked)):
        depth += (masked[i] == "{") - (masked[i] == "}")
        if depth == 0:
            return t[start:i]
    return None


def function_body(t, fn):
    """The text between the braces of the single function matching `fn`, or None."""
    starts = [m.end() for m in re.finditer(fn, t)]
    return balanced(t, starts[0]) if len(starts) == 1 else None


def collect_slow_problems(src):
    body = function_body(normalise(src), FN)
    if body is None:
        return ["echo_plugin.cpp no longer contains exactly one `int do_collect_slow(yuzu::CommandContext& ctx) {`"]
    out = []
    for rx, what in ((STORE_OPEN, "`const bool store_open = db_->is_open();`"),
                     (KEY_PRESENT, "`const bool key_present = pctx.storage_exists(kStorageOfflineKey);`")):
        if len(re.findall(rx, body)) != 1:
            out.append(f"do_collect_slow no longer contains exactly one {what}")
    guard = list(re.finditer(NULL_GUARD, body))
    first_read = re.search(STORE_OPEN, body)
    if len(guard) != 1:
        out.append("do_collect_slow no longer returns early on a null `db_` "
                   "(`if (!db_) { ctx.write_output(\"error|Echo database not initialized\"); return 1; }`)")
    elif first_read and guard[0].start() > first_read.start():
        out.append("the null `db_` return must come before the reconcile reads the store")
    call = list(re.finditer(SWITCH, body))
    if len(call) != 1:
        out.append("do_collect_slow no longer contains exactly one `switch (online_offline_tag_action("
                   "store_open, key_present, key_present ? pctx.storage_get(kStorageOfflineKey) : std::string{}))`")
        return out
    # The case labels of THIS switch only: the walk starts at its opening brace.
    brace = body.index("{", call[0].end())
    switch_body = balanced(body, brace + 1) or ""
    labels = list(re.finditer(r"\bcase " + ACTION + r"(\w+) ?:", switch_body))
    sections = {m.group(1): switch_body[m.end():(labels[i + 1].start() if i + 1 < len(labels) else len(switch_body))]
                for i, m in enumerate(labels)}
    for case, rx, what in (("publish_wedged", PUBLISH, "pctx.storage_set(kStorageOfflineKey, kRollbackWedgedToken)"),
                           ("clear", CLEAR, "pctx.storage_delete(kStorageOfflineKey)")):
        if case not in sections:
            out.append(f"the switch no longer has `case OfflineTagAction::{case}:`")
        elif not re.search(rx, sections[case]):
            out.append(f"`case OfflineTagAction::{case}:` no longer calls {what}")
    switch_end = brace + 1 + len(switch_body)
    refusal = list(re.finditer(REFUSE_SLOW, body))
    if len(refusal) != 1:
        out.append("do_collect_slow no longer contains exactly one "
                   "`if (refuse_on_closed_store(ctx, \"collect_slow\")) return 1;`")
    elif refusal[0].start() < switch_end:
        out.append("the closed-store refusal must run after the storage-offline reconcile (a closed store "
                   "still publishes its tag)")
    for rx, after in ((r"\bretry_pending_mapdrive_backfill\( ?\);", "retry_pending_mapdrive_backfill();"),
                      (r"\bcollect_slow_impl\(", "collect_slow_impl(")):
        later = re.search(rx, body)
        if not later:
            out.append(f"do_collect_slow no longer contains {after}")
        elif later.start() < call[0].start():
            out.append(f"the storage-offline reconcile must run before {after}")
        elif len(refusal) == 1 and later.start() < refusal[0].start():
            out.append(f"the closed-store refusal must run before {after}")
    return out


def dispatch_problems(src):
    body = function_body(normalise(src), DISPATCH_FN)
    if body is None:
        return ["echo_plugin.cpp no longer contains exactly one `int execute_dispatch(...) {`"]
    if len(re.findall(DISPATCH_SEQ, body)) != 1:
        return ["execute_dispatch no longer routes `collect_slow` to do_collect_slow first, then "
                "`if (refuse_on_closed_store(ctx, action)) return 1;`, then the rest of the chain from `collect_fast`"]
    return []


def token_parity_problems(agent_src, server_src):
    """The agent's offline_reason_token() literals against the server's closed label set."""
    consts = dict(re.findall(r'inline constexpr std::string_view (\w+) = "([^"]*)";', agent_src))
    fn = re.search(r"offline_reason_token\(OfflineReason reason\) noexcept \{(.*?)\n\}", agent_src, re.S)
    if not fn:
        return ["echo_status_format.hpp no longer defines offline_reason_token(OfflineReason reason) noexcept"]
    agent = set()
    for _, ret in re.findall(r"case OfflineReason::(\w+):\s*return ([^;]+);", fn.group(1)):
        ret = ret.strip()
        value = ret[1:-1] if ret.startswith('"') else consts.get(ret)
        if value is None:
            return [f"offline_reason_token returns `{ret}`, which is neither a literal nor a string constant here"]
        agent.add(value)
    arr = re.search(r"kEchoStorageOfflineReasons\{([^}]*)\}", server_src)
    if not arr:
        return ["echo_storage_offline_tag.hpp no longer defines kEchoStorageOfflineReasons{...}"]
    server = re.findall(r'"([^"]*)"', arr.group(1))
    out = []
    if not server or server[-1] != "unknown":
        out.append("the server's closed label set must end with `unknown`")
    if set(server[:-1]) != agent:
        out.append(f"the agent's reason tokens {sorted(agent)} differ from the server's {sorted(server[:-1])}: "
                   "a one-sided rename publishes reason=unknown")
    if "unknown" in agent:
        out.append("the agent must never publish the server's catch-all `unknown`")
    return out


def problems(src):
    return collect_slow_problems(src) + dispatch_problems(src)


def _move_refusal_before_switch(tail):
    m = re.search(r'if \(refuse_on_closed_store\(ctx, "collect_slow"\)\)\s*return 1;', tail)
    if not m:
        return tail, 0
    rest = tail[:m.start()] + tail[m.end():]
    k = rest.index("const bool key_present")
    return rest[:k] + m.group(0) + " " + rest[k:], 1


def _move_guard_after_read(tail):
    m = re.search(r'if \(!db_\) \{\s*ctx\.write_output\("error\|Echo database not initialized"\);\s*return 1;\s*\}', tail)
    if not m:
        return tail, 0
    rest = tail[:m.start()] + tail[m.end():]
    k = rest.index("db_->is_open();") + len("db_->is_open();")
    return rest[:k] + " " + m.group(0) + rest[k:], 1


def _swap_dispatch_order(tail):
    a = re.search(r'if \(action == "collect_slow"\)\s*return do_collect_slow\(ctx\);', tail)
    b = re.search(r'if \(refuse_on_closed_store\(ctx, action\)\)\s*return 1;', tail)
    if not (a and b and a.start() < b.start()):
        return tail, 0
    return (tail[:a.start()] + b.group(0) + " " + a.group(0) + tail[b.end():], 1)


# (anchor function, pattern or callable, replacement, expected substring of the first problem). Applied
# to the first match at or after the anchor function's definition, so a same-text call elsewhere in
# the file is never the target.
SLOW, DISPATCH = "int do_collect_slow(", "int execute_dispatch("
MUTATIONS = [
    (SLOW, r"yuzu::echo::online_offline_tag_action\(", "yuzu::echo::online_offline_tag_action_x(", "exactly one `switch"),
    (SLOW, r"store_open,\s*key_present,", "key_present, store_open,", "exactly one `switch"),
    (SLOW, r"const bool store_open = db_->is_open\(\);", "const bool store_open = true;", "store_open = db_->is_open()"),
    (SLOW, r"const bool key_present = pctx\.storage_exists\(" + KEY + r"\);", "const bool key_present = false;",
     "key_present = pctx.storage_exists"),
    (SLOW, r"pctx\.storage_get\(" + KEY + r"\)", 'std::string{"x"}', "exactly one `switch"),
    (SLOW, r"pctx\.storage_set\(" + KEY + r",\s*" + TOKEN + r"\)", 'pctx.storage_set(' + KEY + ', "other")',
     "publish_wedged"),
    (SLOW, r"pctx\.storage_set\(", "pctx.storage_set_x(", "publish_wedged"),
    (SLOW, r"pctx\.storage_delete\(", "pctx.storage_delete_x(", "clear"),
    (SLOW, r"pctx\.storage_delete\(" + KEY + r"\)", "pctx.storage_set(" + KEY + ", " + TOKEN + ")", "clear"),
    (SLOW, r"case " + ACTION + r"publish_wedged:", "case " + ACTION + "leave:", "publish_wedged"),
    (SLOW, r"(?=const bool key_present)", "retry_pending_mapdrive_backfill(); ", "before retry_pending_mapdrive_backfill"),
    (SLOW, r"(?=const bool key_present)", "std::lock_guard lock(collect_mu_); return collect_slow_impl(ctx); ",
     "before collect_slow_impl"),
    (SLOW, r"retry_pending_mapdrive_backfill\(\);", "", "no longer contains retry_pending_mapdrive_backfill"),
    (SLOW, r"return collect_slow_impl\(ctx\);", "return 0;", "no longer contains collect_slow_impl"),
    # the null-store return
    (SLOW, r'if \(!db_\) \{\s*ctx\.write_output\("error\|Echo database not initialized"\);\s*return 1;\s*\}', "",
     "null `db_`"),
    (SLOW, r'ctx\.write_output\("error\|Echo database not initialized"\);\s*return 1;\s*\}',
     'ctx.write_output("error|Echo database not initialized");\n        }', "null `db_`"),
    (SLOW, _move_guard_after_read, None, "before the reconcile reads the store"),
    # the closed-store refusal
    (SLOW, r'if \(refuse_on_closed_store\(ctx, "collect_slow"\)\)\s*return 1;', "", "exactly one `if (refuse_on_closed_store"),
    (SLOW, r'refuse_on_closed_store\(ctx, "collect_slow"\)', 'refuse_on_closed_store(ctx, "collect_fast")',
     "exactly one `if (refuse_on_closed_store"),
    (SLOW, r'(if \(refuse_on_closed_store\(ctx, "collect_slow"\)\))\s*return 1;', r"\1 return 0;",
     "exactly one `if (refuse_on_closed_store"),
    (SLOW, _move_refusal_before_switch, None, "after the storage-offline reconcile"),
    # the dispatch order
    (DISPATCH, r'if \(refuse_on_closed_store\(ctx, action\)\)\s*return 1;', "", "execute_dispatch"),
    (DISPATCH, r'refuse_on_closed_store\(ctx, action\)', 'refuse_on_closed_store(ctx, "status")', "execute_dispatch"),
    (DISPATCH, r'if \(action == "collect_slow"\)\s*return do_collect_slow\(ctx\);', "", "execute_dispatch"),
    (DISPATCH, _swap_dispatch_order, None, "execute_dispatch"),
]


def mutate(raw, anchor, pat, repl):
    start = raw.index(anchor)
    if callable(pat):
        tail, n = pat(raw[start:])
    else:
        tail, n = re.subn(pat, repl, raw[start:], count=1)
    return raw[:start] + tail, n


class EchoStorageOfflineReconcileLexical(unittest.TestCase):
    def setUp(self):
        self.raw = SRC.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::test_echo_storage_offline_reconcile_lexical: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (anchor, pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=getattr(pat, "__name__", pat)):
                mutated, n = mutate(self.raw, anchor, pat, repl)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


class EchoOfflineTokenParity(unittest.TestCase):
    """The agent's reason tokens and the server's gauge label set are duplicated literals with no
    shared header; each side has a one-sided pin, and this compares the two (a rename on one side only
    would otherwise publish reason=unknown in production)."""

    def setUp(self):
        self.agent = AGENT_HDR.read_text(encoding="utf-8")
        self.server = SERVER_HDR.read_text(encoding="utf-8")

    def test_tokens_agree(self):
        p = token_parity_problems(self.agent, self.server)
        for m in p:
            print(f"\n::error::test_echo_storage_offline_reconcile_lexical: {m}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_one_sided_rename_is_caught(self):
        for what, agent, server in (
            ("agent renamed", self.agent.replace('return "open_failed";', 'return "open_error";'), self.server),
            ("server renamed", self.agent, self.server.replace('"rollback_wedged"', '"rollback_stuck"')),
            ("server drops one", self.agent, self.server.replace('"free_space", ', "")),
            ("catch-all not last", self.agent, self.server.replace('"rollback_wedged", "unknown"',
                                                                     '"unknown", "rollback_wedged"')),
        ):
            with self.subTest(what):
                self.assertNotEqual((agent, server), (self.agent, self.server), "mutation changed nothing")
                self.assertTrue(token_parity_problems(agent, server))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
