#!/usr/bin/env python3
"""Static lexical gate over agents/plugins/echo/src/echo_plugin.cpp: the slow-tick storage-offline tag reconcile.

#8099: a database closed at run time by a failed ROLLBACK is published as storage offline with the
reason `rollback_wedged`, by the reconcile block at the top of EchoPlugin::do_collect_slow. The
decision (yuzu::echo::online_offline_tag_action) and the store seam are unit-tested, but EchoPlugin
is TU-local and the wedge cannot be forced inside the loaded plugin without a test knob in shipped
code, so the SHELL that calls the decision and publishes or clears the tag is reachable by no test:
deleting the call, swapping its arguments, or moving it after the collect would stay green. This
gate pins the shell lexically. Invariants inside the do_collect_slow body, anchored on tokens
(never line numbers):

  1. `store_open` is `db_->is_open()` and `key_present` is `pctx.storage_exists(kStorageOfflineKey)`.
  2. `switch (online_offline_tag_action(store_open, key_present, <the key's value or empty>))`.
  3. The `publish_wedged` case calls `pctx.storage_set(kStorageOfflineKey, kRollbackWedgedToken)`.
  4. The `clear` case calls `pctx.storage_delete(kStorageOfflineKey)`.
  5. The switch comes before `retry_pending_mapdrive_backfill();` and `collect_slow_impl(`: a
     reconcile placed after them would not run while a long collect or a backfill retry holds the tick.

`//` and `/* */` comments are stripped and whitespace collapsed before matching. Lexical only: it
cannot see a relocation that keeps the tokens in order but changes control flow (review-enforced).
The self-test applies in-memory mutations inside the function and requires problems() to be
non-empty on each; a mutation whose pattern no longer matches fails loudly (stale pattern).

Usage: python3 tests/test_echo_storage_offline_reconcile_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "agents" / "plugins" / "echo" / "src" / "echo_plugin.cpp"
HINT = " (update tests/test_echo_storage_offline_reconcile_lexical.py only if echo_plugin.cpp was legitimately restructured)"

FN = r"int do_collect_slow\( ?yuzu::CommandContext& ctx ?\) \{"
KEY = r"yuzu::echo::kStorageOfflineKey"
TOKEN = r"yuzu::echo::kRollbackWedgedToken"
ACTION = r"yuzu::echo::OfflineTagAction::"
STORE_OPEN = r"const bool store_open = db_->is_open\(\);"
KEY_PRESENT = r"const bool key_present = pctx\.storage_exists\( ?" + KEY + r" ?\);"
SWITCH = (r"switch \( ?yuzu::echo::online_offline_tag_action\( ?store_open, ?key_present, ?key_present \? "
          r"pctx\.storage_get\( ?" + KEY + r" ?\) : std::string\{\} ?\) ?\)")
PUBLISH = r"pctx\.storage_set\( ?" + KEY + r", ?" + TOKEN + r" ?\)"
CLEAR = r"pctx\.storage_delete\( ?" + KEY + r" ?\)"

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


def function_body(t):
    """The text between the braces of do_collect_slow, or None. Literals are masked (same length)
    only for the brace walk, so a brace inside a log message cannot end the body early."""
    starts = [m.end() for m in re.finditer(FN, t)]
    if len(starts) != 1:
        return None
    masked = _TOKEN.sub(lambda m: '"' + "x" * (len(m.group(0)) - 2) + '"', t)
    depth = 1
    for i in range(starts[0], len(masked)):
        depth += (masked[i] == "{") - (masked[i] == "}")
        if depth == 0:
            return t[starts[0]:i]
    return None


def problems(src):
    body = function_body(normalise(src))
    if body is None:
        return ["echo_plugin.cpp no longer contains exactly one `int do_collect_slow(yuzu::CommandContext& ctx) {`"]
    out = []
    for rx, what in ((STORE_OPEN, "`const bool store_open = db_->is_open();`"),
                     (KEY_PRESENT, "`const bool key_present = pctx.storage_exists(kStorageOfflineKey);`")):
        if len(re.findall(rx, body)) != 1:
            out.append(f"do_collect_slow no longer contains exactly one {what}")
    call = list(re.finditer(SWITCH, body))
    if len(call) != 1:
        out.append("do_collect_slow no longer contains exactly one `switch (online_offline_tag_action("
                   "store_open, key_present, key_present ? pctx.storage_get(kStorageOfflineKey) : std::string{}))`")
        return out
    labels = list(re.finditer(r"case " + ACTION + r"(\w+) ?:", body))
    sections = {m.group(1): body[m.end():(labels[i + 1].start() if i + 1 < len(labels) else len(body))]
                for i, m in enumerate(labels)}
    for case, rx, what in (("publish_wedged", PUBLISH, "pctx.storage_set(kStorageOfflineKey, kRollbackWedgedToken)"),
                           ("clear", CLEAR, "pctx.storage_delete(kStorageOfflineKey)")):
        if case not in sections:
            out.append(f"the switch no longer has `case OfflineTagAction::{case}:`")
        elif not re.search(rx, sections[case]):
            out.append(f"`case OfflineTagAction::{case}:` no longer calls {what}")
    for rx, after in ((r"retry_pending_mapdrive_backfill\( ?\);", "retry_pending_mapdrive_backfill();"),
                      (r"collect_slow_impl\(", "collect_slow_impl(")):
        later = re.search(rx, body)
        if not later:
            out.append(f"do_collect_slow no longer contains {after}")
        elif later.start() < call[0].start():
            out.append(f"the storage-offline reconcile must run before {after}")
    return out


# (pattern, replacement, expected substring of the first problem). Applied to the first match at or
# after do_collect_slow's definition, so a same-text call elsewhere in the file is never the target.
MUTATIONS = [
    (r"yuzu::echo::online_offline_tag_action\(", "yuzu::echo::online_offline_tag_action_x(", "exactly one `switch"),
    (r"store_open,\s*key_present,", "key_present, store_open,", "exactly one `switch"),
    (r"const bool store_open = db_->is_open\(\);", "const bool store_open = true;", "store_open = db_->is_open()"),
    (r"const bool key_present = pctx\.storage_exists\(" + KEY + r"\);", "const bool key_present = false;",
     "key_present = pctx.storage_exists"),
    (r"pctx\.storage_get\(" + KEY + r"\)", 'std::string{"x"}', "exactly one `switch"),
    (r"pctx\.storage_set\(" + KEY + r",\s*" + TOKEN + r"\)", 'pctx.storage_set(' + KEY + ', "other")',
     "publish_wedged"),
    (r"pctx\.storage_set\(", "pctx.storage_set_x(", "publish_wedged"),
    (r"pctx\.storage_delete\(", "pctx.storage_delete_x(", "clear"),
    (r"pctx\.storage_delete\(" + KEY + r"\)", "pctx.storage_set(" + KEY + ", " + TOKEN + ")", "clear"),
    (r"case " + ACTION + r"publish_wedged:", "case " + ACTION + "leave:", "publish_wedged"),
    (r"(?=const bool key_present)", "retry_pending_mapdrive_backfill(); ", "before retry_pending_mapdrive_backfill"),
    (r"(?=const bool key_present)", "std::lock_guard lock(collect_mu_); return collect_slow_impl(ctx); ",
     "before collect_slow_impl"),
    (r"retry_pending_mapdrive_backfill\(\);", "", "no longer contains retry_pending_mapdrive_backfill"),
    (r"return collect_slow_impl\(ctx\);", "return 0;", "no longer contains collect_slow_impl"),
]


def mutate(raw, pat, repl):
    start = raw.index("int do_collect_slow(")
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
        for i, (pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = mutate(self.raw, pat, repl)
                self.assertEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
