#!/usr/bin/env python3
"""Static lexical gate over agents/core/src/agent.cpp: the installed-software worker drain.

The installed_software collector runs each plugin action on a bounded DETACHED worker
(agents/shared/bounded_wait.hpp), and a worker abandoned at its time limit may still be inside a
plugin's dispatcher when the agent tears down. The unit tests (tests/unit/test_inventory_sync.cpp)
cover the drain helper itself, but nothing runs the teardown in agent.cpp, so removing or
reordering the call compiles and every behavioural test stays green while plugins are shut down
(and dlclose'd) under a live worker. This gate pins the three facts the helper's safety rests on:

  1. `drain_detached_collectors_or_exit()` runs on BOTH teardown paths (the Run() ScopeExit and the
     reconnect-loop normal exit), after `quiesce_run_workers()` and before `trigger_engine_.stop()`
     and the plugin shutdown loop.
  2. The source factory receives the AGENT-owned `collector_workers_`, not a private object.
  3. `collector_workers_` is a class-scope member created once. The factory runs inside the
     per-CONNECTION sync thread, so a worker object created there would be rebuilt on every
     reconnect while a worker from the previous connection is still inside a plugin.
It also pins the heartbeat call site of `emit_sync_completeness_unknown_tag(tags, sync_kv);` and the
helper's own body: the unit test injects its own exit callback, so nothing else observes that the
helper really calls `hard_exit(3)` on both its over-grace and its could-not-check paths, with the
`kOrphanDrainGrace` grace.

Lexical only: it cannot see a relocation that keeps the tokens but changes control flow
(review-enforced). agent.cpp has non-ASCII lines, so it is read as UTF-8.
Usage: python3 tests/test_installed_software_drain_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
TAG = "test_installed_software_drain_wiring_lexical"
HINT = (
    " (this gate pins the installed-software worker drain wiring; if agent.cpp was legitimately"
    " restructured or renamed, update the patterns AND the MUTATIONS patterns in"
    " tests/test_installed_software_drain_wiring_lexical.py)"
)

QUIESCE = r"quiesce_run_workers\( ?\);"
DRAIN = r"drain_detached_collectors_or_exit\( ?\);"
STOP = r"trigger_engine_\.stop\( ?\);"
SKIP_TAGS = r"emit_sync_skip_tags\("
UNKNOWN_TAG = r"emit_sync_completeness_unknown_tag\( ?tags, ?sync_kv ?\);"
HELPER = re.compile(r"void\s+drain_detached_collectors_or_exit\(\s*\)\s*noexcept\s*\{")
# One token at a time through the helper: a // comment or a string literal is skipped whole so a
# brace inside either never moves the depth.
HELPER_TOKEN = re.compile(r'//[^\n]*|"(?:\\.|[^"\\\n])*"|[{}]')


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


def helper_body(src):
    """The text of drain_detached_collectors_or_exit() between its braces, // comments removed and
    whitespace collapsed (a brace-match on the RAW text: the helper moves within the class, so no
    neighbouring declaration anchors it); None when the helper is absent."""
    m = HELPER.search(src)
    if not m:
        return None
    depth = 1
    for tok in HELPER_TOKEN.finditer(src, m.end()):
        depth += (tok.group() == "{") - (tok.group() == "}")
        if depth == 0:
            return normalise(src[m.end():tok.start()])
    return None


def problems(src):
    """One message per violated invariant, in invariant order; [] when clean."""
    t = normalise(src)
    out = []

    # 1. Both teardown paths: quiesce -> drain -> trigger_engine_.stop(), nothing that tears a
    #    plugin down in between. The call statement (`name( );`) never matches the helper's
    #    definition (`void name() noexcept {`).
    quiesces = list(re.finditer(QUIESCE, t))
    if len(quiesces) != 2:
        out.append(f"agent.cpp has {len(quiesces)} `quiesce_run_workers();` calls, expected exactly "
                   "two (the Run() ScopeExit and the reconnect-loop teardown)")
    for n, m in enumerate(quiesces, 1):
        stop = re.search(STOP, t[m.end():])
        if not stop:
            out.append(f"teardown path {n}: no `trigger_engine_.stop();` follows `quiesce_run_workers();`")
            continue
        between = t[m.end():m.end() + stop.start()]
        if len(re.findall(DRAIN, between)) != 1:
            out.append(f"teardown path {n}: `drain_detached_collectors_or_exit();` is not called "
                       "exactly once between `quiesce_run_workers();` and `trigger_engine_.stop();`")
        if re.search(r"shutdown\(|plugins_\.clear\(", between):
            out.append(f"teardown path {n}: a plugin is shut down or cleared before "
                       "`trigger_engine_.stop();` (and so before the drain)")
    if len(re.findall(DRAIN, t)) != 2:
        out.append("`drain_detached_collectors_or_exit();` is not called exactly twice")

    # 2. The factory is handed the agent-owned workers.
    if not re.search(
            r"make_installed_software_source\( ?sync_plugins, ?kv_get, ?kv_set, ?collector_workers_ ?\)", t):
        out.append("make_installed_software_source no longer receives "
                   "(sync_plugins, kv_get, kv_set, collector_workers_)")

    # 3. The workers object is one class-scope member (4-space indent, matched on the RAW text so
    #    a same-named local inside the sync thread's lambda cannot satisfy it) and is made once.
    if len(re.findall(r"(?m)^    std::shared_ptr<CollectorWorkers> collector_workers_\b", src)) != 1:
        out.append("`std::shared_ptr<CollectorWorkers> collector_workers_` is no longer declared "
                   "exactly once as a class-scope member")
    if len(re.findall(r"make_shared<CollectorWorkers>", t)) != 1:
        out.append("CollectorWorkers is not created exactly once (a per-connection object would "
                   "be rebuilt on every reconnect)")

    # 4. The heartbeat block publishes the unknown-completeness tag beside the skip tags; this is
    #    the tag's only production call, so deleting it leaves every behavioural test green.
    skip = re.search(SKIP_TAGS, t)
    if len(re.findall(UNKNOWN_TAG, t)) != 1 or not skip or not re.search(UNKNOWN_TAG, t[skip.end():]):
        out.append("`emit_sync_completeness_unknown_tag(tags, sync_kv);` is not called exactly once "
                   "in the heartbeat block after `emit_sync_skip_tags(`")

    # 5. The helper's body: both exits, and the grace the drain waits.
    body = helper_body(src)
    if body is None:
        out.append("`void drain_detached_collectors_or_exit() noexcept {` is not defined")
        return out
    if len(re.findall(r"yuzu::agent::hard_exit\(3\)", body)) != 2:
        out.append("drain_detached_collectors_or_exit() does not contain exactly two "
                   "`yuzu::agent::hard_exit(3)` calls (the over-grace callback and the catch-all)")
    call = re.findall(r"drain_collector_workers\( ?\*collector_workers_,([^\[]*)\[", body)
    if len(call) != 1 or "kOrphanDrainGrace" not in call[0]:
        out.append("drain_detached_collectors_or_exit() does not call drain_collector_workers("
                   "*collector_workers_, <grace>, ...) exactly once with `kOrphanDrainGrace` as the grace")
    if not re.search(r"hard_exit\(3\); ?\} ?\); ?\} ?catch", body):
        out.append("drain_detached_collectors_or_exit(): the over-grace callback no longer ends in "
                   "`yuzu::agent::hard_exit(3);`")
    if not re.search(r"catch ?\(\.\.\.\) ?\{ ?yuzu::agent::hard_exit\(3\);[^;]*\} ?$", body):
        out.append("drain_detached_collectors_or_exit(): the catch-all no longer ends the helper in "
                   "`yuzu::agent::hard_exit(3);` (fail closed)")
    return out


# Each row damages one invariant: (pattern, repl, flags, count, expected substring of the FIRST
# problem). The patterns match the raw agent.cpp.
MUTATIONS = [
    # 1. the drain removed from the first teardown path
    (r"drain_detached_collectors_or_exit\(\);", "", 0, 1,
     "is not called exactly once between"),
    # 2. the drain moved after the trigger engine stop on the first path
    (r"(drain_detached_collectors_or_exit\(\);)(.*?)(trigger_engine_\.stop\(\);)", r"\g<2>\g<3> \g<1>",
     re.S, 1, "is not called exactly once between"),
    # 3. a plugin shutdown wedged before the drain
    (r"(quiesce_run_workers\(\);)", r"\g<1> plugins_.clear();", 0, 1,
     "a plugin is shut down or cleared"),
    # 4. a third quiesce call (a new teardown path without the drain)
    (r"(quiesce_run_workers\(\);)", r"\g<1> quiesce_run_workers();", 0, 1,
     "expected exactly two"),
    # 5. the factory handed a private workers object
    (r"kv_set, collector_workers_\)", "kv_set, std::make_shared<CollectorWorkers>())", 0, 1,
     "no longer receives"),
    # 6. the member re-declared as a local (deeper indent)
    (r"(?m)^    std::shared_ptr<CollectorWorkers> collector_workers_",
     "                    std::shared_ptr<CollectorWorkers> collector_workers_", 0, 1,
     "class-scope member"),
    # 7. a second CollectorWorkers created (the per-connection bug)
    (r"make_installed_software_source\(",
     "(void)std::make_shared<CollectorWorkers>(); make_installed_software_source(", 0, 1,
     "created exactly once"),
    # 8. the heartbeat tag call deleted
    (r"yuzu::agent::emit_sync_completeness_unknown_tag\(tags, sync_kv\);", "", 0, 1,
     "heartbeat block after"),
    # 9-11. the helper's two exits and its grace, scoped to the helper so another hard_exit(3) in
    #       agent.cpp can never stand in for one of them
    (r"(void drain_detached_collectors_or_exit\(\) noexcept \{.*?)yuzu::agent::hard_exit\(3\);",
     r"\g<1>(void)0;", re.S, 1, "exactly two `yuzu::agent::hard_exit(3)`"),
    (r"(void drain_detached_collectors_or_exit\(\) noexcept \{.*?\} catch \(\.\.\.\) \{\s*)"
     r"yuzu::agent::hard_exit\(3\);", r"\g<1>(void)0;", re.S, 1, "exactly two `yuzu::agent::hard_exit(3)`"),
    (r"(void drain_detached_collectors_or_exit\(\) noexcept \{.*?duration_cast<std::chrono::milliseconds>\("
     r"\s*)yuzu::agent::kOrphanDrainGrace", r"\g<1>std::chrono::seconds{0}", re.S, 1,
     "`kOrphanDrainGrace` as the grace"),
]


class InstalledSoftwareDrainWiringLexical(unittest.TestCase):
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
                self.assertTrue(any(expected in m for m in p),
                                f"expected a problem containing {expected!r}, got {p}")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
