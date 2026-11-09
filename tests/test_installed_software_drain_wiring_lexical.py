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


def normalise(src):
    """Strip // comments, join lines, collapse whitespace (/* */ deliberately not stripped)."""
    return re.sub(r"[ \t\n\r\f\v]+", " ", re.sub(r"//.*", "", src))


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
