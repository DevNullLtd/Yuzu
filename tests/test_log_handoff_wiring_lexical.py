#!/usr/bin/env python3
"""#4666 PR-2 static lexical gate over agents/core/src/main.cpp's AND agents/core/src/service_win.cpp's
log-handoff wiring call sites.

main.cpp: four textual invariants, each guarding a real hazard agent_log_wiring.hpp's /
log_handoff.hpp's own header banners describe:

  1. `LogHandoffEpilogue log_epilogue` appears BEFORE `auto agent = make_agent(` -- C++ destroys
     stack/member locals in REVERSE declaration order (agent_log_wiring.hpp's own
     declaration-order contract), so the epilogue must be declared before anything (the Agent
     object) that might still be logging when its destructor runs -- otherwise the epilogue's
     teardown() call races a live logger.
  2. `install_log_handoff_in_this_image(` is actually called -- main.cpp must wire the handoff
     into ITS OWN image's registry (log_handoff.hpp's MULTI-IMAGE note), not just construct a
     LogHandoff and never install it.
  3. main.cpp never calls `spdlog::set_default_logger(` directly -- that would bypass
     agent_log_wiring.hpp's R-LOGGER-safe wrapper (which drops its own install()-returned
     shared_ptr before returning) and risks a second owning reference to the logger/sinks
     surviving past LogHandoff::teardown()'s bounded watchdog.
  4. main.cpp never calls `->teardown(` directly -- LogHandoffEpilogue's destructor
     (release_log_handoff_from_this_image) already calls LogHandoff::teardown(); a second,
     hand-written call site would double-teardown or race the epilogue's own.

service_win.cpp: two equally load-bearing invariants added after an adversarial-review finding
that main.cpp's gate had no Windows-service equivalent:

  5. `SemaphoreReleaseGuard done_guard` is declared BEFORE service_main's outer `try {` -- it must
     be the function's first local so it releases g_service_main_done LAST (reverse-declaration-
     order destruction), after every other local and both catch blocks have run. Declaring it
     after the try would let an early return/throw skip it, leaving run_service()'s post-dispatch
     wait blocked for its full grace period.
  6. The F3 orphan-exit `drain_log_bounded(` call immediately preceding `hard_exit(3)` sits INSIDE
     the nearest enclosing `try { ... } catch`, not between a `}` and the `hard_exit(3)` call --
     drain_log_bounded() is not noexcept, so a call site outside its guarding try would let an
     exception from the drain skip hard_exit(3) entirely.

Static/text-only, no build required -- a lexical gate, not a semantic one: it cannot see a
relocation that keeps the same tokens but changes the surrounding control flow (review-enforced).
Line numbers are 1-based and comment lines count (no normalisation).

Why Python: this replaces a bash gate that forked a grep/head/tail/cut pipeline per check; one
process is cheaper on every OS, notably under MSYS2 on the Windows CI leg (#5428).

Usage: python3 tests/test_log_handoff_wiring_lexical.py
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_CPP = ROOT / "agents" / "core" / "src" / "main.cpp"
SERVICE_WIN_CPP = ROOT / "agents" / "core" / "src" / "service_win.cpp"
TAG = "test_log_handoff_wiring_lexical"


def first(lines, s, start=1):
    """1-based number of the first line >= start containing s, else None."""
    for n in range(start, len(lines) + 1):
        if s in lines[n - 1]:
            return n
    return None


def last_before(lines, s, upto):
    """1-based number of the last line <= upto containing s, else 0."""
    for n in range(min(upto, len(lines)), 0, -1):
        if s in lines[n - 1]:
            return n
    return 0


def problems(main, win):
    """One message per violated invariant, in the bash gate's order; [] when clean."""
    out = []
    ml = main.split("\n")
    wl = win.split("\n")

    e = first(ml, "LogHandoffEpilogue log_epilogue")
    m = first(ml, "auto agent = make_agent(")
    if e is None:
        out.append("'LogHandoffEpilogue log_epilogue' not found in main.cpp")
    if m is None:
        out.append("'auto agent = make_agent(' not found in main.cpp")
    if e is not None and m is not None and e >= m:
        out.append(f"LogHandoffEpilogue (line {e}) must be declared BEFORE 'auto agent = make_agent(' "
                   f"(line {m}) -- reverse-declaration-order destruction requires this ordering")
    if "install_log_handoff_in_this_image(" not in main:
        out.append("main.cpp never calls install_log_handoff_in_this_image(")
    if "spdlog::set_default_logger(" in main:
        out.append("main.cpp calls spdlog::set_default_logger( directly -- route through "
                   "agent_log_wiring.hpp's install_log_handoff_in_this_image() instead (R-LOGGER)")
    if "->teardown(" in main:
        out.append("main.cpp calls ->teardown( directly -- LogHandoffEpilogue's destructor already calls "
                   "LogHandoff::teardown(); a second call site double-tears-down or races the epilogue's own call")

    sm = first(wl, "void WINAPI service_main(")
    g = first(wl, "SemaphoreReleaseGuard done_guard")
    # The FIRST "try {" at or after service_main's line is its outer try.
    ot = first(wl, "try {", sm) if sm is not None else None
    if sm is None:
        out.append("'void WINAPI service_main(' not found in service_win.cpp")
    if g is None:
        out.append("'SemaphoreReleaseGuard done_guard' not found in service_win.cpp")
    if ot is None:
        out.append("no 'try {' found after service_main( in service_win.cpp")
    if sm is not None and g is not None and g <= sm:
        out.append(f"SemaphoreReleaseGuard (line {g}) must appear AFTER service_main's opening line ({sm})")
    if g is not None and ot is not None and g >= ot:
        out.append(f"SemaphoreReleaseGuard (line {g}) must be declared BEFORE service_main's outer 'try {{' "
                   f"(line {ot}) -- it must be the function's FIRST local so reverse-declaration-order "
                   f"destruction releases g_service_main_done LAST")

    h = first(wl, "hard_exit(3)")
    if h is None:
        out.append("'hard_exit(3)' not found in service_win.cpp (F3 site missing?)")
    else:
        d = last_before(wl, "drain_log_bounded(", h)
        if d == 0:
            out.append(f"no drain_log_bounded( call found before hard_exit(3) (line {h}) in service_win.cpp")
        else:
            # Nearest enclosing boundary BEFORE the drain: the higher of the last "try {" and the
            # last "} catch". If it is a "} catch", the drain sits between a catch and
            # hard_exit(3), outside any try.
            lt = last_before(wl, "try {", d - 1)
            lc = last_before(wl, "} catch", d - 1)
            if lc > lt:
                out.append(f"the drain_log_bounded( at line {d} (preceding hard_exit(3) at line {h}) sits AFTER a "
                           f"'}} catch' (line {lc}) with no intervening 'try {{' -- it is outside its guarding try. "
                           f"drain_log_bounded() is not noexcept; an exception there would skip hard_exit(3) "
                           f"entirely (the exact defect this gate exists to catch, self-caught once already "
                           f"during this PR's development)")
    return out


EPILOGUE = "    yuzu::agent::LogHandoffEpilogue log_epilogue{*log_handoff};\n"
MAKE_AGENT = "    auto agent = make_agent(std::move(cfg));\n"
DONE_GUARD = "    yuzu::agent::SemaphoreReleaseGuard done_guard{g_service_main_done};\n"
F3_DRAIN = "                    yuzu::agent::drain_log_bounded(std::chrono::milliseconds{200});\n"


def _once(test, src, anchor):
    test.assertEqual(src.count(anchor), 1, f"mutation anchor not unique: {anchor!r}")


class LogHandoffWiringLexical(unittest.TestCase):
    def setUp(self):
        self.main = MAIN_CPP.read_text(encoding="utf-8")
        self.win = SERVICE_WIN_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.main, self.win)
        for m in p:
            print(f"::error::{TAG}: {m}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        main, win = self.main, self.win
        for a in (EPILOGUE, MAKE_AGENT):
            _once(self, main, a)
        for a in (DONE_GUARD, F3_DRAIN):
            _once(self, win, a)
        # L5: the guard moves to just after the first `try {` line following service_main.
        sm = win.index("void WINAPI service_main(")
        l5 = win.replace(DONE_GUARD, "", 1)  # the guard precedes the try, so removal shifts it
        try_end = l5.index("\n", l5.index("try {", sm)) + 1
        l5 = l5[:try_end] + DONE_GUARD + l5[try_end:]

        cases = [
            ("L1 epilogue after make_agent",
             main.replace(EPILOGUE, "", 1).replace(MAKE_AGENT, MAKE_AGENT + EPILOGUE, 1), win,
             "must be declared BEFORE 'auto agent"),
            ("L2 install_log_handoff renamed",
             main.replace("install_log_handoff_in_this_image(", "install_log_handoff_elsewhere("), win,
             "never calls install_log_handoff_in_this_image("),
            ("L3 direct spdlog::set_default_logger",
             main + "spdlog::set_default_logger(nullptr);\n", win,
             "spdlog::set_default_logger("),
            ("L4 direct ->teardown(", main + "log_handoff->teardown();\n", win, "->teardown("),
            ("L5 done_guard after the outer try", main, l5, "must be declared BEFORE service_main's outer"),
            ("L6 catch before the F3 drain", main,
             win.replace(F3_DRAIN, "} catch (...) {\n" + F3_DRAIN, 1), "outside its guarding try"),
        ]
        for name, m, w, expected in cases:
            with self.subTest(mutation=name):
                self.assertNotEqual((m, w), (main, win), "mutation changed nothing (stale anchor)")
                p = problems(m, w)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
