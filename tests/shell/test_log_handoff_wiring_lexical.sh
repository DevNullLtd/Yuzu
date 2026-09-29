#!/usr/bin/env bash
# test_log_handoff_wiring_lexical.sh -- #4666 PR-2 static lexical gate over
# agents/core/src/main.cpp's AND agents/core/src/service_win.cpp's log-handoff wiring
# call sites.
#
# main.cpp: four textual invariants, each guarding a real hazard agent_log_wiring.hpp's /
# log_handoff.hpp's own header banners describe:
#
#   1. `LogHandoffEpilogue log_epilogue` appears BEFORE `auto agent = make_agent(` --
#      C++ destroys stack/member locals in REVERSE declaration order
#      (agent_log_wiring.hpp's own declaration-order contract), so the epilogue must be
#      declared before anything (the Agent object) that might still be logging when its
#      destructor runs -- otherwise the epilogue's teardown() call races a live logger.
#   2. `install_log_handoff_in_this_image(` is actually called -- main.cpp must wire the
#      handoff into ITS OWN image's registry (log_handoff.hpp's MULTI-IMAGE note), not
#      just construct a LogHandoff and never install it.
#   3. main.cpp never calls `spdlog::set_default_logger(` directly -- that would bypass
#      agent_log_wiring.hpp's R-LOGGER-safe wrapper (which drops its own install()-
#      returned shared_ptr before returning) and risks a second owning reference to the
#      logger/sinks surviving past LogHandoff::teardown()'s bounded watchdog.
#   4. main.cpp never calls `->teardown(` directly -- LogHandoffEpilogue's destructor
#      (release_log_handoff_from_this_image) already calls LogHandoff::teardown(); a
#      second, hand-written call site would double-teardown or race the epilogue's own.
#
# service_win.cpp: two equally load-bearing invariants added after an adversarial-review
# finding that main.cpp's gate had no Windows-service equivalent -- exactly the kind of
# regression tripwire gap that let two independent implementers each write the same
# drain-outside-try firewall defect once during this PR's own development:
#
#   5. `SemaphoreReleaseGuard done_guard` is declared BEFORE service_main's outer `try {`
#      -- it must be the function's first local so it releases g_service_main_done LAST
#      (reverse-declaration-order destruction), after every other local and both catch
#      blocks have run. Declaring it after the try would let an early return/throw skip
#      it, leaving run_service()'s post-dispatch wait blocked for its full grace period.
#   6. The F3 orphan-exit `drain_log_bounded(` call immediately preceding `hard_exit(3)`
#      sits INSIDE the nearest enclosing `try { ... } catch`, not between a `}` and the
#      `hard_exit(3)` call -- drain_log_bounded() is not noexcept, so a call site placed
#      outside its guarding try (the exact defect one implementer wrote, then self-caught,
#      during this PR's development) would let an exception from the drain skip
#      hard_exit(3) entirely.
#
# Static/text-only, no build required -- a lexical gate, not a semantic one (mirrors
# scripts/ci/check-plugin-spawn-lexical.sh's tier-(a) role: fast, no-build, catches an
# obvious textual regression; it cannot see a relocation that keeps the same tokens but
# changes the surrounding control flow -- that is a review-enforced concern, same
# limitation that script's own header documents for its domain).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
MAIN_CPP="$ROOT/agents/core/src/main.cpp"
SERVICE_WIN_CPP="$ROOT/agents/core/src/service_win.cpp"

if [ ! -f "$MAIN_CPP" ]; then
  echo "::error::test_log_handoff_wiring_lexical: $MAIN_CPP not found" >&2
  exit 1
fi
if [ ! -f "$SERVICE_WIN_CPP" ]; then
  echo "::error::test_log_handoff_wiring_lexical: $SERVICE_WIN_CPP not found" >&2
  exit 1
fi

fail=0

epilogue_line="$(grep -n 'LogHandoffEpilogue log_epilogue' "$MAIN_CPP" | head -1 | cut -d: -f1 || true)"
make_agent_line="$(grep -n 'auto agent = make_agent(' "$MAIN_CPP" | head -1 | cut -d: -f1 || true)"

if [ -z "$epilogue_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'LogHandoffEpilogue log_epilogue' not found in main.cpp" >&2
  fail=1
fi
if [ -z "$make_agent_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'auto agent = make_agent(' not found in main.cpp" >&2
  fail=1
fi
if [ -n "$epilogue_line" ] && [ -n "$make_agent_line" ] && [ "$epilogue_line" -ge "$make_agent_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: LogHandoffEpilogue (line $epilogue_line) must be declared BEFORE 'auto agent = make_agent(' (line $make_agent_line) -- reverse-declaration-order destruction requires this ordering" >&2
  fail=1
fi

if ! grep -q 'install_log_handoff_in_this_image(' "$MAIN_CPP"; then
  echo "::error::test_log_handoff_wiring_lexical: main.cpp never calls install_log_handoff_in_this_image(" >&2
  fail=1
fi

if grep -q 'spdlog::set_default_logger(' "$MAIN_CPP"; then
  echo "::error::test_log_handoff_wiring_lexical: main.cpp calls spdlog::set_default_logger( directly -- route through agent_log_wiring.hpp's install_log_handoff_in_this_image() instead (R-LOGGER)" >&2
  fail=1
fi

if grep -q -- '->teardown(' "$MAIN_CPP"; then
  echo "::error::test_log_handoff_wiring_lexical: main.cpp calls ->teardown( directly -- LogHandoffEpilogue's destructor already calls LogHandoff::teardown(); a second call site double-tears-down or races the epilogue's own call" >&2
  fail=1
fi

# --- service_win.cpp invariant 5: SemaphoreReleaseGuard before service_main's outer try ---

service_main_line="$(grep -n 'void WINAPI service_main(' "$SERVICE_WIN_CPP" | head -1 | cut -d: -f1 || true)"
guard_line="$(grep -n 'SemaphoreReleaseGuard done_guard' "$SERVICE_WIN_CPP" | head -1 | cut -d: -f1 || true)"
# The FIRST "try {" strictly after service_main's opening brace is its outer try.
outer_try_line=""
if [ -n "$service_main_line" ]; then
  outer_try_line="$(tail -n "+$service_main_line" "$SERVICE_WIN_CPP" | grep -n 'try {' | head -1 | cut -d: -f1 || true)"
  if [ -n "$outer_try_line" ]; then
    outer_try_line=$((service_main_line + outer_try_line - 1))
  fi
fi

if [ -z "$service_main_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'void WINAPI service_main(' not found in service_win.cpp" >&2
  fail=1
fi
if [ -z "$guard_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'SemaphoreReleaseGuard done_guard' not found in service_win.cpp" >&2
  fail=1
fi
if [ -z "$outer_try_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: no 'try {' found after service_main( in service_win.cpp" >&2
  fail=1
fi
if [ -n "$service_main_line" ] && [ -n "$guard_line" ] && [ "$guard_line" -le "$service_main_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: SemaphoreReleaseGuard (line $guard_line) must appear AFTER service_main's opening line ($service_main_line)" >&2
  fail=1
fi
if [ -n "$guard_line" ] && [ -n "$outer_try_line" ] && [ "$guard_line" -ge "$outer_try_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: SemaphoreReleaseGuard (line $guard_line) must be declared BEFORE service_main's outer 'try {' (line $outer_try_line) -- it must be the function's FIRST local so reverse-declaration-order destruction releases g_service_main_done LAST" >&2
  fail=1
fi

# --- service_win.cpp invariant 6: the F3 drain_log_bounded( stays inside its guarding try ---

hard_exit3_line="$(grep -n 'hard_exit(3)' "$SERVICE_WIN_CPP" | head -1 | cut -d: -f1 || true)"
if [ -z "$hard_exit3_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'hard_exit(3)' not found in service_win.cpp (F3 site missing?)" >&2
  fail=1
else
  # The drain call immediately preceding this hard_exit(3) -- the LAST drain_log_bounded(
  # line before it.
  f3_drain_line="$(head -n "$hard_exit3_line" "$SERVICE_WIN_CPP" | grep -n 'drain_log_bounded(' | tail -1 | cut -d: -f1 || true)"
  if [ -z "$f3_drain_line" ]; then
    echo "::error::test_log_handoff_wiring_lexical: no drain_log_bounded( call found before hard_exit(3) (line $hard_exit3_line) in service_win.cpp" >&2
    fail=1
  else
    # Nearest enclosing structural boundary BEFORE the drain: the higher-numbered of the
    # last "try {" and the last "} catch" strictly before f3_drain_line. If the nearest
    # one is a "} catch", the drain sits between a catch and hard_exit(3), not inside a
    # try -- exactly the firewall defect this gate exists to catch.
    last_try_line="$(head -n $((f3_drain_line - 1)) "$SERVICE_WIN_CPP" | grep -n 'try {' | tail -1 | cut -d: -f1 || true)"
    last_catch_line="$(head -n $((f3_drain_line - 1)) "$SERVICE_WIN_CPP" | grep -n '} catch' | tail -1 | cut -d: -f1 || true)"
    last_try_line="${last_try_line:-0}"
    last_catch_line="${last_catch_line:-0}"
    if [ "$last_catch_line" -gt "$last_try_line" ]; then
      echo "::error::test_log_handoff_wiring_lexical: the drain_log_bounded( at line $f3_drain_line (preceding hard_exit(3) at line $hard_exit3_line) sits AFTER a '} catch' (line $last_catch_line) with no intervening 'try {' -- it is outside its guarding try. drain_log_bounded() is not noexcept; an exception there would skip hard_exit(3) entirely (the exact defect this gate exists to catch, self-caught once already during this PR's development)" >&2
      fail=1
    fi
  fi
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "test_log_handoff_wiring_lexical: OK -- main.cpp's log-handoff wiring invariants hold (epilogue line $epilogue_line < make_agent line $make_agent_line; install_log_handoff_in_this_image( present; no direct spdlog::set_default_logger(/->teardown( call); service_win.cpp's invariants hold (SemaphoreReleaseGuard line $guard_line < outer try line $outer_try_line; F3 drain line $f3_drain_line inside its guarding try, before hard_exit(3) at line $hard_exit3_line)"
