#pragma once

/**
 * test_bounded_return.hpp -- must_return_within(): run a call whose RETURN is under test
 * (OpenRetryLoop::stop(), a plugin's shutdown()) with a watchdog that ends the process, with a
 * message naming the call, if the call has not returned within a bound.
 *
 * Why not std::async + wait_for + REQUIRE: a failed REQUIRE unwinds, and the unwind destroys the
 * owner (the loop, the plugin session), whose destructor blocks in the very same call. The test
 * then hangs to the meson timeout with no message. A hung stop() cannot be unwound, so a clean
 * test failure is not available; ending the process with the call's name is the best available
 * outcome (flake-retry.py reports the abnormal exit as unclassifiable, which is correct for a
 * hang). Any earlier failed assertion is flushed before the process ends.
 *
 * The call runs on the CALLING thread, on purpose: OpenRetryLoop::stop() and the plugin's
 * shutdown() are documented as called from the thread that ran start()/init(), and this keeps
 * the test on the production threading contract. Only the watchdog is a new thread.
 *
 * hard_exit() and not _Exit: hard_exit() is the repo's one termination primitive (TerminateProcess
 * on Windows, where there is no DllMain-safe _Exit; _exit elsewhere). It does not flush, so the
 * watchdog flushes stdio first.
 *
 * Safe to call from a destructor during exception unwind: nothing here throws past the call
 * itself, and the guard that stops the watchdog runs on every exit path.
 *
 * Every call prints its real elapsed time to stderr (the meson test log), so a bound is
 * re-derived from data rather than guessed. CI keeps no per-case timing (#8234).
 *
 * The bound is applied exactly as given: nothing here scales it. A caller that needs a sanitizer
 * stretch multiplies by yuzu::test::kSpinScale itself (EchoSession does, for a real plugin
 * shutdown); a caller whose bound is the property under test does not.
 *
 * The contract is pinned by the [echo][bounded_return] cases in test_echo_open_retry.cpp, which
 * drive detail::must_return_within_ms with a recording expiry action instead of ending the process:
 * the call runs on the calling thread, the action gets the call's name and exactly the limit, the
 * watchdog is joined on return and on a throw, and a call that returns never trips it. NOT covered
 * by a retained test: the default action's real exit code 3 and its stderr text (a unit test never
 * spawns a process). The evidence for those is the one-off mutation run recorded in the PR body and
 * the native Windows leg.
 */

#include "hard_exit.hpp"
#include "test_helpers.hpp"

#include <chrono>
#include <cstdio>
#include <future>
#include <thread>
#include <utility>

namespace yuzu::test {

/// The bound for a call whose return is under test: 120 s, in every build.
///
/// Derivation (measured 2026-11-18, no guess): the slowest single Catch2 leaf of the 13
/// "echo plugin:*" dispatcher cases on native Windows MSVC Debug (a Windows host, origin/dev
/// f4cc683af1, 5 runs, a WSL VM active, CPU 12-31%) took 38.7 s. A shutdown happens inside a
/// leaf, so that is an upper bound on any shutdown. Shared CI amplifies I/O 3-6x (the "Budget
/// rule" in docs/testing/unit-test-conventions.md); at the lower end, 3 x 38.7 s = 116.1 s,
/// rounded up to 120 s.
/// On macOS (5 runs) the slowest case took 1.331 s and the offline-shutdown case 0.007 s.
///
/// Against the meson limits it races: 120 s is below 180 s (the 'echo unit tests' entry, where
/// the OpenRetryLoop cases run) and below 480 s (agent shard C, where the dispatcher fixture's
/// shutdown runs). The fixture stretches its bound by kSpinScale (a real plugin shutdown is
/// legitimately slower under a sanitizer): 720 s on the sanitizer legs, against shard C's 960 s
/// there, because those legs run `meson test --timeout-multiplier 2` (sanitizer-tests.yml,
/// nightly.yml). A hang early in a run therefore gets the named message. One that starts late in
/// a slow run can still reach the meson timeout first: the echo unit tests measure 40-82 s on
/// Windows, so a hang after about 60 s of a 180 s entry ends at the limit, before this bound.
/// Revise the constant only with a recorded measurement; the elapsed times this helper prints
/// are the data for that.
inline constexpr std::chrono::seconds kReturnBound{120};

namespace detail {

/// The default expiry action: flush stdio, name the call and the limit, end the process.
inline void end_process_on_hang(const char* what, std::chrono::milliseconds limit) noexcept {
    std::fflush(nullptr); // hard_exit does not flush; an earlier failed assertion must survive
    std::fprintf(stderr, "\nmust_return_within: %s did not return within %g s; ending the test process\n",
                 what, std::chrono::duration<double>(limit).count());
    std::fflush(stderr);
    yuzu::agent::hard_exit(3);
}

/// must_return_within with the limit in milliseconds and the expiry action a parameter, so a test
/// can drive an expiry with a tiny limit and a recording action instead of ending the process.
/// `on_hang(what, limit)` runs on the watchdog thread, at most once, and only if `call` has not
/// returned within `limit`. The limit is applied exactly as given.
template <typename F, typename OnHang>
void must_return_within_ms(std::chrono::milliseconds limit, const char* what, F&& call, OnHang on_hang) {
    std::promise<void> done;
    std::thread watchdog([limit, what, on_hang, finished = done.get_future()]() mutable {
        if (finished.wait_for(limit) == std::future_status::ready)
            return;
        on_hang(what, limit);
    });
    const auto began = std::chrono::steady_clock::now();
    const ScopeExit stop_watchdog{[&] {
        done.set_value();
        watchdog.join();
        const std::chrono::duration<double> took = std::chrono::steady_clock::now() - began;
        std::fprintf(stderr, "must_return_within: %s returned in %.3f s (bound %g s)\n", what, took.count(),
                     std::chrono::duration<double>(limit).count());
    }};
    std::forward<F>(call)();
}

} // namespace detail

/// Run `call()` on this thread; end the process (exit 3, `what` and the limit on stderr) if it has
/// not returned within `bound`, applied exactly as given (no sanitizer scaling: see the file
/// comment). Print the elapsed seconds and the bound when it returns.
template <typename F>
void must_return_within(std::chrono::seconds bound, const char* what, F&& call) {
    detail::must_return_within_ms(std::chrono::duration_cast<std::chrono::milliseconds>(bound), what,
                                  std::forward<F>(call), &detail::end_process_on_hang);
}

} // namespace yuzu::test
