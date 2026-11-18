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
 */

#include "hard_exit.hpp"
#include "test_helpers.hpp"

#include <chrono>
#include <cstdio>
#include <future>
#include <thread>
#include <utility>

namespace yuzu::test {

/// The bound for a call whose return is under test: 120 s.
///
/// Derivation (measured 2026-11-18, no guess): the slowest single Catch2 leaf of the 13
/// "echo plugin:*" dispatcher cases on native Windows MSVC Debug (a Windows host, origin/dev
/// f4cc683af1, 5 runs, a WSL VM active, CPU 12-31%) took 38.7 s. A shutdown happens inside a
/// leaf, so that is an upper bound on any shutdown. Shared CI amplifies I/O 3-6x (the "Budget
/// rule" in docs/testing/unit-test-conventions.md); at the lower end, 3 x 38.7 s = 116.1 s,
/// rounded up to 120 s.
/// On macOS (5 runs) the slowest case took 1.331 s and the offline-shutdown case 0.007 s.
/// 120 s is below agent shard C's 480 s limit, so a hang still gets a named message before
/// the meson timeout. Revise it only with a recorded measurement; the elapsed times this
/// helper prints are the data for that.
inline constexpr std::chrono::seconds kReturnBound{120};

/// Run `call()` on this thread; end the process (exit 3, `what` on stderr) if it has not
/// returned within `bound` (sanitizer-scaled). Print the elapsed seconds when it returns.
template <typename F>
void must_return_within(std::chrono::seconds bound, const char* what, F&& call) {
    const auto limit = bound * kSpinScale;
    std::promise<void> done;
    std::thread watchdog([&limit, &bound, what, finished = done.get_future()]() mutable {
        if (finished.wait_for(limit) == std::future_status::ready)
            return;
        std::fflush(nullptr); // hard_exit does not flush; an earlier failed assertion must survive
        std::fprintf(stderr, "\nmust_return_within: %s did not return within %lld s; ending the test process\n",
                     what, static_cast<long long>(bound.count()));
        std::fflush(stderr);
        yuzu::agent::hard_exit(3);
    });
    const auto began = std::chrono::steady_clock::now();
    const ScopeExit stop_watchdog{[&] {
        done.set_value();
        watchdog.join();
        const std::chrono::duration<double> took = std::chrono::steady_clock::now() - began;
        std::fprintf(stderr, "must_return_within: %s returned in %.3f s (bound %lld s)\n", what, took.count(),
                     static_cast<long long>(bound.count()));
    }};
    std::forward<F>(call)();
}

} // namespace yuzu::test
