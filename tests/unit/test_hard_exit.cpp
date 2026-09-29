// test_hard_exit.cpp - the F3 orphan-exit obligation's testable half (ADR-0021
// rung 7.6). hard_exit() itself terminates the process and so is not
// in-process testable (same as the pre-existing on_signal_hard_exit, which
// has never had a unit test either) - only wait_for_workers_to_drain()'s pure
// polling logic is exercised here.

#include "hard_exit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>

using namespace std::chrono_literals;

TEST_CASE("returns true immediately when the worker count is already zero",
          "[hard_exit]") {
    const auto start = std::chrono::steady_clock::now();
    const bool drained =
        yuzu::agent::wait_for_workers_to_drain([] { return std::size_t{0}; }, 5s, 1ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(drained);
    CHECK(elapsed < 200ms); // must not wait out the grace when already zero
}

TEST_CASE("returns true once the count transitions to zero within the grace",
          "[hard_exit]") {
    std::atomic<int> calls{0};
    auto active_workers = [&calls] {
        // Nonzero for the first 3 polls, then zero.
        return calls.fetch_add(1) < 3 ? std::size_t{1} : std::size_t{0};
    };

    CHECK(yuzu::agent::wait_for_workers_to_drain(active_workers, 5s, 5ms));
    CHECK(calls.load() >= 4); // at least the 3 nonzero polls + the zero one
}

TEST_CASE("returns false when the count never reaches zero within the grace",
          "[hard_exit]") {
    const auto start = std::chrono::steady_clock::now();
    const bool drained =
        yuzu::agent::wait_for_workers_to_drain([] { return std::size_t{1}; }, 50ms, 5ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(drained);
    CHECK(elapsed >= 50ms);
    CHECK(elapsed < 1s); // bounded - must not overshoot the grace by much
}

TEST_CASE("a zero grace with a nonzero count returns false without hanging",
          "[hard_exit]") {
    CHECK_FALSE(yuzu::agent::wait_for_workers_to_drain([] { return std::size_t{1}; }, 0ms, 1ms));
}

// OrphanExitGuard's destructor calls hard_exit() (terminates the process) when
// still armed with a nonzero, never-draining count - not in-process testable,
// same reason hard_exit() itself isn't. Only the two SAFE paths are covered:
// disarm() suppresses the check entirely, and a count that is already zero
// never triggers it.

TEST_CASE("a disarmed OrphanExitGuard's destructor is a no-op even with a "
          "nonzero, never-draining count",
          "[hard_exit]") {
    {
        yuzu::agent::OrphanExitGuard guard{[] { return std::size_t{1}; }, 1ms, 99};
        guard.disarm();
    } // if disarm() didn't work, this line would never be reached (hard_exit(99))
    SUCCEED("destructor did not call hard_exit after disarm()");
}

TEST_CASE("an armed OrphanExitGuard is a no-op when the count is already zero",
          "[hard_exit]") {
    {
        yuzu::agent::OrphanExitGuard guard{[] { return std::size_t{0}; }, 1ms, 99};
        // left armed - the destructor must see count==0 and do nothing.
    }
    SUCCEED("destructor did not call hard_exit when already drained");
}
