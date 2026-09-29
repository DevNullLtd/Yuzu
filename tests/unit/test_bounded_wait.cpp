// bounded_wait.hpp (agents/shared) bounds the WAIT on an uncancellable
// blocking call (Wave 2 PR2.1c, governance Gate 4 unhappy-path fix:
// getnameinfo's reverse-DNS lookup has no per-call timeout, and a
// black-holing resolver could otherwise pin a worker on the agent's bounded
// ThreadPool indefinitely). Hoisted here from the discovery plugin (#3429
// round 4) once agent-core's server_address_resolver.cpp needed the same
// primitive to bound its own getaddrinfo() call.
// These tests use a synthetic slow callable rather than real DNS, so the
// timeout behaviour is deterministic and network-independent.
#include <catch2/catch_test_macros.hpp>

#include "bounded_wait.hpp"

#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::shared::bounded_call;

TEST_CASE("bounded_call: a fast function returns its result well before the timeout",
          "[agent][bounded_wait]") {
    const auto result = bounded_call(500ms, [] { return 42; });
    REQUIRE(result.has_value());
    CHECK(*result == 42);
}

TEST_CASE("bounded_call: a function that never returns in time yields nullopt, not a hang",
          "[agent][bounded_wait]") {
    // Simulates the black-holing-resolver scenario: the callable blocks far
    // longer than the caller is willing to wait.
    const auto start = std::chrono::steady_clock::now();
    const auto result = bounded_call(100ms, [] {
        std::this_thread::sleep_for(3s);
        return 1;
    });
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(result.has_value());
    // The whole point of the fix: the CALLER returns promptly, not after the
    // callable finishes. Generous CI-safe ceiling, still far under the 3s the
    // callable itself sleeps for.
    CHECK(elapsed < 1500ms);
}

TEST_CASE("bounded_call: propagates a std::string result", "[agent][bounded_wait]") {
    const auto result = bounded_call(500ms, [] { return std::string{"resolved.example"}; });
    REQUIRE(result.has_value());
    CHECK(*result == "resolved.example");
}

TEST_CASE("bounded_call: an exception inside fn() does not crash the process",
          "[agent][bounded_wait]") {
    // fn() runs on a raw detached thread, outside ThreadPool's own exception
    // firewall -- an uncaught throw here would std::terminate() the whole
    // process (governance Gate 5 chaos-injector finding). Reaching this
    // CHECK at all is the proof: the process is still running.
    const auto result = bounded_call(
        300ms, []() -> int { throw std::runtime_error("simulated detached-thread failure"); });
    CHECK_FALSE(result.has_value());
}

TEST_CASE("bounded_call: caps concurrently-outstanding detached threads, degrading excess "
          "callers to an immediate nullopt instead of spawning unboundedly",
          "[agent][bounded_wait]") {
    // Governance Gate 5 chaos-injector finding: a sustained black hole across
    // many concurrent callers could otherwise accumulate an unbounded number
    // of detached threads (verified by execution during the review to reach
    // dozens under simulation). kTotal comfortably exceeds bounded_wait.hpp's
    // internal ceiling so some callers MUST be degraded.
    constexpr int kTotal = 100;
    std::vector<std::thread> callers;
    std::vector<std::chrono::steady_clock::duration> elapsed(kTotal);

    for (int i = 0; i < kTotal; ++i) {
        callers.emplace_back([&, i] {
            const auto start = std::chrono::steady_clock::now();
            bounded_call(2000ms, [] {
                std::this_thread::sleep_for(4s);
                return 1;
            });
            elapsed[i] = std::chrono::steady_clock::now() - start;
        });
    }
    for (auto& t : callers)
        t.join();

    // A real (slot-acquiring) attempt waits up to ~2s before its own timeout;
    // a call degraded by the ceiling returns near-instantly. If the ceiling
    // did nothing, every one of the 100 calls would wait out the full ~2s.
    // A generous lower bound (not the exact 100-minus-ceiling count) keeps
    // this robust to scheduling jitter and any stray thread left running
    // from an earlier test case in this same process.
    int fast_returns = 0;
    for (const auto& e : elapsed) {
        if (e < 500ms)
            ++fast_returns;
    }
    CHECK(fast_returns >= 20);

    // Drain: the outstanding-call counter is process-wide, shared with every
    // other test case in this binary. Wait for the slot-acquiring callers'
    // detached threads to finish (they were sleeping 4s) and decrement it,
    // so a later test case doesn't start against a still-saturated ceiling.
    for (int i = 0; i < 100 && yuzu::shared::detail::g_outstanding_bounded_calls.load() > 0;
        ++i) {
        std::this_thread::sleep_for(100ms);
    }
}

TEST_CASE("OutstandingCallGuard: releases the ceiling slot when an exception unwinds the stack "
          "while the guard is still held (colleague-review blocker: construction-failure "
          "exception safety)",
          "[agent][bounded_wait]") {
    // bounded_call() claims a slot via OutstandingCallGuard::try_acquire() BEFORE constructing
    // std::make_shared<State> and the std::thread -- both of which can throw (std::bad_alloc,
    // std::system_error from pthread_create under resource pressure). Before the RAII fix, the
    // counter was a bare `++`/`--` whose only decrement site was inside the detached thread
    // body, so a throw on either of those two lines permanently leaked a slot. This proves the
    // guard's destructor runs during unwinding and releases the slot even when nothing ever
    // reaches the point that used to do the decrementing.
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::OutstandingCallGuard;

    const int baseline = g_outstanding_bounded_calls.load();

    bool threw = false;
    try {
        auto guard = OutstandingCallGuard::try_acquire();
        REQUIRE(guard.has_value());
        CHECK(g_outstanding_bounded_calls.load() == baseline + 1);
        // Stand-in for make_shared<State>/std::thread's constructor throwing
        // before the guard would normally be handed off to the detached thread.
        throw std::bad_alloc();
    } catch (const std::bad_alloc&) {
        threw = true;
    }

    CHECK(threw);
    CHECK(g_outstanding_bounded_calls.load() == baseline);
}

TEST_CASE("OutstandingCallGuard: move-construction transfers ownership so only the moved-to "
          "guard releases the slot, never the moved-from one",
          "[agent][bounded_wait]") {
    // Mirrors bounded_call()'s real usage: the guard returned by try_acquire() is moved into
    // the detached thread's lambda. If the move constructor failed to clear the source's
    // "held" flag, both the moved-from local and the moved-to copy would decrement --
    // double-releasing the slot and driving the counter negative for a later caller.
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::OutstandingCallGuard;

    const int baseline = g_outstanding_bounded_calls.load();

    {
        auto guard = OutstandingCallGuard::try_acquire();
        REQUIRE(guard.has_value());
        OutstandingCallGuard moved = std::move(*guard);
        CHECK(g_outstanding_bounded_calls.load() == baseline + 1);
        // `guard`'s contents are now moved-from; its destructor at end of scope must be a
        // no-op. `moved` releases the slot when it goes out of scope just below.
    }
    CHECK(g_outstanding_bounded_calls.load() == baseline);
}

TEST_CASE("bounded_call_ex: a ceiling rejection is reported as Rejected, never as TimedOut "
          "(M3 — the caller must be able to tell whether fn() ever touched its handles)",
          "[agent][bounded_wait][m3]") {
    // bounded_call() collapses both into an empty optional. That is fine for a
    // caller with nothing to clean up, and wrong for one holding an OS handle
    // fn() uses: after a TimedOut, a detached thread may still be using it and
    // closing races a live call; after a Rejected, fn() never ran and closing
    // is safe. power_health's PDH thermal poll leaked a PDH_HQUERY on BOTH,
    // and rejection is the case that arrives in bursts under load.
    using yuzu::shared::BoundedCallStatus;
    using yuzu::shared::bounded_call_ex;
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::kMaxOutstandingBoundedCalls;
    using yuzu::shared::detail::OutstandingCallGuard;

    // A prompt call, with the ceiling free, completes.
    {
        auto ok = bounded_call_ex(std::chrono::milliseconds(2000), [] { return 7; });
        CHECK(ok.status == BoundedCallStatus::Completed);
        REQUIRE(ok.value.has_value());
        CHECK(*ok.value == 7);
    }

    // Saturate the ceiling from THIS thread, so the next call is rejected
    // deterministically rather than by racing real work.
    std::vector<OutstandingCallGuard> held;
    while (g_outstanding_bounded_calls.load() <= kMaxOutstandingBoundedCalls) {
        auto g = OutstandingCallGuard::try_acquire();
        if (!g)
            break;
        held.push_back(std::move(*g));
    }

    bool fn_ran = false;
    auto rejected = bounded_call_ex(std::chrono::milliseconds(2000), [&fn_ran] {
        fn_ran = true;
        return 1;
    });
    CHECK(rejected.status == BoundedCallStatus::Rejected);
    CHECK_FALSE(rejected.value.has_value());
    // The load-bearing half: Rejected means fn() was never invoked, which is
    // exactly what makes closing the caller's handle safe on this path.
    CHECK_FALSE(fn_ran);

    held.clear(); // release the ceiling for later test cases
}
