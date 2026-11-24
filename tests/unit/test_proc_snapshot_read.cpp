/**
 * test_proc_snapshot_read.cpp -- yuzu::agent::read_proc_snapshot_bounded (SRE-1).
 *
 * Load-bearing cases: a normal read returns its numbers; a reader that NEVER returns still gives
 * the caller its thread back (TimedOut), a second call while it is blocked is Busy without a
 * second reader being started, and once the reader returns the next call reads normally again;
 * a Rejected admission does not leave the in-flight flag set.
 *
 * Rejected instantiates the header-only driver in THIS image with a test-owned flag: the
 * outstanding-call ceiling is per image (see keychain_read.hpp), so saturating it from here
 * cannot reach agent-core's copy used by read_proc_snapshot_bounded_for_test.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/proc_snapshot_read.hpp>

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

using namespace std::chrono_literals;
using yuzu::agent::ProcSnapshot;
using yuzu::agent::ProcSnapshotStatus;
using yuzu::agent::read_proc_snapshot_bounded_for_test;

TEST_CASE("read_proc_snapshot_bounded returns the reader's numbers", "[proc_snapshot][agent]") {
    int seen_pid = 0;
    const auto r = read_proc_snapshot_bounded_for_test(4242, 5000ms, [&](int pid) {
        seen_pid = pid;
        ProcSnapshot s;
        s.start_sec = 1700000000;
        s.start_usec = 123456;
        s.nice = 7;
        return s;
    });
    REQUIRE(r.status == ProcSnapshotStatus::Completed);
    CHECK(seen_pid == 4242);
    CHECK(r.snap.err == 0);
    CHECK(r.snap.start_sec == 1700000000);
    CHECK(r.snap.start_usec == 123456);
    CHECK(r.snap.nice == 7);
}

TEST_CASE("a reader's errno passes through a Completed call", "[proc_snapshot][agent]") {
    const auto r = read_proc_snapshot_bounded_for_test(1, 5000ms, [](int) {
        ProcSnapshot s;
        s.err = 3;
        return s;
    });
    REQUIRE(r.status == ProcSnapshotStatus::Completed);
    CHECK(r.snap.err == 3);
}

TEST_CASE("a blocked reader times out, blocks a second call (Busy), then recovers",
          "[proc_snapshot][agent]") {
    std::promise<void> gate;
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    // A failing REQUIRE must not leave a worker wedged: it would hold the process-wide
    // in-flight flag and turn every later test into Busy.
    yuzu::test::ScopeExit opener{release};
    // The abandoned worker outlives this scope on failure: everything it touches is captured
    // BY VALUE (shared state), never by reference to the stack.
    auto gate_f = gate.get_future().share();
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto readers_started = std::make_shared<std::atomic<int>>(0);

    const auto t0 = std::chrono::steady_clock::now();
    auto r1 = read_proc_snapshot_bounded_for_test(
        10, 300ms, [gate_f, entered, readers_started](int) -> ProcSnapshot {
            ++*readers_started;
            entered->set_value();
            gate_f.wait();
            return ProcSnapshot{};
        });
    CHECK(r1.status == ProcSnapshotStatus::TimedOut);
    CHECK(std::chrono::steady_clock::now() - t0 < 4s); // the caller got its thread back
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    // The worker is still blocked: a second dispatch is refused without starting a reader.
    auto r2 = read_proc_snapshot_bounded_for_test(11, 300ms, [readers_started](int) {
        ++*readers_started;
        return ProcSnapshot{};
    });
    CHECK(r2.status == ProcSnapshotStatus::Busy);
    CHECK(readers_started->load() == 1);

    // The worker returns and releases the flag itself: the next call reads normally.
    release();
    ProcSnapshotStatus st = ProcSnapshotStatus::Busy;
    for (int i = 0; i < 500 && st == ProcSnapshotStatus::Busy; ++i) {
        auto r3 = read_proc_snapshot_bounded_for_test(12, 5000ms, [](int) {
            ProcSnapshot s;
            s.nice = 3;
            return s;
        });
        st = r3.status;
        if (st == ProcSnapshotStatus::Completed)
            CHECK(r3.snap.nice == 3);
        else
            std::this_thread::sleep_for(10ms);
    }
    CHECK(st == ProcSnapshotStatus::Completed);
}

TEST_CASE("a spent deadline starts nothing and leaves the flag clear", "[proc_snapshot][agent]") {
    std::atomic<int> started{0};
    const auto r = read_proc_snapshot_bounded_for_test(1, 0ms, [&](int) {
        ++started;
        return ProcSnapshot{};
    });
    CHECK(r.status == ProcSnapshotStatus::TimedOut);
    CHECK(started.load() == 0);
    const auto r2 =
        read_proc_snapshot_bounded_for_test(1, 5000ms, [](int) { return ProcSnapshot{}; });
    CHECK(r2.status == ProcSnapshotStatus::Completed);
}

TEST_CASE("a Rejected admission releases the in-flight flag", "[proc_snapshot][agent]") {
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::kMaxOutstandingBoundedCalls;

    // Starts from zero outstanding calls in this image (sibling tests' guards are released on
    // their own threads shortly after they finish).
    REQUIRE(yuzu::test::spin_until([] { return g_outstanding_bounded_calls.load() == 0; }, 10s));

    static std::atomic_flag flag; // outlives any worker
    std::promise<void> gate;
    bool gate_open = false;
    yuzu::test::ScopeExit opener{[&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    }};
    auto gate_f = gate.get_future().share();
    for (int i = 0; i < kMaxOutstandingBoundedCalls; ++i) {
        auto parked = yuzu::shared::bounded_call_ex(1ms, [gate_f]() -> bool {
            gate_f.wait();
            return true;
        });
        REQUIRE(parked.status == yuzu::shared::BoundedCallStatus::TimedOut);
    }

    const auto r = yuzu::agent::detail::bounded_proc_snapshot(
        flag, 1, 5000ms, [](int) { return ProcSnapshot{}; });
    CHECK(r.status == ProcSnapshotStatus::Rejected);
    CHECK_FALSE(flag.test_and_set()); // clear: the worker never ran, the caller released it
    flag.clear();
}
