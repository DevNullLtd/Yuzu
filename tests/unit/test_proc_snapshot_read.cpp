/**
 * test_proc_snapshot_read.cpp -- yuzu::agent::read_proc_snapshot_bounded (SRE-1).
 *
 * Load-bearing cases: a normal read returns its numbers; a reader that NEVER returns still gives
 * the caller its thread back (TimedOut), a second call while it is blocked is Abandoned without a
 * second reader being started, and once the reader returns the next call reads normally again; a
 * second call while a HEALTHY read is in flight is Busy (not Abandoned); a Rejected admission
 * does not leave the slot held.
 *
 * Rejected instantiates the header-only driver in THIS image with a test-owned slot: the
 * outstanding-call ceiling is per image (see keychain_read.hpp), so saturating it from here
 * cannot reach agent-core's copy used by read_proc_snapshot_bounded_for_test.
 *
 * No sleep is used as synchronisation: ordering comes from promises, and recovery is awaited with
 * yuzu::test::spin_until. Anything an abandonable reader touches is captured BY VALUE.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/proc_snapshot_read.hpp>

#include "test_bounded_return.hpp"
#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <type_traits>

using namespace std::chrono_literals;
using yuzu::agent::ProcSnapshot;
using yuzu::agent::ProcSnapshotStatus;
using yuzu::agent::read_proc_snapshot_bounded_for_test;

TEST_CASE("ProcSnapshot carries numbers only", "[proc_snapshot][agent]") {
    // A further member (a process-name field, say) breaks this structured binding.
    ProcSnapshot s;
    const auto& [err, start_sec, start_usec, nice, start_abstime] = s;
    static_assert(std::is_same_v<decltype(ProcSnapshot::err), int>);
    static_assert(std::is_same_v<decltype(ProcSnapshot::start_sec), std::uint64_t>);
    static_assert(std::is_same_v<decltype(ProcSnapshot::start_usec), std::uint64_t>);
    static_assert(std::is_same_v<decltype(ProcSnapshot::nice), std::int32_t>);
    static_assert(std::is_same_v<decltype(ProcSnapshot::start_abstime), std::uint64_t>);
    CHECK(err == 0);
    CHECK(start_sec == 0);
    CHECK(start_usec == 0);
    CHECK(nice == 0);
    CHECK(start_abstime == 0);
}

TEST_CASE("read_proc_snapshot_bounded returns the reader's numbers", "[proc_snapshot][agent]") {
    auto seen_pid = std::make_shared<std::atomic<int>>(0); // by value: the reader is abandonable
    const auto r = read_proc_snapshot_bounded_for_test(4242, 5000ms, [seen_pid](int pid) {
        *seen_pid = pid;
        ProcSnapshot s;
        s.start_sec = 1700000000;
        s.start_usec = 123456;
        s.nice = 7;
        s.start_abstime = 99;
        return s;
    });
    REQUIRE(r.status == ProcSnapshotStatus::Completed);
    CHECK(seen_pid->load() == 4242);
    CHECK(r.snap.err == 0);
    CHECK(r.snap.start_sec == 1700000000);
    CHECK(r.snap.start_usec == 123456);
    CHECK(r.snap.nice == 7);
    CHECK(r.snap.start_abstime == 99);
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

TEST_CASE("a blocked reader times out, blocks a second call (Abandoned), then recovers",
          "[proc_snapshot][agent]") {
    std::promise<void> gate;
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    // A failing REQUIRE must not leave a worker wedged: it would hold the process-wide slot and
    // turn every later test into Busy/Abandoned. Declared AFTER the promise it opens.
    yuzu::test::ScopeExit opener{release};
    auto gate_f = gate.get_future().share();
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto readers_started = std::make_shared<std::atomic<int>>(0);

    auto r1 = read_proc_snapshot_bounded_for_test(
        10, 300ms, [gate_f, entered, readers_started](int) -> ProcSnapshot {
            ++*readers_started;
            entered->set_value();
            gate_f.wait();
            return ProcSnapshot{};
        });
    CHECK(r1.status == ProcSnapshotStatus::TimedOut); // the caller got its thread back
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    // The worker is still blocked past a deadline: a second dispatch is told so, and no reader
    // is started.
    auto r2 = read_proc_snapshot_bounded_for_test(11, 300ms, [readers_started](int) {
        ++*readers_started;
        return ProcSnapshot{};
    });
    CHECK(r2.status == ProcSnapshotStatus::Abandoned);
    CHECK(readers_started->load() == 1);

    // The worker returns and releases the slot itself: the next call reads normally.
    release();
    ProcSnapshotStatus st = ProcSnapshotStatus::Abandoned;
    int nice = 0;
    CHECK(yuzu::test::spin_until([&] {
        const auto r3 = read_proc_snapshot_bounded_for_test(12, 5000ms, [](int) {
            ProcSnapshot s;
            s.nice = 3;
            return s;
        });
        st = r3.status;
        nice = r3.snap.nice;
        return st != ProcSnapshotStatus::Abandoned && st != ProcSnapshotStatus::Busy;
    }));
    CHECK(st == ProcSnapshotStatus::Completed);
    CHECK(nice == 3);
}

TEST_CASE("a second dispatch during a healthy read is Busy, not Abandoned",
          "[proc_snapshot][agent]") {
    std::promise<void> gate;
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    auto gate_f = gate.get_future().share();
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto readers_started = std::make_shared<std::atomic<int>>(0);

    // The first dispatch has a generous deadline, so it never times out here.
    auto first = std::async(std::launch::async, [gate_f, entered, readers_started] {
        return read_proc_snapshot_bounded_for_test(
            20, 30000ms, [gate_f, entered, readers_started](int) -> ProcSnapshot {
                ++*readers_started;
                entered->set_value();
                gate_f.wait();
                ProcSnapshot s;
                s.nice = 5;
                return s;
            });
    });
    // Declared AFTER the future: destructs first, so a failing REQUIRE opens the gate before the
    // future's destructor joins.
    yuzu::test::ScopeExit opener{release};
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    const auto second = read_proc_snapshot_bounded_for_test(21, 300ms, [readers_started](int) {
        ++*readers_started;
        return ProcSnapshot{};
    });
    CHECK(second.status == ProcSnapshotStatus::Busy);
    CHECK(readers_started->load() == 1);

    release();
    const auto r = first.get();
    REQUIRE(r.status == ProcSnapshotStatus::Completed);
    CHECK(r.snap.nice == 5);
}

TEST_CASE("a spent deadline starts nothing and leaves the slot free", "[proc_snapshot][agent]") {
    auto started = std::make_shared<std::atomic<int>>(0);
    yuzu::agent::ProcSnapshotResult r;
    yuzu::test::must_return_within(10s, "bounded read, spent deadline", [&] {
        r = read_proc_snapshot_bounded_for_test(1, 0ms, [started](int) {
            ++*started;
            return ProcSnapshot{};
        });
    });
    CHECK(r.status == ProcSnapshotStatus::TimedOut);
    CHECK(started->load() == 0);
    const auto r2 =
        read_proc_snapshot_bounded_for_test(1, 5000ms, [](int) { return ProcSnapshot{}; });
    CHECK(r2.status == ProcSnapshotStatus::Completed);
}

TEST_CASE("a throwing reader answers TimedOut at once and frees the slot",
          "[proc_snapshot][agent]") {
    // A throwing reader must return at once, far inside its 30 s deadline.
    yuzu::agent::ProcSnapshotResult r;
    yuzu::test::must_return_within(10s, "bounded read, throwing reader", [&] {
        r = read_proc_snapshot_bounded_for_test(1, 30000ms,
                                                [](int) -> ProcSnapshot { throw 1; });
    });
    CHECK(r.status == ProcSnapshotStatus::TimedOut);
    // The worker's releaser has run or is about to: the slot becomes free, never Abandoned.
    ProcSnapshotStatus st = ProcSnapshotStatus::Busy;
    CHECK(yuzu::test::spin_until([&] {
        st = read_proc_snapshot_bounded_for_test(1, 5000ms, [](int) { return ProcSnapshot{}; })
                 .status;
        return st != ProcSnapshotStatus::Busy && st != ProcSnapshotStatus::Abandoned;
    }));
    CHECK(st == ProcSnapshotStatus::Completed);
}

TEST_CASE("a Rejected admission releases the slot", "[proc_snapshot][agent]") {
    using yuzu::shared::detail::g_outstanding_bounded_calls;
    using yuzu::shared::detail::kMaxOutstandingBoundedCalls;

    // Starts from zero outstanding calls in this image (sibling tests' guards are released on
    // their own threads shortly after they finish).
    REQUIRE(yuzu::test::spin_until([] { return g_outstanding_bounded_calls.load() == 0; }, 10s));

    static yuzu::agent::ProcSnapshotSlot slot; // outlives any worker
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
        slot, 1, 5000ms, [](int) { return ProcSnapshot{}; });
    CHECK(r.status == ProcSnapshotStatus::Rejected);
    // The worker never ran, so the caller released the slot: it is acquirable again.
    CHECK(slot.try_acquire().result == yuzu::agent::ProcSnapshotSlot::Acquire::acquired);
    slot.release();
}

TEST_CASE("a stale mark_abandoned cannot land on a later healthy acquisition (ABA)",
          "[proc_snapshot][agent]") {
    using Slot = yuzu::agent::ProcSnapshotSlot;
    Slot slot;
    // Dispatch A acquires, its deadline fires, but the worker returns (releases) before the
    // waiter wakes and calls mark_abandoned.
    const auto a = slot.try_acquire();
    REQUIRE(a.result == Slot::Acquire::acquired);
    slot.release();
    // Dispatch B acquires a healthy read.
    const auto b = slot.try_acquire();
    REQUIRE(b.result == Slot::Acquire::acquired);
    CHECK(b.generation != a.generation);
    // A's stale mark must do nothing: B is still a healthy Busy, not Abandoned.
    slot.mark_abandoned(a.generation);
    CHECK(slot.try_acquire().result == Slot::Acquire::busy);
    // B's own deadline mark does land.
    slot.mark_abandoned(b.generation);
    CHECK(slot.try_acquire().result == Slot::Acquire::abandoned);
    // The worker returns: free again, with a fresh generation.
    slot.release();
    const auto c = slot.try_acquire();
    CHECK(c.result == Slot::Acquire::acquired);
    CHECK(c.generation != b.generation);
    slot.release();
}

TEST_CASE("the slot sequences free, busy, abandoned and release", "[proc_snapshot][agent]") {
    using Slot = yuzu::agent::ProcSnapshotSlot;
    Slot slot;
    const auto t = slot.try_acquire();
    REQUIRE(t.result == Slot::Acquire::acquired);
    CHECK(slot.try_acquire().result == Slot::Acquire::busy);
    slot.mark_abandoned(t.generation);
    CHECK(slot.try_acquire().result == Slot::Acquire::abandoned);
    // A mark on an already-free slot (the worker finished at the deadline) does nothing.
    slot.release();
    slot.mark_abandoned(t.generation);
    const auto u = slot.try_acquire();
    CHECK(u.result == Slot::Acquire::acquired);
    slot.release();
}

TEST_CASE("a throwing reader unwinds through the releaser: never Abandoned afterwards",
          "[proc_snapshot][agent]") {
    static yuzu::agent::ProcSnapshotSlot slot; // outlives any worker
    const auto r = yuzu::agent::detail::bounded_proc_snapshot(
        slot, 1, 30000ms, [](int) -> ProcSnapshot { throw 1; });
    CHECK(r.status == ProcSnapshotStatus::TimedOut);
    // The releaser ran during the unwind, before the caller was woken, so the slot is free
    // deterministically (no wait), and the caller's mark_abandoned was a no-op.
    const auto t = slot.try_acquire();
    CHECK(t.result == yuzu::agent::ProcSnapshotSlot::Acquire::acquired);
    slot.release();
}
