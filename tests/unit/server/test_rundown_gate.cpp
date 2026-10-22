/**
 * test_rundown_gate.cpp -- the shutdown rundown behind the `registry.write` audit hook
 * (server/core/src/rundown_gate.hpp). Pure: no Postgres. The hook's own behaviour with the gate
 * (a frame after the close, a close mid-frame, release on every exit) is pinned in
 * test_plugin_result_audit.cpp.
 *
 * No test here sleeps. A bound of 0 ms never blocks, which is how "someone is still inside" is
 * asked without a clock; the cross-thread cases wait on latches and futures, and a missing wake-up
 * shows as a failed drain after a generous bound, never as a timing assumption.
 */
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <latch>
#include <memory>
#include <thread>
#include <type_traits>
#include <vector>

#include "rundown_gate.hpp"
#include "../test_helpers.hpp"

using namespace std::chrono_literals;
using yuzu::server::RundownGate;

// One place per Entry, given back exactly once: an Entry that could be copied or moved would give
// it back twice, or hand it to a scope that outlives the borrow.
static_assert(!std::is_copy_constructible_v<RundownGate::Entry> &&
                  !std::is_move_constructible_v<RundownGate::Entry> &&
                  !std::is_copy_assignable_v<RundownGate::Entry> &&
                  !std::is_move_assignable_v<RundownGate::Entry>,
              "a RundownGate::Entry is neither copyable nor movable");

TEST_CASE("rundown gate: an open gate admits, a closed gate refuses for good",
          "[server][rundown]") {
    RundownGate gate;
    CHECK_FALSE(gate.closed());
    {
        const auto a = gate.try_enter();
        const auto b = gate.try_enter();
        CHECK(a);
        CHECK(b);
    }
    gate.close();
    CHECK(gate.closed());
    CHECK_FALSE(gate.try_enter());
    gate.close(); // idempotent
    CHECK(gate.closed());
    CHECK_FALSE(gate.try_enter()); // sticky: nothing reopens it
}

TEST_CASE("rundown gate: wait_idle reports whether anyone is still inside, and 0 ms never blocks",
          "[server][rundown]") {
    RundownGate gate;
    CHECK(gate.wait_idle(0ms)); // nobody has entered
    {
        const auto in = gate.try_enter();
        REQUIRE(in);
        gate.close();
        CHECK_FALSE(gate.wait_idle(0ms)); // one is inside
    }
    CHECK(gate.wait_idle(0ms)); // and it left
}

TEST_CASE("rundown gate: the drain waits for every entrant, not the first to leave",
          "[server][rundown]") {
    RundownGate gate;
    auto first = std::unique_ptr<RundownGate::Entry>{new RundownGate::Entry(gate.try_enter())};
    auto second = std::unique_ptr<RundownGate::Entry>{new RundownGate::Entry(gate.try_enter())};
    REQUIRE(*first);
    REQUIRE(*second);
    gate.close();
    CHECK_FALSE(gate.wait_idle(0ms));
    first.reset();
    CHECK_FALSE(gate.wait_idle(0ms)); // one is still inside
    second.reset();
    CHECK(gate.wait_idle(0ms));
}

TEST_CASE("rundown gate: an entry is given back when its scope ends by an exception",
          "[server][rundown]") {
    RundownGate gate;
    try {
        const auto in = gate.try_enter();
        REQUIRE(in);
        throw 42;
    } catch (int) {
    }
    gate.close();
    CHECK(gate.wait_idle(0ms));
}

TEST_CASE("rundown gate: a drain waiting for the last entrant is woken when it leaves",
          "[server][rundown]") {
    // The holder leaves as soon as it sees the gate closed, so across many rounds it leaves both
    // before and after the drain is parked in its wait. A missing wake-up leaves a round parked
    // until its generous bound runs out, and the drain then reports false. `give_up` only keeps a
    // broken gate (one that never reports the close) from hanging the run: the drain fails first.
    for (int round = 0; round < 200; ++round) {
        RundownGate gate;
        std::latch entered{1};
        std::atomic<bool> give_up{false};
        std::thread holder([&] {
            const auto in = gate.try_enter();
            entered.count_down();
            while (!gate.closed() && !give_up.load())
                std::this_thread::yield();
        }); // `in` leaves here
        entered.wait();
        std::promise<bool> drained;
        auto result = drained.get_future();
        std::thread drainer([&] {
            gate.close();
            drained.set_value(gate.wait_idle(30s));
            give_up.store(true);
        });
        const bool ok = result.get();
        holder.join();
        drainer.join();
        REQUIRE(ok);
    }
}

TEST_CASE("rundown gate: entrants racing one close are drained or refused, never both inside",
          "[server][rundown]") {
    constexpr int kThreads = 8;
    RundownGate gate;
    std::latch go{kThreads + 1};
    std::atomic<int> inside{0};
    std::atomic<long> admitted{0};
    std::atomic<bool> drained{false};
    std::atomic<bool> stop{false}; // a broken gate that never refuses must fail, not hang
    std::atomic<int> admitted_after_drain{0};
    std::vector<std::thread> workers;
    for (int i = 0; i < kThreads; ++i)
        workers.emplace_back([&] {
            go.arrive_and_wait();
            for (;;) {
                const auto in = gate.try_enter();
                if (!in)
                    return;
                inside.fetch_add(1);
                if (drained.load())
                    admitted_after_drain.fetch_add(1);
                admitted.fetch_add(1);
                std::this_thread::yield();
                inside.fetch_sub(1);
                if (stop.load())
                    return;
            }
        });
    go.arrive_and_wait();
    // Close only after some entrant got in, so the drain has something to wait for.
    CHECK(yuzu::test::spin_until([&] { return admitted.load() > 0; }));
    gate.close();
    CHECK(gate.wait_idle(30s));
    CHECK(inside.load() == 0); // nobody is inside once the drain returned
    drained.store(true);
    stop.store(true);
    for (auto& t : workers)
        t.join();
    CHECK(admitted_after_drain.load() == 0); // and nobody got in afterwards
}
