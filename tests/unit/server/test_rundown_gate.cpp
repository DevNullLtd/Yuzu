/**
 * test_rundown_gate.cpp -- the shutdown rundown behind the `registry.write` audit hook
 * (server/core/src/rundown_gate.hpp). Pure: no Postgres. The hook's own behaviour with the gate
 * (a frame after the close, a close mid-frame, release on every exit) is pinned in
 * test_plugin_result_audit.cpp.
 *
 * No test here sleeps or polls a clock. A bound of 0 ms never blocks, which is how "someone is
 * still inside" is asked without a clock; the cross-thread cases wait on latches and futures. A
 * drain that was never woken still reports true when its bound runs out (wait_for evaluates its
 * predicate once more at the deadline), so the wake-up case asserts how LONG the drain waited.
 * Test names carry no comma: a by-name Catch2 filter splits at one and matches nothing, which
 * defeats the CI single-case retry.
 */
#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <latch>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "rundown_gate.hpp"

using namespace std::chrono_literals;
using yuzu::server::RundownGate;

// One place per Entry, given back exactly once: an Entry that could be copied or moved would give
// it back twice, or hand it to a scope that outlives the borrow.
static_assert(!std::is_copy_constructible_v<RundownGate::Entry> &&
                  !std::is_move_constructible_v<RundownGate::Entry> &&
                  !std::is_copy_assignable_v<RundownGate::Entry> &&
                  !std::is_move_assignable_v<RundownGate::Entry>,
              "a RundownGate::Entry is neither copyable nor movable");

TEST_CASE("rundown gate: an open gate admits and a closed gate refuses for good",
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

TEST_CASE("rundown gate: wait_idle reports whether anyone is still inside and 0 ms never blocks",
          "[server][rundown]") {
    RundownGate gate;
    CHECK(gate.wait_idle(0ms)); // nobody has entered
    {
        const auto in = gate.try_enter();
        REQUIRE(in);
        gate.close();
        CHECK_FALSE(gate.wait_idle(0ms)); // one is inside
        // A positive bound that expires with an entrant still inside is false too, not "idle":
        // stop() proceeds to reset the store and the pool on true, so this is the answer that
        // keeps it from running past a hook. The entry is held, so the result cannot be true and
        // nothing here depends on how long the wait took.
        CHECK_FALSE(gate.wait_idle(5ms));
    }
    CHECK(gate.wait_idle(0ms)); // and it left
}

TEST_CASE("rundown gate: the drain waits for every entrant and not the first to leave",
          "[server][rundown]") {
    RundownGate gate;
    {
        const auto outer = gate.try_enter();
        REQUIRE(outer);
        {
            const auto inner = gate.try_enter();
            REQUIRE(inner);
            gate.close();
            CHECK_FALSE(gate.wait_idle(0ms)); // two are inside
        }
        CHECK_FALSE(gate.wait_idle(0ms)); // one is still inside: a count, not a flag
    }
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
    // Each round: a holder is inside, the drainer closes the gate and waits, then the holder
    // leaves. The holder leaves after a fixed number of yields (a count, not a clock) so that in
    // nearly every round the drain is already parked and needs the wake-up; a round where it is
    // not still passes. `give_up` only keeps a broken gate from hanging the run.
    for (int round = 0; round < 200; ++round) {
        RundownGate gate;
        std::latch entered{1};
        std::latch gate_closed{1};
        std::atomic<bool> give_up{false};
        std::thread holder([&] {
            const auto in = gate.try_enter();
            entered.count_down();
            gate_closed.wait();
            for (int i = 0; i < 2000 && !give_up.load(); ++i)
                std::this_thread::yield();
        }); // `in` leaves here
        entered.wait();
        std::promise<std::pair<bool, std::chrono::milliseconds>> drained;
        auto result = drained.get_future();
        std::thread drainer([&] {
            gate.close();
            gate_closed.count_down();
            const auto t0 = std::chrono::steady_clock::now();
            const bool ok = gate.wait_idle(30s);
            drained.set_value({ok, std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::steady_clock::now() - t0)});
            give_up.store(true);
        });
        const auto [ok, waited] = result.get();
        holder.join();
        drainer.join();
        REQUIRE(ok);
        // Woken, the drain returns at once; unwoken it would return at its 30 s bound.
        REQUIRE(waited < 15s);
    }
}

TEST_CASE("rundown gate: entrants racing one close are drained or refused and never both inside",
          "[server][rundown]") {
    constexpr int kThreads = 8;
    RundownGate gate;
    std::latch go{kThreads + 1};
    std::latch first_in{1};
    std::atomic<bool> first_signalled{false};
    std::atomic<int> inside{0};
    std::atomic<long> admitted{0};
    std::atomic<bool> drained{false};
    std::atomic<bool> stop{false}; // a broken gate that never refuses must fail, not hang
    std::atomic<int> admitted_after_drain{0};
    std::atomic<int> seen_closed{0};
    const auto signal_first = [&] {
        if (!first_signalled.exchange(true))
            first_in.count_down();
    };
    std::vector<std::thread> workers;
    for (int i = 0; i < kThreads; ++i)
        workers.emplace_back([&] {
            go.arrive_and_wait();
            for (;;) {
                const auto in = gate.try_enter();
                // Polled while close() runs, so a data race on the flag shows. The result is
                // consumed: a discarded load is deleted by the optimiser above -O0.
                seen_closed.fetch_add(gate.closed() ? 1 : 0);
                if (!in) {
                    signal_first(); // a gate that refuses before any close must not hang the test
                    return;
                }
                inside.fetch_add(1);
                if (drained.load())
                    admitted_after_drain.fetch_add(1);
                admitted.fetch_add(1);
                signal_first();
                std::this_thread::yield();
                inside.fetch_sub(1);
                if (stop.load())
                    return;
            }
        });
    go.arrive_and_wait();
    first_in.wait(); // close only after some entrant got in, so the drain has something to wait for
    gate.close();
    CHECK(gate.wait_idle(30s));
    CHECK(inside.load() == 0); // nobody is inside once the drain returned
    drained.store(true);
    stop.store(true);
    for (auto& t : workers)
        t.join();
    CHECK(admitted.load() > 0);
    CHECK(admitted_after_drain.load() == 0); // and nobody got in afterwards
}
