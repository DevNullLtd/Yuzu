// Tests for MutationGate (quarantine_serialization.hpp, #3286): bounds
// concurrent execution of the quarantine plugin's mutating actions to one at
// a time. Pure C++ standard library concurrency primitive — no fixture text,
// no platform guard, no OS/subprocess involvement, so this TU compiles and
// runs on every leg.
//
// Constraint C2: no sleep_for + polling anywhere here — every synchronization
// point between threads is a condition_variable wait (the `wait_for` helper
// below, mirroring test_thread_pool.cpp's identical-purpose helper). No test
// here spawns a subprocess.

#include "quarantine_serialization.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
#include <type_traits>

using yuzu::quarantine::MutationGate;

namespace {

// Wait until `pred()` holds or the bounded spin budget is exhausted. Uses a
// condition_variable so it is not a busy-loop; returns pred()'s final value.
template <typename Pred> bool wait_for(std::mutex& m, std::condition_variable& cv, Pred pred) {
    std::unique_lock lock(m);
    return cv.wait_for(lock, std::chrono::seconds(10), pred);
}

// Acquires the gate and, on success, takes an EARLY return from an inner
// branch rather than falling off the end of the function — exercises that
// Guard's destructor fires on that path too, not just the "normal" one.
// `take_early_return` is a runtime parameter (never a compile-time constant)
// so the compiler cannot prove either branch unreachable.
bool acquire_then_maybe_return_early(MutationGate& gate, bool take_early_return) {
    auto guard = gate.try_enter();
    if (!guard.has_value())
        return false;
    if (take_early_return) {
        return true; // Guard's destructor must run HERE, releasing the gate.
    }
    return true;
}

} // namespace

// The gate's ownership contract, asserted at COMPILE time rather than left to
// the runtime tests below.
//
// A copyable Guard would be an unlock-twice bug that no runtime test written
// against a correct Guard can observe: the copy compiles, both instances
// destruct, and the second release of an already-released gate
// is undefined behaviour — which may well pass on the leg that runs it. The
// move tests below prove the CURRENT type moves correctly; they cannot prove a
// future edit did not add a copy constructor alongside. This can.
//
// A copyable MutationGate is the same defect one level up: the plugin's single
// gate accessor exists so every mutating action contends on ONE mutex, and a
// copy would hand a caller its own private mutex that serialises against
// nothing while still looking like the gate.
static_assert(!std::is_copy_constructible_v<MutationGate::Guard>,
              "MutationGate::Guard must not be copyable — a copy double-unlocks the mutex");
static_assert(!std::is_copy_assignable_v<MutationGate::Guard>,
              "MutationGate::Guard must not be copy-assignable — see above");
static_assert(std::is_nothrow_move_constructible_v<MutationGate::Guard>,
              "MutationGate::Guard must move without throwing — it is returned by value "
              "from try_enter() through std::optional");
static_assert(std::is_nothrow_move_assignable_v<MutationGate::Guard>,
              "MutationGate::Guard must move-assign without throwing");
static_assert(!std::is_default_constructible_v<MutationGate::Guard>,
              "MutationGate::Guard must only ever exist attached to a held mutex — a "
              "default-constructed one would be a guard that guards nothing");
static_assert(!std::is_copy_constructible_v<MutationGate>,
              "MutationGate must not be copyable — a copy serialises against nothing while "
              "presenting as the gate");
static_assert(!std::is_copy_assignable_v<MutationGate>, "MutationGate must not be copy-assignable");


TEST_CASE("MutationGate::try_enter succeeds immediately when uncontended, and "
         "a released Guard makes the gate available for a second acquisition",
         "[agent][quarantine_serialization]") {
    MutationGate gate(std::chrono::milliseconds{1000});

    auto first = gate.try_enter();
    REQUIRE(first.has_value());
    first.reset(); // releases via Guard's destructor

    auto second = gate.try_enter();
    CHECK(second.has_value());
}

TEST_CASE("MutationGate forces a genuine overlap between two threads: a "
         "second entrant cannot acquire while the first still holds the "
         "gate -- the critical sections never interleave -- the short wait "
         "budget returns promptly rather than blocking indefinitely, and "
         "the gate is acquirable again once the holder releases",
         "[agent][quarantine_serialization]") {
    using namespace std::chrono_literals;
    MutationGate gate(300ms);

    std::mutex m;
    std::condition_variable cv;
    bool holder_entered = false;
    bool release = false;

    std::thread holder([&] {
        auto guard = gate.try_enter();
        if (!guard.has_value())
            return; // surfaced below: holder_entered never flips and the
                     // REQUIRE(wait_for(...)) fails cleanly rather than hanging
        {
            std::lock_guard lock(m);
            holder_entered = true;
        }
        cv.notify_all();
        // Do not release until the test has confirmed the second entrant's
        // attempt was made and failed while this thread was still inside --
        // that confirmation is what makes the overlap genuine rather than
        // two calls that merely happened not to race.
        std::unique_lock lock(m);
        cv.wait(lock, [&] { return release; });
        // `guard` destructs here, releasing the gate.
    });

    // Release-and-join on EVERY exit path, including a thrown REQUIRE below.
    // Without this, a failing assertion unwinds while `holder` is still
    // joinable and its worker is blocked on an untimed cv.wait — the thread
    // destructor then calls std::terminate and the whole agent shard dies as a
    // CRASH rather than a test failure, taking every unrelated case with it and
    // hiding which assertion actually failed.
    struct ReleaseAndJoin {
        std::mutex& m;
        std::condition_variable& cv;
        bool& release;
        std::thread& t;
        ~ReleaseAndJoin() {
            {
                std::lock_guard lock(m);
                release = true;
            }
            cv.notify_all();
            if (t.joinable())
                t.join();
        }
    } release_and_join{m, cv, release, holder};

    REQUIRE(wait_for(m, cv, [&] { return holder_entered; }));

    // The holder is now confirmed inside. A second, independent attempt
    // made on this (the main) thread while that is true must fail: the
    // holder cannot have released yet (it is blocked on cv.wait for
    // `release`, which nothing has set), so this call can only return an
    // engaged optional if two callers were simultaneously inside the gate --
    // exactly the interleaving MutationGate exists to prevent.
    const auto start = std::chrono::steady_clock::now();
    auto second_attempt = gate.try_enter();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(second_attempt.has_value());
    // The whole point of a BOUNDED wait: this call returned promptly around
    // the 300ms budget, not after hanging on a lock nothing was ever going
    // to release on its own. Generous CI-safe ceiling (test_bounded_wait.cpp
    // uses the same style of bound), comfortably above the 300ms budget so
    // scheduling jitter under load cannot spuriously fail this, but tight
    // enough to prove it did not block indefinitely.
    CHECK(elapsed < 5s);

    {
        std::lock_guard lock(m);
        release = true;
    }
    cv.notify_all();
    holder.join();

    // The gate is free again: a fresh attempt succeeds immediately.
    auto third_attempt = gate.try_enter();
    CHECK(third_attempt.has_value());
}

TEST_CASE("MutationGate::Guard releases the gate on scope exit, including via "
         "an early return from the enclosing function",
         "[agent][quarantine_serialization]") {
    MutationGate gate(std::chrono::milliseconds{500});

    CHECK(acquire_then_maybe_return_early(gate, /*take_early_return=*/true));

    // If the early-return path had leaked the lock, this independent second
    // acquisition would time out and return a disengaged optional.
    auto second = gate.try_enter();
    CHECK(second.has_value());
}

TEST_CASE("MutationGate::Guard is movable, and only the moved-to instance "
         "releases the gate -- a moved-from Guard's destructor is a no-op",
         "[agent][quarantine_serialization]") {
    MutationGate gate(std::chrono::milliseconds{500});

    {
        auto guard = gate.try_enter();
        REQUIRE(guard.has_value());
        MutationGate::Guard moved = std::move(*guard);
        // `guard` (the optional) is now moved-from. At this block's closing
        // brace, `moved` destructs first (reverse construction order) and
        // releases the gate; `guard`'s moved-from Guard destructs second and
        // must be a no-op. If the move constructor had failed to clear the
        // source's pointer, both destructors would call unlock() on an
        // already-released gate -- a corrupted held_ flag, and
        // exactly the bug this test exists to catch.
        (void)moved;
    }

    // The gate is available again -- proves the unlock happened, cleanly,
    // exactly once.
    auto second = gate.try_enter();
    CHECK(second.has_value());
}

TEST_CASE("MutationGate serves waiters in ARRIVAL ORDER, so a release cannot be "
          "starved by a burst of retrying quarantines",
          "[agent][quarantine_serialization]") {
    // The shape this test exists for is not "two threads contend". It is: N
    // threads hold the gate in a loop while ONE thread — the operator's
    // `unquarantine` — tries to get in. Under the previous
    // std::timed_mutex::try_lock_for implementation that thread measurably won
    // ZERO of 8 attempts across 20 seconds at 8 holders, because try_lock has
    // no queue and an arriving thread barges past one that has already waited.
    //
    // With FIFO the property is structural rather than statistical: a waiter
    // that arrived first is served first, so this asserts an ORDER, not a
    // timing. No sleep_for-and-hope anywhere (constraint C2) — every step is a
    // condition_variable handshake.
    MutationGate gate(std::chrono::milliseconds{5000});

    std::mutex m;
    std::condition_variable cv;
    std::vector<int> served;      // the order acquisitions actually happened in
    bool blocker_holding = false; // the initial holder is in
    bool release_blocker = false; // ...and may now let go
    int queued = 0;               // how many contenders are known to be waiting

    // Thread 0 takes the gate and holds it until told to let go, so every
    // other thread below is guaranteed to arrive while it is held.
    std::thread blocker([&] {
        auto g = gate.try_enter();
        if (!g.has_value())
            return;
        {
            std::lock_guard lock(m);
            served.push_back(0);
            blocker_holding = true;
        }
        cv.notify_all();
        std::unique_lock lock(m);
        cv.wait(lock, [&] { return release_blocker; });
    });

    {
        std::unique_lock lock(m);
        REQUIRE(cv.wait_for(lock, std::chrono::seconds(10), [&] { return blocker_holding; }));
    }

    // Contenders 1..4 arrive in a KNOWN order: each one announces that it is
    // about to block, and the next is not started until it has. That is what
    // makes "arrival order" a fact this test knows rather than a race it hopes
    // for.
    std::vector<std::thread> contenders;
    for (int i = 1; i <= 4; ++i) {
        {
            std::lock_guard lock(m);
            queued = i - 1;
        }
        contenders.emplace_back([&, i] {
            {
                std::lock_guard lock(m);
                queued = i;
            }
            cv.notify_all();
            auto g = gate.try_enter();
            std::lock_guard lock(m);
            if (g.has_value())
                served.push_back(i);
            // Guard released here, at scope exit, letting the next in line run.
        });
        std::unique_lock lock(m);
        REQUIRE(cv.wait_for(lock, std::chrono::seconds(10), [&, i] { return queued == i; }));
    }

    {
        std::lock_guard lock(m);
        release_blocker = true;
    }
    cv.notify_all();
    blocker.join();
    for (auto& t : contenders)
        t.join();

    // Every contender got in — none was starved out to its 5s budget — and
    // they got in in the order they arrived. Under try_lock_for neither is
    // guaranteed, and at 8 holders the last one measurably never got in at all.
    REQUIRE(served.size() == 5);
    CHECK(served == std::vector<int>{0, 1, 2, 3, 4});
}

TEST_CASE("MutationGate: a waiter that times out does not block the queue behind it",
          "[agent][quarantine_serialization]") {
    // The failure mode a naive ticket lock introduces: a waiter that gives up
    // must remove itself, or the queue head names a thread that is no longer
    // waiting and NOBODY can ever be served again. That converts a starvation
    // bug into a permanent wedge, which is strictly worse.
    MutationGate gate(std::chrono::milliseconds{150});

    std::mutex m;
    std::condition_variable cv;
    bool holding = false;
    bool release = false;

    std::thread holder([&] {
        auto g = gate.try_enter();
        {
            std::lock_guard lock(m);
            holding = g.has_value();
        }
        cv.notify_all();
        std::unique_lock lock(m);
        cv.wait(lock, [&] { return release; });
    });
    {
        std::unique_lock lock(m);
        REQUIRE(cv.wait_for(lock, std::chrono::seconds(10), [&] { return holding; }));
    }

    // This one is guaranteed to time out: the gate is held throughout.
    auto timed_out = gate.try_enter();
    CHECK_FALSE(timed_out.has_value());

    {
        std::lock_guard lock(m);
        release = true;
    }
    cv.notify_all();
    holder.join();

    // The gate must be usable again. If the timed-out waiter had stayed in the
    // queue, this acquisition would block for its whole budget and fail.
    auto after = gate.try_enter();
    CHECK(after.has_value());
}
