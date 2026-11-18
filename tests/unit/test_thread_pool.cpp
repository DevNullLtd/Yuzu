// Tests for the agent dispatch ThreadPool, focused on the #2037 exception
// firewall: a task that lets an exception escape must NOT terminate the process
// or kill the worker — it must be contained so the pool keeps serving tasks.
//
// Note: without the firewall, the "throwing task" cases below would call
// std::terminate()/abort() and take the whole test binary down (surfacing on
// Windows as exit code 0xC0000409), so these cases are self-proving.

#include "thread_pool.hpp"

#include "test_helpers.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

#include <catch2/catch_test_macros.hpp>

using yuzu::agent::ThreadPool;
using yuzu::test::ScopeExit;

namespace {

// Wait until `pred()` holds or the bounded spin budget is exhausted. Uses a
// condition_variable so it is not a busy-loop; returns pred()'s final value.
template <typename Pred> bool wait_for(std::mutex& m, std::condition_variable& cv, Pred pred) {
    std::unique_lock lock(m);
    return cv.wait_for(lock, std::chrono::seconds(10), pred);
}

} // namespace

TEST_CASE("ThreadPool contains a throwing task and keeps running", "[thread_pool]") {
    std::mutex m;
    std::condition_variable cv;
    int completed = 0;
    constexpr int kNormalTasks = 8;

    auto bump = [&] {
        {
            std::lock_guard lock(m);
            ++completed;
        }
        cv.notify_all();
    };

    // Declared AFTER the state the tasks capture so ~ThreadPool joins the workers
    // before m/cv are destroyed — otherwise a worker could still touch a
    // destroyed mutex/cv during teardown (UB; TSan would flag it).
    ThreadPool pool(4);

    // A task that throws a std::exception — must be contained by the firewall.
    REQUIRE(pool.submit([] { throw std::runtime_error("boom (std)"); }));
    // A task that throws a non-std value — the catch(...) arm.
    REQUIRE(pool.submit([] { throw 42; }));

    // Normal tasks submitted after the throwers must still all run, proving the
    // workers survived the exceptions.
    for (int i = 0; i < kNormalTasks; ++i) {
        REQUIRE(pool.submit(bump));
    }

    const bool all_ran = wait_for(m, cv, [&] { return completed == kNormalTasks; });
    REQUIRE(all_ran);
    REQUIRE(completed == kNormalTasks);
}

TEST_CASE("ThreadPool runs every submitted task", "[thread_pool]") {
    std::atomic<int> ran{0};
    constexpr int kTasks = 200;
    {
        ThreadPool pool(4);
        for (int i = 0; i < kTasks; ++i) {
            REQUIRE(pool.submit([&] { ran.fetch_add(1, std::memory_order_relaxed); }));
        }
        // ~ThreadPool drains and joins.
    }
    REQUIRE(ran.load() == kTasks);
}

TEST_CASE("ThreadPool applies backpressure when the queue is full", "[thread_pool]") {
    constexpr std::size_t kWorkers = 4;
    constexpr std::size_t kQueueCap = 2;

    std::mutex m;
    std::condition_variable cv;
    int entered = 0; // workers currently parked inside a blocking task
    bool release = false;

    auto blocker = [&] {
        {
            std::lock_guard lock(m);
            ++entered;
        }
        cv.notify_all();
        std::unique_lock lock(m);
        cv.wait(lock, [&] { return release; });
    };

    // Pool declared AFTER m/cv/release/blocker so ~ThreadPool joins the workers
    // before that state is destroyed (workers touch m/cv until they return —
    // destroying those first is UB, which TSan would flag).
    ThreadPool pool(kWorkers, kQueueCap);

    // ScopeExit declared AFTER the pool so on scope exit — including a REQUIRE
    // unwind — it destructs BEFORE ~ThreadPool: release+notify happens-before the
    // join, so the parked workers are freed and the join can't hang (qa-B1),
    // while the join still completes before m/cv die.
    ScopeExit release_on_exit{[&] {
        {
            std::lock_guard lock(m);
            release = true;
        }
        cv.notify_all();
    }};

    // Occupy every worker so nothing drains the queue. Submit one blocker at a
    // time and wait until it is actually running before submitting the next —
    // otherwise the occupy submits would race the small queue cap and spuriously
    // hit backpressure here rather than in the assertion below.
    for (std::size_t i = 0; i < kWorkers; ++i) {
        REQUIRE(pool.submit(blocker));
        REQUIRE(wait_for(m, cv, [&] { return entered == static_cast<int>(i + 1); }));
    }

    // Fill the queue to capacity — these are accepted but not yet run.
    for (std::size_t i = 0; i < kQueueCap; ++i) {
        REQUIRE(pool.submit([] {}));
    }
    // The next submit must be rejected: queue is full.
    REQUIRE_FALSE(pool.submit([] {}));

    // release_on_exit unblocks the workers so ~ThreadPool joins cleanly.
}

// ── Protective lane (ADR-2005): a reserved slot containment can always use ──────────────────────

namespace {
// Blocks until released; counts how many have STARTED.
struct Gate {
    std::mutex m;
    std::condition_variable cv;
    bool open = false;
    std::atomic<int> started{0};
    void block() {
        ++started;
        std::unique_lock lock(m);
        cv.wait_for(lock, std::chrono::seconds(30), [this] { return open; });
    }
    void release() {
        { std::lock_guard lock(m); open = true; }
        cv.notify_all();
    }
};

bool spin_until(const std::function<bool()>& pred, std::chrono::milliseconds limit = std::chrono::seconds(10)) {
    const auto end = std::chrono::steady_clock::now() + limit;
    while (!pred()) {
        if (std::chrono::steady_clock::now() > end)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}
} // namespace

TEST_CASE("ThreadPool: N-1 stuck ordinary tasks cannot starve a protective task", "[thread_pool][protective]") {
    // 4 workers, 1 reserved: at most 3 ordinary tasks may run at once. Submit 6 stuck ordinary
    // tasks: exactly 3 start, the other 3 wait in the queue, and the reserved worker stays free.
    auto gate = std::make_shared<Gate>();
    auto gauge = std::make_shared<yuzu::agent::PoolGauge>();
    {
        ThreadPool pool(4, 1000, /*reserved_protective=*/1, gauge);
        for (int i = 0; i < 6; ++i)
            REQUIRE(pool.submit([gate] { gate->block(); }));
        REQUIRE(spin_until([&] { return gate->started.load() == 3; }));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        CHECK(gate->started.load() == 3); // never the 4th: the last slot is reserved
        CHECK(pool.stats().running == 3);
        // The heartbeat reads this gauge (yuzu.command_pool_busy = "running/workers"): 3 of 4, 3 queued.
        CHECK(gauge->workers.load() == 4);
        CHECK(gauge->running.load() == 3);
        CHECK(gauge->queued.load() == 3);

        std::atomic<bool> protective_ran{false};
        const auto t0 = std::chrono::steady_clock::now();
        REQUIRE(pool.submit([&] { protective_ran = true; }, /*protective=*/true));
        CHECK(spin_until([&] { return protective_ran.load(); }, std::chrono::seconds(2)));
        CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2));
        gate->release(); // let the ordinary ones drain before the pool is destroyed
    }
}

TEST_CASE("ThreadPool: a protective task also runs when every ordinary slot is busy and queued behind",
          "[thread_pool][protective]") {
    auto gate = std::make_shared<Gate>();
    ThreadPool pool(4, /*max_queue_size=*/2, /*reserved_protective=*/1);
    for (int i = 0; i < 3; ++i) { // one at a time: the queue bound is 2, a worker must take each first
        REQUIRE(pool.submit([gate] { gate->block(); }));
        REQUIRE(spin_until([&] { return gate->started.load() == i + 1; }));
    }
    for (int i = 0; i < 2; ++i) // 2 more wait in the ordinary queue (its bound)
        REQUIRE(pool.submit([gate] { gate->block(); }));
    CHECK_FALSE(pool.submit([] {})); // the ordinary lane is full ...
    std::atomic<bool> ran{false};
    CHECK(pool.submit([&] { ran = true; }, true)); // ... and does not reject a protective task
    CHECK(spin_until([&] { return ran.load(); }, std::chrono::seconds(2)));
    gate->release();
}

TEST_CASE("ThreadPool: with no reserved slot an ordinary task takes every worker (the regression this fixes)",
          "[thread_pool][protective]") {
    auto gate = std::make_shared<Gate>();
    ThreadPool pool(4, 1000, /*reserved_protective=*/0);
    for (int i = 0; i < 4; ++i)
        REQUIRE(pool.submit([gate] { gate->block(); }));
    REQUIRE(spin_until([&] { return gate->started.load() == 4; }));
    std::atomic<bool> ran{false};
    REQUIRE(pool.submit([&] { ran = true; }, true));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK_FALSE(ran.load()); // starved: no free worker at all
    gate->release();
    CHECK(spin_until([&] { return ran.load(); }));
}

TEST_CASE("ThreadPool: the reservation never leaves zero workers for ordinary tasks and drains on stop",
          "[thread_pool][protective]") {
    ThreadPool pool(4, 1000, /*reserved_protective=*/99); // clamped to workers - 1
    CHECK(pool.stats().reserved_protective == 3);
    std::atomic<int> done{0};
    for (int i = 0; i < 10; ++i)
        REQUIRE(pool.submit([&] { ++done; }));
    CHECK(spin_until([&] { return done.load() == 10; }));
}
