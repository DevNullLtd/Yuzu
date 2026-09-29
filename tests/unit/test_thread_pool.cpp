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
#include <mutex>
#include <stdexcept>

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
